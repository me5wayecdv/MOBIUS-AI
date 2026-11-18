from __future__ import annotations

import hashlib
import json

from conftest import make_apk
from mobius.adapters.models import InvestigationRow


def _upload_authorized_scan(client, *, analyst="analyst-1"):
    apk = make_apk()
    upload = client.post(
        "/api/v1/applications",
        files={"file": ("fixture.apk", apk, "application/vnd.android.package-archive")},
        headers={"X-Analyst-ID": analyst},
    )
    assert upload.status_code == 201, upload.text
    app = upload.json()
    auth = client.post(
        "/api/v1/authorizations",
        json={
            "apk_sha256": app["sha256"],
            "target_package": "com.example",
            "scope_text": "Static analysis of the supplied artifact only; no execution.",
            "statement": "Fixture is owned by the test suite.",
            "max_intensity": 0,
            "expires_at": "2030-01-01T00:00:00Z",
        },
        headers={"X-Analyst-ID": analyst},
    )
    assert auth.status_code == 201, auth.text
    scan = client.post(
        "/api/v1/scans",
        json={
            "application_id": app["id"],
            "authorization_id": auth.json()["id"],
            "objective": "Inspect fixture code and resolve source references.",
            "intensity": 0,
        },
        headers={"X-Analyst-ID": analyst},
    )
    assert scan.status_code == 201, scan.text
    return app, scan.json()


def _seed_jadx_cache(ctx, app):
    source = (
        "package com.example;\n"
        "public final class Entry {\n"
        "    public void onCreate() {\n"
        "        writeSecret();\n"
        "    }\n"
        "    private void writeSecret() {\n"
        "        System.out.println(\"fixture\");\n"
        "    }\n"
        "}\n"
    ).encode()
    relative = "com/example/Entry.java"
    entry = ctx.settings.artifact_root / "jadx-cache" / app["sha256"] / "1.5.6"
    source_path = entry / "sources" / relative
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_bytes(source)
    manifest = {
        "schema_version": 1,
        "apk_sha256": app["sha256"],
        "tool_version": "1.5.6",
        "source_files": [{
            "path": relative,
            "sha256": hashlib.sha256(source).hexdigest(),
            "size": len(source),
        }],
    }
    (entry / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return relative


def test_code_lookup_api_reads_only_verified_scan_scoped_jadx_cache(client, ctx):
    app, scan = _upload_authorized_scan(client)
    relative = _seed_jadx_cache(ctx, app)
    base = f"/api/v1/scans/{scan['id']}/code"

    classes = client.get(base + "/classes")
    assert classes.status_code == 200, classes.text
    assert classes.json()["items"] == [{
        "class_name": "com.example.Entry",
        "path": relative,
        "fidelity": "decompiled",
    }]

    methods = client.get(base + "/methods", params={"class_name": "com.example.Entry"})
    assert methods.status_code == 200, methods.text
    names = {item["name"] for item in methods.json()["items"]}
    assert {"onCreate", "writeSecret"} <= names

    source = client.get(
        base + "/source",
        params={"path": relative, "start_line": 2, "end_line": 7},
    )
    assert source.status_code == 200, source.text
    assert source.json()["fidelity"] == "decompiled"
    assert "writeSecret" in source.json()["text"]
    assert source.json()["start_line"] == 2


def test_code_lookup_api_refuses_missing_cache_and_does_not_claim_source(client):
    _app, scan = _upload_authorized_scan(client)
    response = client.get(f"/api/v1/scans/{scan['id']}/code/classes")
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "JADX_SOURCE_UNAVAILABLE"


def test_decompile_endpoint_fails_closed_without_verified_isolation(client):
    _app, scan = _upload_authorized_scan(client)
    response = client.post(f"/api/v1/scans/{scan['id']}/code/decompile")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "JADX_WORKER_IMAGE_UNAVAILABLE"


def test_code_lookup_enforces_scan_owner_and_source_bounds(client, ctx):
    app, scan = _upload_authorized_scan(client)
    relative = _seed_jadx_cache(ctx, app)
    base = f"/api/v1/scans/{scan['id']}/code"

    denied = client.get(base + "/classes", headers={"X-Analyst-ID": "another-analyst"})
    assert denied.status_code == 404

    traversal = client.get(base + "/source", params={"path": "../outside.java"})
    assert traversal.status_code == 422
    oversized = client.get(
        base + "/source",
        params={"path": relative, "start_line": 1, "end_line": 41},
    )
    assert oversized.status_code == 422


def test_code_lookup_rejects_tampered_source_cache(client, ctx):
    app, scan = _upload_authorized_scan(client)
    relative = _seed_jadx_cache(ctx, app)
    source_path = (
        ctx.settings.artifact_root / "jadx-cache" / app["sha256"] / "1.5.6"
        / "sources" / relative
    )
    source_path.write_text("tampered", encoding="utf-8")

    response = client.get(
        f"/api/v1/scans/{scan['id']}/code/source",
        params={"path": relative, "start_line": 1, "end_line": 1},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "JADX_CACHE_INVALID"



def test_jadx_decompile_is_queued_and_owner_scoped(client, ctx):
    from dataclasses import replace

    _app, scan = _upload_authorized_scan(client)
    ctx.settings = replace(
        ctx.settings,
        jadx_image="ghcr.io/example/mobius-jadx@sha256:" + "a" * 64,
    )
    with ctx.session() as session:
        row = session.get(InvestigationRow, scan["id"])
        row.state = "SURFACE_READY"
        session.commit()

    base = f"/api/v1/scans/{scan['id']}/code/decompile/jobs"
    queued = client.post(base)
    assert queued.status_code == 202, queued.text
    body = queued.json()
    assert body["kind"] == "jadx_decompile"
    assert body["status"] == "queued"

    status = client.get(base + "/" + body["job_id"])
    assert status.status_code == 200, status.text
    assert status.json()["status"] == "queued"

    denied = client.get(
        base + "/" + body["job_id"],
        headers={"X-Analyst-ID": "another-analyst"},
    )
    assert denied.status_code == 404



def test_jadx_queue_rejects_mutable_worker_image_reference(client, ctx):
    from dataclasses import replace

    _app, scan = _upload_authorized_scan(client)
    ctx.settings = replace(ctx.settings, jadx_image="ghcr.io/example/mobius-jadx:latest")
    response = client.post(
        f"/api/v1/scans/{scan['id']}/code/decompile/jobs",
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "JADX_WORKER_IMAGE_UNAVAILABLE"
