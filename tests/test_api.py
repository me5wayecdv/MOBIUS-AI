"""End-to-end through HTTP.

These tests use the real FastAPI app, a real (in-memory) database and real services. The
only fake is the APK bytes. Nothing is stubbed at the route layer, so a green run means the
documented wire contract actually works.
"""

from __future__ import annotations

import io
import zipfile

from conftest import make_apk


def _upload(client, data=None, name="app.apk"):
    return client.post(
        "/api/v1/applications",
        files={"file": (name, data or make_apk(), "application/vnd.android.package-archive")},
    )


def _authorize(client, sha, **kw):
    body = {
        "apk_sha256": sha,
        "target_package": "com.example",
        "scope_text": "Static analysis of the supplied artefact only; no execution.",
        "statement": "I am authorised to analyse this build.",
        "max_intensity": 2,
        "expires_at": "2030-01-01T00:00:00Z",
    }
    body.update(kw)
    return client.post("/api/v1/authorizations", json=body)


def _scan(client, app_id, auth_id, **kw):
    body = {
        "application_id": app_id,
        "authorization_id": auth_id,
        "objective": "Determine whether exported components reach a privileged sink.",
        "intensity": 0,
    }
    body.update(kw)
    return client.post("/api/v1/scans", json=body)


def test_health_reports_capabilities_not_optimism(client):
    body = client.get("/api/v1/health").json()
    assert body["status"] == "ok"
    assert body["auth"] == "stub"
    assert set(body["tools"]) == {"androguard", "jadx", "apktool", "adb"}
    # In this environment the Android toolchain is absent; the endpoint must say so
    # rather than implying dynamic analysis is available.
    assert body["tools"]["adb"] is False


def test_gate_catalogue_is_exposed_before_a_scan(client):
    gates = client.get("/api/v1/gates").json()
    assert len(gates) == 11
    exported = next(g for g in gates if g["category"] == "exported-component-no-permission")
    assert exported["required_evidence"] == ["exported", "permission", "caller_check_absent", "sink_reachable"]
    assert exported["maswe"] == ["MASWE-0018"]


def test_full_flow(client):
    upload = _upload(client)
    assert upload.status_code == 201
    app = upload.json()
    assert len(app["sha256"]) == 64

    auth = _authorize(client, app["sha256"])
    assert auth.status_code == 201, auth.text

    scan = _scan(client, app["id"], auth.json()["id"])
    assert scan.status_code == 201, scan.text
    # Uppercase, matching docs/API_SPECIFICATION.md and the DB/event representation. One
    # spelling everywhere means no mapping layer that can drift.
    assert scan.json()["state"] == "RECON"
    assert scan.json()["last_event_seq"] == 2


def test_duplicate_upload_is_flagged(client):
    # Reuse the exact same bytes: make_apk() writes current ZIP timestamps, so two
    # independently generated fixtures are not byte-identical APK artefacts.
    apk = make_apk()
    first = _upload(client, data=apk).json()
    second = _upload(client, data=apk).json()
    assert second["id"] == first["id"]
    assert second.get("duplicate") is True


def test_invalid_apk_returns_a_typed_error(client):
    resp = client.post(
        "/api/v1/applications",
        files={"file": ("x.apk", b"definitely not a zip", "application/octet-stream")},
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["code"] == "APK_INVALID"
    assert body["status"] == 422


def test_unauthorised_scan_is_refused_with_a_stable_code(client):
    app = _upload(client).json()
    resp = _scan(client, app["id"], "ath_missing")
    assert resp.status_code == 409
    assert resp.json()["code"] == "AUTH_REQUIRED"


def test_hash_mismatch_is_refused(client):
    app = _upload(client).json()
    auth = _authorize(client, "a" * 64).json()
    resp = _scan(client, app["id"], auth["id"])
    assert resp.status_code == 409
    assert resp.json()["code"] == "AUTH_REQUIRED"


def test_intensity_ceiling_is_enforced_over_http(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"], max_intensity=0).json()
    resp = _scan(client, app["id"], auth["id"], intensity=2)
    assert resp.status_code == 409
    assert resp.json()["code"] == "INTENSITY_NOT_GRANTED"


def test_pause_and_resume_are_reflected_in_state_without_changing_it(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()

    paused = client.post(f"/api/v1/scans/{scan['id']}/pause", json={"reason": "scope check"}).json()
    assert paused["paused"] is True
    assert paused["state"] == "RECON"

    resumed = client.post(f"/api/v1/scans/{scan['id']}/resume").json()
    assert resumed["paused"] is False


def test_events_are_pollable_with_a_cursor(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()

    first = client.get(f"/api/v1/scans/{scan['id']}/events").json()
    assert [e["type"] for e in first["items"]] == ["investigation_started", "investigation_updated"]
    assert first["next_after"] == 2
    assert client.get(f"/api/v1/scans/{scan['id']}/events?after=2").json()["items"] == []


def test_validation_endpoint_confirms_and_rejects(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()

    base = {
        "category": "exported-component-no-permission",
        "title": "Exported activity writes attacker-supplied path",
        "description": "MainActivity forwards EXTRA_PATH to FileOutputStream.",
        "evidence_refs": ["ev_1"],
        "discovered_by": "SPECTRE",
        "validated_by": "VERITAS",
    }
    confirmed = client.post(
        f"/api/v1/scans/{scan['id']}/validate",
        json={**base, "attributes": {
            "exported": True, "permission": None,
            "caller_check_absent": True, "sink_reachable": True}},
    )
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["verdict"]["verdict"] == "confirmed"
    assert confirmed.json()["finding"]["status"] == "confirmed"

    rejected = client.post(
        f"/api/v1/scans/{scan['id']}/validate",
        json={**base, "attributes": {
            "exported": True, "permission": None,
            "caller_check_absent": True, "sink_reachable": False}},
    )
    assert rejected.json()["verdict"]["verdict"] == "rejected"
    assert rejected.json()["verdict"]["rejection_reason"] == "not-reachable"

    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"]
    assert len(findings) == 2


def test_validation_refuses_self_validation(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()
    resp = client.post(
        f"/api/v1/scans/{scan['id']}/validate",
        json={
            "category": "exported-component-no-permission",
            "attributes": {"exported": True, "permission": None,
                           "caller_check_absent": True, "sink_reachable": True},
            "title": "Self-validated claim",
            "description": "d",
            "evidence_refs": ["ev_1"],
            "discovered_by": "SPECTRE",
            "validated_by": "SPECTRE",
        },
    )
    assert resp.status_code == 409
    assert resp.json()["code"] == "VALIDATOR_MUST_DIFFER"


def test_recon_runs_over_http_and_exposes_the_surface(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()

    recon = client.post(f"/api/v1/scans/{scan['id']}/recon")
    assert recon.status_code == 200, recon.text
    body = recon.json()
    assert body["state"] == "SURFACE_READY"
    assert body["evidence_id"].startswith("ev_")

    surface = client.get(f"/api/v1/scans/{scan['id']}/surface").json()
    assert surface["observations"], "RECON must record what it saw"

    again = client.post(f"/api/v1/scans/{scan['id']}/recon")
    assert again.status_code == 409
    assert again.json()["code"] == "SCAN_STATE_CONFLICT"


def test_recon_rejects_a_non_manifest_apk(client):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<not-a-manifest/>")
    app = client.post(
        "/api/v1/applications",
        files={"file": ("x.apk", buf.getvalue(), "application/vnd.android.package-archive")},
    ).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()
    resp = client.post(f"/api/v1/scans/{scan['id']}/recon")
    assert resp.status_code == 422
    assert resp.json()["code"] == "MANIFEST_INVALID"


def test_health_reports_androguard_present_when_installed(client):
    body = client.get("/api/v1/health").json()
    import importlib.util

    assert body["tools"]["androguard"] is (importlib.util.find_spec("androguard") is not None)


def test_unknown_scan_is_404_with_a_code(client):
    resp = client.get("/api/v1/scans/scn_missing")
    assert resp.status_code == 404
    assert resp.json()["code"] == "NOT_FOUND"


def test_evidence_round_trip(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()

    created = client.post(
        f"/api/v1/scans/{scan['id']}/evidence",
        params={"kind": "manifest", "summary": "extracted manifest", "content": "<manifest/>"},
    )
    assert created.status_code == 201, created.text
    listed = client.get(f"/api/v1/scans/{scan['id']}/evidence").json()["items"]
    assert len(listed) == 1
    assert listed[0]["summary"] == "extracted manifest"


def test_fresh_checkout_starts_without_pre_created_directories(tmp_path):
    """A clone has no data/ directory. The app must create it, not fail on first upload."""
    from mobius.api.config import Settings
    from mobius.api.deps import AppContext

    settings = Settings(
        db_url=f"sqlite+pysqlite:///{tmp_path}/nested/dir/mobius.db",
        artifact_root=tmp_path / "nested" / "artifacts",
        env="test",
    )
    ctx = AppContext(settings)
    with ctx.session() as session:
        from sqlalchemy import text

        assert session.execute(text("SELECT 1")).scalar() == 1
    assert (tmp_path / "nested" / "artifacts").is_dir()
    ctx.engine.dispose()


def _apk_with_fixture_dex(manifest: str) -> bytes:
    import io as _io
    import pathlib
    import zipfile as _zip

    dex = (pathlib.Path(__file__).parent / "fixtures" / "dex" / "AnalysisTest.dex").read_bytes()
    buf = _io.BytesIO()
    with _zip.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
    return buf.getvalue()


def test_spectre_runs_over_http_against_a_real_dex(client):
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.demo"><application>'
        '<activity android:name="AnalysisTest" android:exported="true"/>'
        "</application></manifest>"
    )
    app = client.post(
        "/api/v1/applications",
        files={"file": ("demo.apk", _apk_with_fixture_dex(manifest),
                        "application/vnd.android.package-archive")},
    ).json()
    auth = _authorize(client, app["sha256"], target_package="com.example.demo").json()
    scan = _scan(client, app["id"], auth["id"]).json()
    assert client.post(f"/api/v1/scans/{scan['id']}/recon").status_code == 200

    resp = client.post(f"/api/v1/scans/{scan['id']}/spectre")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "CORRELATING"
    assert body["index"]["classes"] == 1
    assert body["candidates"] == 1
    # AnalysisTest has no lifecycle entry point, so the honest answer is "not established".
    assert body["results"][0]["reachability"] == "no-entry-point"
    assert body["results"][0]["status"] == "manual_review_required"


def test_spectre_rejects_an_unparseable_dex_with_a_typed_error(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()
    client.post(f"/api/v1/scans/{scan['id']}/recon")
    resp = client.post(f"/api/v1/scans/{scan['id']}/spectre")
    assert resp.status_code == 422
    assert resp.json()["code"] == "CODE_INDEX_FAILED"


def test_nexus_drives_the_whole_loop_over_http(client):
    """RECON -> NEXUS -> CLOSED, with the budget and the stop reason in the response."""
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.demo"><application>'
        '<activity android:name="AnalysisTest" android:exported="true"/>'
        "</application></manifest>"
    )
    app = client.post(
        "/api/v1/applications",
        files={"file": ("demo.apk", _apk_with_fixture_dex(manifest),
                        "application/vnd.android.package-archive")},
    ).json()
    auth = _authorize(client, app["sha256"], target_package="com.example.demo").json()
    scan = _scan(client, app["id"], auth["id"]).json()
    assert client.post(f"/api/v1/scans/{scan['id']}/recon").status_code == 200

    resp = client.post(f"/api/v1/scans/{scan['id']}/nexus?max_steps=5")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "CLOSED"
    assert body["stop_reason"] == "completed"
    assert body["dispatched"] == 1
    assert body["budget"] == {"max_steps": 5, "steps_used": 1, "steps_remaining": 4}
    assert body["findings"]["confirmed"] == 0
    assert body["steps"][0]["agent"] == "SPECTRE"

    detail = client.get(f"/api/v1/scans/{scan['id']}").json()
    assert detail["state"] == "CLOSED"


def test_nexus_refuses_a_scan_that_has_not_run_recon(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()

    resp = client.post(f"/api/v1/scans/{scan['id']}/nexus")
    assert resp.status_code == 409
    assert resp.json()["code"] == "SCAN_STATE_CONFLICT"


def test_the_report_is_written_and_read_back_over_http(client):
    """A closed investigation must produce a document a reviewer can actually open."""
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.demo"><application>'
        '<activity android:name="AnalysisTest" android:exported="true"/>'
        "</application></manifest>"
    )
    app = client.post(
        "/api/v1/applications",
        files={"file": ("demo.apk", _apk_with_fixture_dex(manifest),
                        "application/vnd.android.package-archive")},
    ).json()
    auth = _authorize(client, app["sha256"], target_package="com.example.demo").json()
    scan = _scan(client, app["id"], auth["id"]).json()
    client.post(f"/api/v1/scans/{scan['id']}/recon")
    closed = client.post(f"/api/v1/scans/{scan['id']}/nexus").json()
    assert closed["state"] == "CLOSED"

    written = client.post(f"/api/v1/scans/{scan['id']}/report")
    assert written.status_code == 200, written.text
    body = written.json()
    assert body["evidence_id"].startswith("ev_")
    assert "# MOBIUS investigation report" in body["markdown"]

    fetched = client.get(f"/api/v1/scans/{scan['id']}/report")
    assert fetched.status_code == 200
    assert fetched.headers["content-type"].startswith("text/markdown")
    assert fetched.text == body["markdown"]


def test_reading_a_report_that_was_never_written_is_404(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()

    resp = client.get(f"/api/v1/scans/{scan['id']}/report")
    assert resp.status_code == 404


def test_scans_can_be_listed(client):
    """A UI cannot show a scan it cannot list, and a demo must not hardcode an id."""
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()

    body = client.get("/api/v1/scans").json()
    assert body["count"] >= 1
    assert any(item["id"] == scan["id"] for item in body["items"])
    assert body["items"][0]["state"] == "RECON"


def test_the_war_room_is_served_and_reads_only_real_endpoints(client):
    resp = client.get("/ui")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")

    html = resp.text
    # It must talk to the API rather than to baked-in data.
    assert "/api/v1" in html
    # Timeline replay and reconnect are driven by polling the durable event cursor.
    assert "/events?after=0&limit=1000" in html
    assert "setInterval(()=>refreshEvents(),3000)" in html
    assert "All visible state is read from persisted investigation data and events." in html
    assert "/hypotheses" in html
    assert "poc/runs" in html
    assert "d050-mission" in html and "d055-poc-report" in html
    assert client.get("/", follow_redirects=False).status_code in (302, 307)



def test_stub_identity_refuses_staging_and_production(tmp_path):
    import pytest
    from mobius.api.config import Settings
    from mobius.api.deps import AppContext

    for environment in ("staging", "production", "prod"):
        settings = Settings(
            db_url="sqlite+pysqlite:///:memory:",
            artifact_root=tmp_path / environment,
            env=environment,
        )
        with pytest.raises(RuntimeError, match="stub identity only"):
            AppContext(settings, create_schema=False)


def test_stub_identity_remains_available_in_development_and_test(tmp_path):
    from mobius.api.config import Settings
    from mobius.api.deps import AppContext

    for environment in ("development", "dev", "test"):
        settings = Settings(
            db_url="sqlite+pysqlite:///:memory:",
            artifact_root=tmp_path / environment,
            env=environment,
        )
        context = AppContext(settings, create_schema=False)
        context.engine.dispose()



def test_upload_read_is_bounded_before_service_validation(client, monkeypatch):
    import mobius.api.routes as routes

    monkeypatch.setattr(routes, "MAX_APK_BYTES", 4)
    # The route read limit and service validation limit must agree in this test.
    import mobius.services.intake as intake
    monkeypatch.setattr(intake, "MAX_APK_BYTES", 4)
    response = _upload(client)
    assert response.status_code == 413
    assert response.json()["code"] == "APK_TOO_LARGE"



def test_investigations_are_isolated_by_analyst_identity(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    created = client.post(
        "/api/v1/scans",
        headers={"X-Analyst-Id": "analyst-alice"},
        json={
            "application_id": app["id"],
            "authorization_id": auth["id"],
            "objective": "Alice's authorized static analysis",
            "intensity": 0,
        },
    )
    assert created.status_code == 201, created.text
    scan_id = created.json()["id"]

    # The default analyst cannot read or operate Alice's investigation.
    assert client.get(f"/api/v1/scans/{scan_id}").status_code == 404
    assert client.post(f"/api/v1/scans/{scan_id}/recon").status_code == 404
    assert client.get(f"/api/v1/scans/{scan_id}/events").status_code == 404
    assert client.get("/api/v1/scans").json()["count"] == 0

    # The owning identity can read it and sees it in their own list.
    headers = {"X-Analyst-Id": "analyst-alice"}
    assert client.get(f"/api/v1/scans/{scan_id}", headers=headers).status_code == 200
    assert client.get("/api/v1/scans", headers=headers).json()["count"] == 1


def test_recon_rejects_authorization_for_a_different_manifest_package(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"], target_package="com.attacker.claim").json()
    scan = _scan(client, app["id"], auth["id"]).json()

    response = client.post(f"/api/v1/scans/{scan['id']}/recon")
    assert response.status_code == 409
    assert response.json()["code"] == "AUTH_REQUIRED"
    assert client.get(f"/api/v1/scans/{scan['id']}/evidence").json()["items"] == []
    assert client.get(f"/api/v1/scans/{scan['id']}/surface").json()["observations"] == []


def test_isolated_recon_job_is_queued_polled_and_applied(client, ctx):
    from mobius.services.worker_queue import WorkerQueue

    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()

    queued = client.post(f"/api/v1/scans/{scan['id']}/recon/jobs")
    assert queued.status_code == 202, queued.text
    job_id = queued.json()["job_id"]
    assert queued.json()["status"] == "queued"

    with ctx.session() as session:
        queue = WorkerQueue(session)
        claimed = queue.claim("test-isolated-worker")
        assert claimed is not None and claimed.id == job_id
        queue.succeed(
            job_id,
            "test-isolated-worker",
            {"manifest_xml": "<manifest package='com.example'/>"},
        )
        session.commit()

    status = client.get(f"/api/v1/scans/{scan['id']}/recon/jobs/{job_id}")
    assert status.status_code == 200
    assert status.json()["status"] == "succeeded"

    applied = client.post(f"/api/v1/scans/{scan['id']}/recon/jobs/{job_id}/apply")
    assert applied.status_code == 200, applied.text
    assert applied.json()["package_name"] == "com.example"
    assert client.get(f"/api/v1/scans/{scan['id']}/recon/jobs/{job_id}").json()["applied"] is True

    duplicate = client.post(f"/api/v1/scans/{scan['id']}/recon/jobs/{job_id}/apply")
    assert duplicate.status_code == 409



def test_spectre_and_nexus_are_blocked_outside_test_without_isolated_dex_worker(client, ctx):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()
    assert client.post(f"/api/v1/scans/{scan['id']}/recon").status_code == 200

    # The test fixture normally enables inline execution. Simulate a shared development
    # API: neither direct SPECTRE nor NEXUS may parse attacker-supplied DEX in-process.
    from dataclasses import replace
    ctx.settings = replace(ctx.settings, env="development")
    spectre = client.post(f"/api/v1/scans/{scan['id']}/spectre")
    nexus = client.post(f"/api/v1/scans/{scan['id']}/nexus")

    assert spectre.status_code == 503
    assert "isolated DEX worker" in spectre.json()["detail"]
    assert nexus.status_code == 503
    assert "isolated DEX worker" in nexus.json()["detail"]



def test_isolated_dex_job_is_queued_indexed_and_applied(client, ctx):
    import hashlib
    import json
    import pathlib
    from io import BytesIO
    import zipfile

    from mobius.adapters.dex import index_apk
    from mobius.adapters.dex_payload import code_index_payload
    from mobius.services.worker_queue import WorkerQueue

    fixture = pathlib.Path(__file__).parent / "fixtures" / "dex" / "AnalysisTest.dex"
    apk_stream = BytesIO()
    with zipfile.ZipFile(apk_stream, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml",
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            'package="com.example"><application>'
            '<activity android:name="AnalysisTest" android:exported="true"/>'
            "</application></manifest>",
        )
        archive.writestr("classes.dex", fixture.read_bytes())
    apk_bytes = apk_stream.getvalue()

    app = _upload(client, data=apk_bytes).json()
    auth = _authorize(client, app["sha256"], target_package="com.example").json()
    scan = _scan(client, app["id"], auth["id"]).json()
    assert client.post(f"/api/v1/scans/{scan['id']}/recon").status_code == 200

    queued = client.post(f"/api/v1/scans/{scan['id']}/spectre/jobs")
    assert queued.status_code == 202, queued.text
    job_id = queued.json()["job_id"]
    assert queued.json()["kind"] == "dex_index"

    index = index_apk(apk_bytes)
    payload = code_index_payload(index, hashlib.sha256(apk_bytes).hexdigest())
    with ctx.session() as session:
        queue = WorkerQueue(session)
        claimed = queue.claim("dex-worker-test")
        assert claimed is not None and claimed.id == job_id
        queue.succeed(job_id, "dex-worker-test", payload)
        session.commit()

    status = client.get(f"/api/v1/scans/{scan['id']}/spectre/jobs/{job_id}")
    assert status.status_code == 200
    assert status.json()["status"] == "succeeded"

    applied = client.post(f"/api/v1/scans/{scan['id']}/spectre/jobs/{job_id}/apply")
    assert applied.status_code == 200, applied.text
    assert applied.json()["index"]["classes"] == 1
    assert applied.json()["index"]["dex_files"] == 1
    assert applied.json()["index"]["complete"] is True
    assert client.get(f"/api/v1/scans/{scan['id']}/spectre/jobs/{job_id}").json()["applied"] is True

    duplicate = client.post(f"/api/v1/scans/{scan['id']}/spectre/jobs/{job_id}/apply")
    assert duplicate.status_code == 409


def test_isolated_dex_job_rejects_worker_result_for_different_apk(client, ctx):
    import hashlib
    import pathlib
    import zipfile
    from io import BytesIO

    from mobius.adapters.dex import index_apk
    from mobius.adapters.dex_payload import code_index_payload
    from mobius.services.worker_queue import WorkerQueue

    fixture = pathlib.Path(__file__).parent / "fixtures" / "dex" / "AnalysisTest.dex"
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest package='com.example'/>")
        archive.writestr("classes.dex", fixture.read_bytes())
    apk_bytes = stream.getvalue()
    app = _upload(client, data=apk_bytes).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()
    client.post(f"/api/v1/scans/{scan['id']}/recon")

    queued = client.post(f"/api/v1/scans/{scan['id']}/spectre/jobs").json()
    wrong_apk = apk_bytes + b"tampered"
    payload = code_index_payload(index_apk(apk_bytes), hashlib.sha256(wrong_apk).hexdigest())
    with ctx.session() as session:
        queue = WorkerQueue(session)
        queue.claim("dex-worker-test")
        queue.succeed(queued["job_id"], "dex-worker-test", payload)
        session.commit()

    response = client.post(
        f"/api/v1/scans/{scan['id']}/spectre/jobs/{queued['job_id']}/apply"
    )
    assert response.status_code == 422
    assert response.json()["code"] == "CODE_INDEX_FAILED"


def _provider_manifest() -> str:
    return """<manifest package='com.example' xmlns:android='http://schemas.android.com/apk/res/android'>
  <application>
    <provider android:name='.NotesProvider' android:authorities='com.example.notes' android:exported='true'/>
  </application>
</manifest>"""


def test_provider_analysis_validates_exported_provider(client):
    app = _upload(client, data=make_apk(manifest=_provider_manifest())).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()

    resp = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["providers"] == 1
    assert len(body["results"]) == 2  # one finding per operation (read + write)
    for result in body["results"]:
        # The fake classes.dex does not parse, so code coverage is partial:
        # protection is evidenced (unprotected) but caller-check and sink
        # clauses stay unknown -> manual review, never guessed either way.
        assert result["attributes"] == {"exported": True, "permission": None}
        assert result["verdict"] == "insufficient_evidence"
        assert result["finding_status"] == "manual_review_required"

    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"]
    assert len(findings) == 2
    assert {f["category"] for f in findings} == {"exported-provider-unprotected-sink"}

    # The evidence summary is the primary text a reviewer reads: it must
    # carry the established manifest facts, not only the gate outcome.
    evidence_items = client.get(f"/api/v1/scans/{scan['id']}/evidence").json()["items"]
    provider_summaries = [e["summary"] for e in evidence_items
                          if e["summary"].startswith("provider-analysis:")]
    assert len(provider_summaries) == 2
    for summary in provider_summaries:
        assert "exported True" in summary
        assert "protection unprotected" in summary

    # the ARCHIVIST report is composed from the same findings: write it, then
    # read it back and confirm the provider analysis is visible there.
    written = client.post(f"/api/v1/scans/{scan['id']}/report")
    assert written.status_code == 200, written.text
    report = client.get(f"/api/v1/scans/{scan['id']}/report")
    assert report.status_code == 200, report.text
    assert "com.example.NotesProvider" in report.text


def _provider_worker_payload(sha, package="com.example", methods=3, ledger=None,
                             caller_check_absent=True, operations=("read",),
                             origin_entry="classes.dex", origin_position=0,
                             origin_duplicated=False, include_origins=True):
    """Hand-built worker payload: lets tests tamper with exactly one field."""
    ops = []
    for name in operations:
        op = {
            "operation": name,
            "protection_status": "unprotected",
            "protection_permission": None,
            "protection_basis": "no provider permission declared",
            "caller_check_absent": caller_check_absent,
            "guard_findings": [],
            "coverage_complete": True,
            "sink_flows": [
                {"method": "com.example.NotesProvider.query",
                 "sink": "SQLiteDatabase.rawQuery",
                 "detail": "caller-controlled projection"},
            ],
            "flow_complete": True,
        }
        if caller_check_absent is not None:
            op["evidence_classes"] = ["com.example.NotesProvider"]
        ops.append(op)
    payload = {
        "schema_version": 1,
        "artifact_sha256": sha,
        "package_name": package,
        "methods_adapted": methods,
        "dex_coverage": ledger if ledger is not None else [
            {"entry": "classes.dex", "status": "parsed", "size_bytes": 100, "methods": methods},
        ],
        "origins": (
            {
                "com.example.NotesProvider": {
                    "entry": origin_entry,
                    "entry_position": origin_position,
                    "duplicated": origin_duplicated,
                }
            }
            if include_origins
            else {}
        ),
        "exposures": [
            {
                "provider": "com.example.NotesProvider",
                "exported": True,
                "grant_uri_permissions": False,
                "uri_patterns": [],
                "numeric_uri_patterns": [],
                "operations": ops,
            },
        ],
    }
    return payload


def _surface_ready_scan(client):
    app = _upload(client, data=make_apk(manifest=_provider_manifest())).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()
    assert client.post(f"/api/v1/scans/{scan['id']}/recon").status_code == 200
    return app, scan


def _complete_provider_job(client, ctx, scan, payload):
    from mobius.services.worker_queue import WorkerQueue
    with ctx.session() as session:
        queue = WorkerQueue(session)
        claimed = queue.claim("provider-worker-test")
        assert claimed is not None
        queue.succeed(claimed.id, "provider-worker-test", payload,
                      staged_sha256=payload["artifact_sha256"])
        session.commit()
        return claimed.id


def test_isolated_provider_job_is_queued_succeeded_and_applied(client, ctx):
    app, scan = _surface_ready_scan(client)

    queued = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs")
    assert queued.status_code == 202, queued.text
    assert queued.json()["kind"] == "provider_analysis"
    job_id = queued.json()["job_id"]

    payload = _provider_worker_payload(app["sha256"])
    assert _complete_provider_job(client, ctx, scan, payload) == job_id

    status = client.get(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}")
    assert status.status_code == 200
    assert status.json()["status"] == "succeeded"
    assert status.json()["applied"] is False

    applied = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert applied.status_code == 200, applied.text
    body = applied.json()
    assert body["package_name"] == "com.example"
    assert body["providers"] == 1
    assert len(body["results"]) == 1
    assert body["results"][0]["attributes"]["caller_check_absent"] is True
    assert client.get(
        f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}"
    ).json()["applied"] is True

    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"]
    assert {f["category"] for f in findings} == {"exported-provider-unprotected-sink"}

    duplicate = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert duplicate.status_code == 409


def test_isolated_provider_job_rejects_result_for_different_apk(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]

    payload = _provider_worker_payload("0" * 64)  # bound to a different artifact
    assert _complete_provider_job(client, ctx, scan, payload) == job_id

    applied = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert applied.status_code == 422
    assert "not bound to the authorized APK" in applied.text
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []


def test_isolated_provider_job_rejects_wrong_target_package(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]

    payload = _provider_worker_payload(app["sha256"], package="com.other.app")
    assert _complete_provider_job(client, ctx, scan, payload) == job_id

    # The package contradicts the stored recon manifest for the same artifact:
    # unappliable, terminally rejected, and no findings are recorded.
    applied = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert applied.status_code == 422
    assert "recon" in applied.text
    status = client.get(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}")
    assert status.json()["status"] == "rejected"
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []


def test_isolated_provider_apply_rejects_dex_job_kind_and_unfinished_jobs(client, ctx):
    app, scan = _surface_ready_scan(client)

    dex_job = client.post(f"/api/v1/scans/{scan['id']}/spectre/jobs").json()["job_id"]
    wrong_kind = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{dex_job}/apply")
    assert wrong_kind.status_code == 404

    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]
    unfinished = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert unfinished.status_code == 409


def test_isolated_provider_later_unseen_dex_keeps_caller_check(client, ctx):
    """Per-class provenance: a failed LATER dex entry cannot shadow a class
    claimed first in runtime order, so a fully-evidenced caller_check_absent
    survives a globally incomplete ledger (dex_complete stays honestly
    False; only the shadowing-dependent downgrade is lifted)."""
    app, scan = _surface_ready_scan(client)
    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]

    payload = _provider_worker_payload(
        app["sha256"],
        methods=3,
        ledger=[
            {"entry": "classes.dex", "status": "parsed", "size_bytes": 100, "methods": 3},
            {"entry": "classes2.dex", "status": "failed-parse", "size_bytes": 50,
             "error": "BadDEX"},
        ],
        caller_check_absent=True,
        origin_entry="classes.dex", origin_position=0,
    )
    assert _complete_provider_job(client, ctx, scan, payload) == job_id

    applied = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert applied.status_code == 200, applied.text
    result = applied.json()["results"][0]
    assert applied.json()["dex_complete"] is False
    # provenance sound: the clause keeps its evidence
    assert result["attributes"]["caller_check_absent"] is True


def test_isolated_provider_unseen_earlier_dex_downgrades_caller_check(client, ctx):
    """An entry BEFORE the supplying one in runtime order that could not be
    parsed may carry the copy the device actually loads: the claim cannot
    stand in either direction and is downgraded to unknown."""
    app, scan = _surface_ready_scan(client)
    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]

    payload = _provider_worker_payload(
        app["sha256"],
        methods=3,
        ledger=[
            {"entry": "classes.dex", "status": "failed-parse", "size_bytes": 100,
             "error": "BadDEX"},
            {"entry": "classes2.dex", "status": "parsed", "size_bytes": 100, "methods": 3},
        ],
        caller_check_absent=True,
        origin_entry="classes2.dex", origin_position=1,
    )
    assert _complete_provider_job(client, ctx, scan, payload) == job_id

    applied = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert applied.status_code == 200, applied.text
    result = applied.json()["results"][0]
    assert applied.json()["dex_complete"] is False
    # downgraded to unknown: the clause carries no evidence either way
    assert "caller_check_absent" not in result["attributes"]
    assert result["verdict"] == "insufficient_evidence"


def test_isolated_provider_duplicated_class_downgrades_caller_check(client, ctx):
    """A class body present in two dex files rests on the first-wins
    classpath-order assumption: the claim is downgraded to unknown."""
    app, scan = _surface_ready_scan(client)
    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]

    payload = _provider_worker_payload(
        app["sha256"],
        caller_check_absent=True,
        origin_duplicated=True,
    )
    assert _complete_provider_job(client, ctx, scan, payload) == job_id

    applied = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert applied.status_code == 200, applied.text
    result = applied.json()["results"][0]
    assert "caller_check_absent" not in result["attributes"]
    assert result["verdict"] == "insufficient_evidence"


def test_inline_provider_analysis_requires_test_env_or_flag(client, ctx):
    from dataclasses import replace
    app, scan = _surface_ready_scan(client)
    ctx.settings = replace(ctx.settings, env="development")
    try:
        resp = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis")
        assert resp.status_code == 503
        assert "isolated worker job" in resp.json()["detail"]
    finally:
        ctx.settings = replace(ctx.settings, env="test")


def test_provider_inline_flag_is_ignored_in_production(client, ctx, monkeypatch):
    """The local-development opt-in must never bypass containment in production."""
    from dataclasses import replace
    app, scan = _surface_ready_scan(client)
    monkeypatch.setenv("MOBIUS_PROVIDER_INLINE", "1")
    ctx.settings = replace(ctx.settings, env="production")
    try:
        resp = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis")
        assert resp.status_code == 503
    finally:
        ctx.settings = replace(ctx.settings, env="test")


def test_isolated_provider_apply_fails_after_authorization_revoked(client, ctx):
    """Revocation between queue/claim and apply must stop the application of
    the worker result and leave zero findings."""
    app, scan = _surface_ready_scan(client)
    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]
    assert _complete_provider_job(client, ctx, scan, _provider_worker_payload(app["sha256"])) == job_id

    from mobius.adapters.models import AuthorizationRow
    from mobius.adapters.events import utcnow
    with ctx.session() as session:
        session.get(AuthorizationRow, scan["authorization_id"]).revoked_at = utcnow()
        session.commit()

    applied = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert applied.status_code == 422
    assert "revoked or expired" in applied.text
    # truthful terminal rejection, committed despite the 422 rollback
    assert client.get(
        f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}"
    ).json()["status"] == "rejected"
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []


def test_isolated_provider_apply_fails_after_authorization_expires(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]
    assert _complete_provider_job(client, ctx, scan, _provider_worker_payload(app["sha256"])) == job_id

    from mobius.adapters.models import AuthorizationRow
    with ctx.session() as session:
        session.get(AuthorizationRow, scan["authorization_id"]).expires_at = "2020-01-01T00:00:00Z"
        session.commit()

    applied = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert applied.status_code == 422
    assert "revoked or expired" in applied.text
    assert client.get(
        f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}"
    ).json()["status"] == "rejected"
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []


def test_isolated_provider_apply_is_atomic_when_recording_fails(client, ctx, monkeypatch):
    """A failure while recording the SECOND operation must roll back the first:
    apply is all-or-nothing, never partial findings."""
    app, scan = _surface_ready_scan(client)
    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]
    payload = _provider_worker_payload(app["sha256"], operations=("read", "write"))
    assert _complete_provider_job(client, ctx, scan, payload) == job_id

    from mobius.services.validation import ValidationService
    real_validate = ValidationService.validate
    calls = {"n": 0}

    def fail_second(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("simulated gate failure mid-recording")
        return real_validate(self, *args, **kwargs)

    monkeypatch.setattr(ValidationService, "validate", fail_second)
    # TestClient re-raises server exceptions; the dependency's rollback runs
    # during teardown before the re-raise reaches here.
    import pytest as _pytest
    with _pytest.raises(RuntimeError, match="simulated gate failure"):
        client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert calls["n"] == 2
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []
    evidence = client.get(f"/api/v1/scans/{scan['id']}/evidence").json()["items"]
    assert [e for e in evidence if e["kind"] == "tool-output"] == []  # recon's manifest stays
    # the job is NOT marked applied: a fixed deployment can apply it later
    assert client.get(
        f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}"
    ).json()["applied"] is False


def test_succeeded_provider_job_is_never_reclaimed(client, ctx):
    """Worker-side exactly-once: a succeeded job leaves the claim pool."""
    from mobius.services.worker_queue import WorkerQueue
    app, scan = _surface_ready_scan(client)
    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]
    with ctx.session() as session:
        queue = WorkerQueue(session)
        claimed = queue.claim("provider-worker-test")
        assert claimed is not None and claimed.id == job_id
        queue.succeed(job_id, "provider-worker-test", _provider_worker_payload(app["sha256"]))
        session.commit()
    with ctx.session() as session:
        assert WorkerQueue(session).claim("provider-worker-test") is None


def test_invalid_payload_job_is_terminally_rejected_and_reenqueuable(client, ctx):
    """A succeeded job whose payload can never be applied must not deadlock the
    investigation: apply marks it terminally rejected (committed separately
    from the rolled-back request), the evidence stays on the row, and a fresh
    job can be enqueued, completed and applied."""
    app, scan = _surface_ready_scan(client)
    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]

    bad = _provider_worker_payload(app["sha256"], ledger=[
        {"entry": "classes.dex", "status": "parsed", "size_bytes": 100, "methods": 999},
    ])  # ledger count contradicts methods_adapted
    assert _complete_provider_job(client, ctx, scan, bad) == job_id

    applied = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert applied.status_code == 422

    status = client.get(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}")
    assert status.json()["status"] == "rejected"
    assert status.json()["error_code"] == "InvalidWorkerPayload"
    assert "ledger" in status.json()["error_detail"]  # retained rejection evidence
    assert status.json()["applied"] is False

    # the rejection survived the rolled-back request: a new job can be queued
    requeued = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs")
    assert requeued.status_code == 202, requeued.text
    new_job = requeued.json()["job_id"]
    assert new_job != job_id
    good = _provider_worker_payload(app["sha256"])
    assert _complete_provider_job(client, ctx, scan, good) == new_job
    applied = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{new_job}/apply")
    assert applied.status_code == 200, applied.text

    # and a SECOND run after an applied one is refused at ENQUEUE, before any
    # compute is queued
    third = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs")
    assert third.status_code == 409
    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"]
    provider_findings = [f for f in findings
                         if f["category"] == "exported-provider-unprotected-sink"]
    assert len(provider_findings) == 1  # no duplication


def test_inline_provider_analysis_is_blocked_after_applied_job(client, ctx):
    app, scan = _surface_ready_scan(client)
    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]
    payload = _provider_worker_payload(app["sha256"])
    assert _complete_provider_job(client, ctx, scan, payload) == job_id
    assert client.post(
        f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply"
    ).status_code == 200

    inline = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis")
    assert inline.status_code == 409  # lifecycle gate, not duplicate findings


def test_apply_rejects_staged_digest_mismatch(client, ctx):
    """The host-side staged digest is an independent anchor: a job whose
    recorded staged bytes do not match the authorized artifact is unappliable
    even when the worker payload's own digest field agrees."""
    app, scan = _surface_ready_scan(client)
    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]
    payload = _provider_worker_payload(app["sha256"])
    from mobius.services.worker_queue import WorkerQueue
    with ctx.session() as session:
        queue = WorkerQueue(session)
        claimed = queue.claim("provider-worker-test")
        queue.succeed(claimed.id, "provider-worker-test", payload,
                      staged_sha256="f" * 64)  # host staged different bytes
        session.commit()

    applied = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert applied.status_code == 422
    assert "staged-input digest" in applied.text
    status = client.get(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}")
    assert status.json()["status"] == "rejected"
    assert client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"] == []


def test_legacy_second_job_terminalizes_safely_after_first_applied(client, ctx):
    """A job enqueued BEFORE the first one was applied (legal then) must not
    dead-end: applying it after the first job's apply marks it terminally
    rejected, does not duplicate findings, and does not block or crash."""
    app, scan = _surface_ready_scan(client)
    job1 = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]
    payload = _provider_worker_payload(app["sha256"])
    assert _complete_provider_job(client, ctx, scan, payload) == job1
    applied = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job1}/apply")
    assert applied.status_code == 200

    # simulate the legacy second job directly (enqueue now refuses, correctly)
    from mobius.services.worker_queue import WorkerQueue
    with ctx.session() as session:
        job2 = WorkerQueue(session)._flush_new(
            __import__("mobius.adapters.models", fromlist=["WorkerJobRow"]).WorkerJobRow(
                id="legacy-second-job", investigation_id=scan["id"],
                kind="provider_analysis", artifact_key=app["artifact_key"],
                status="succeeded", attempts=1, result_json=payload,
                created_at="2026-11-19T00:00:00.000Z",
                staged_sha256=app["sha256"],
            )
        )
        session.commit()

    applied2 = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/legacy-second-job/apply")
    assert applied2.status_code == 422
    assert "already applied" in applied2.text
    status = client.get(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/legacy-second-job")
    assert status.json()["status"] == "rejected"
    findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"]
    provider_findings = [f for f in findings
                         if f["category"] == "exported-provider-unprotected-sink"]
    assert len(provider_findings) == 1
    # terminal state persisted despite the 422 rollback: still rejected on re-read
    assert client.get(
        f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/legacy-second-job"
    ).json()["status"] == "rejected"


def test_partial_dex_downgrades_refutation_to_unknown(client, ctx):
    """Blocker F: a failed-parse entry EARLIER in runtime order than the
    supplying one may carry the copy the runtime actually loads. An
    'enforcing' guard found in the analysed copy must NOT refute:
    caller_check_absent=False downgrades to None exactly like True."""
    app, scan = _surface_ready_scan(client)
    job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]
    ops = []
    for name in ("read", "write"):
        ops.append({
            "operation": name,
            "protection_status": "unprotected",
            "protection_permission": None,
            "protection_basis": "no provider permission declared",
            "caller_check_absent": False,  # 'enforcing' evidence on partial code
            "guard_findings": [{
                "api": "Landroid/content/Context;->checkCallingPermission",
                "outcome": "enforcing", "detail": "result gates sink"}],
            "coverage_complete": True,
            "sink_flows": [{"method": "com.example.NotesProvider.query",
                            "sink": "SQLiteQueryBuilder.query",
                            "detail": "caller-controlled selection at offset 4"}],
            "flow_complete": True,
            "evidence_classes": ["com.example.NotesProvider"],
        })
    payload = _provider_worker_payload(
        app["sha256"], operations=("read", "write"),
        origin_entry="classes2.dex", origin_position=1,
    )
    payload["exposures"][0]["operations"] = ops
    payload["methods_adapted"] = 1
    payload["dex_coverage"] = [
        {"entry": "classes.dex", "status": "failed-parse", "size_bytes": 100,
         "error": "RuntimeError"},
        {"entry": "classes2.dex", "status": "parsed", "size_bytes": 100, "methods": 1},
    ]
    assert _complete_provider_job(client, ctx, scan, payload) == job_id
    applied = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
    assert applied.status_code == 200, applied.text
    for result in applied.json()["results"]:
        # no caller_check_absent attribute at all: unknown stays missing
        assert "caller_check_absent" not in result["attributes"]


def test_model_consent_endpoint_accepts_opencode_and_rejects_unknown_providers(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"]).json()
    scan = _scan(client, app["id"], auth["id"]).json()

    # Scan creation refuses to carry consent (it must be granted explicitly later).
    refused = client.post(
        "/api/v1/scans",
        json={
            "application_id": app["id"],
            "authorization_id": auth["id"],
            "objective": "Determine whether exported components reach a privileged sink.",
            "intensity": 0,
            "llm_data_sharing": True,
        },
    )
    assert refused.status_code == 422

    # Unknown providers are rejected by the request schema.
    bogus = client.put(
        f"/api/v1/scans/{scan['id']}/model-consent",
        json={"enabled": True, "provider": "openai"},
    )
    assert bogus.status_code == 422

    # Enabled consent must name a provider.
    unnamed = client.put(
        f"/api/v1/scans/{scan['id']}/model-consent",
        json={"enabled": True},
    )
    assert unnamed.status_code in (409, 422)

    # opencode is an explicit, revocable data-disclosure consent.
    ok = client.put(
        f"/api/v1/scans/{scan['id']}/model-consent",
        json={"enabled": True, "provider": "opencode"},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["llm_data_sharing"] == {
        "enabled": True,
        "provider": "opencode",
        "auto_veritas": False,
    }

    # Revocation clears the named provider.
    off = client.put(
        f"/api/v1/scans/{scan['id']}/model-consent",
        json={"enabled": False},
    )
    assert off.status_code == 200
    assert off.json()["llm_data_sharing"]["enabled"] is False
    assert off.json()["llm_data_sharing"]["provider"] is None
