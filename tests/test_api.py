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
    assert len(gates) == 10
    exported = next(g for g in gates if g["category"] == "exported-component-no-permission")
    assert exported["required_evidence"] == ["exported", "permission", "caller_check_absent", "sink_reachable"]
    assert exported["maswe"] == ["MASWE-0029"]


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
    auth = _authorize(client, app["sha256"], target_package="com.example.demo").json()
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
    assert "EventSource" in html
    # The event panel is replayed from the store, so an unknown event type still shows.
    assert "/events?limit=200" in html
    # And it must say where its numbers come from.
    assert "Every value on this page is read from the API" in html
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



def test_recon_rejects_authorization_for_a_different_manifest_package(client):
    app = _upload(client).json()
    auth = _authorize(client, app["sha256"], target_package="com.attacker.claim").json()
    scan = _scan(client, app["id"], auth["id"]).json()

    response = client.post(f"/api/v1/scans/{scan['id']}/recon")
    assert response.status_code == 409
    assert response.json()["code"] == "AUTH_REQUIRED"
    # A mismatched package must not leave behind a manifest evidence record or surface.
    assert client.get(f"/api/v1/scans/{scan['id']}/evidence").json()["items"] == []
    assert client.get(f"/api/v1/scans/{scan['id']}/surface").json()["observations"] == []
