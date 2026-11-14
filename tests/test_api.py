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
    first = _upload(client).json()
    second = _upload(client).json()
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
