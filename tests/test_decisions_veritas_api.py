"""HTTP coverage for the decision-provenance replay API (D-025) and the
VERITAS advisory review route (D-026).

Decisions are seeded through the ORM (single-table adds only - see conftest),
then read back over the real app. VERITAS is exercised through its failure
modes here; the model-backed path itself is covered in test_veritas.py.
"""

from __future__ import annotations

import hashlib

from mobius.adapters.events import utcnow
from mobius.adapters.models import DecisionRow, FindingRow


def _upload(client, data=None, name="app.apk"):
    from conftest import make_apk

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


def _scan(client, app_id, auth_id):
    return client.post(
        "/api/v1/scans",
        json={
            "application_id": app_id,
            "authorization_id": auth_id,
            "objective": "Determine whether exported components reach a privileged sink.",
            "intensity": 0,
        },
    )


def _make_scan(client):
    from conftest import make_apk

    apk = make_apk()
    sha = hashlib.sha256(apk).hexdigest()
    app_id = _upload(client, apk).json()["id"]
    auth_id = _authorize(client, sha).json()["id"]
    return _scan(client, app_id, auth_id).json()["id"]


def _add_decision(session, scan_id, suffix, created_at):
    row = DecisionRow(
        id=f"dec_{suffix}",
        investigation_id=scan_id,
        agent="nexus",
        action="callers_of",
        action_args={"method": "a"},
        considered_evidence=["ev_a"],
        alternatives=[{"action": "stop", "reason": "budget"}],
        expected_outcome="Callers are enumerated",
        uncertainty=None,
        prompt_version="v1",
        model_id=None,
        provider=None,
        created_at=created_at,
    )
    session.add(row)
    session.commit()
    return row.id


def test_decisions_replay_returns_persisted_provenance_in_order(client, session):
    scan_id = _make_scan(client)
    first = _add_decision(session, scan_id, "01", "2026-11-19T05:00:00.000Z")
    second = _add_decision(session, scan_id, "02", "2026-11-19T05:01:00.000Z")

    body = client.get(f"/api/v1/scans/{scan_id}/decisions").json()
    assert [item["id"] for item in body["items"]] == [first, second]
    item = body["items"][0]
    assert item["action"] == "callers_of"
    assert item["alternatives"] == [{"action": "stop", "reason": "budget"}]
    # Full provenance surface exists even when no model was involved.
    for key in (
        "prompt_version",
        "model_id",
        "provider",
        "requested_model",
        "response_sha256",
        "output_json",
        "created_at",
    ):
        assert key in item
    # Deterministic decisions record no provider/model.
    assert item["provider"] is None and item["model_id"] is None


def test_decisions_replay_is_scoped_and_cursored(client, session):
    scan_a = _make_scan(client)
    scan_b = _make_scan(client)
    a1 = _add_decision(session, scan_a, "11", "2026-11-19T05:00:00.000Z")
    _add_decision(session, scan_a, "12", "2026-11-19T05:01:00.000Z")
    b1 = _add_decision(session, scan_b, "13", "2026-11-19T05:02:00.000Z")

    items = client.get(f"/api/v1/scans/{scan_b}/decisions").json()["items"]
    assert [item["id"] for item in items] == [b1]

    after = client.get(f"/api/v1/scans/{scan_a}/decisions?after={a1}").json()["items"]
    assert [item["id"] for item in after] == ["dec_12"]


def test_decisions_replay_unknown_scan_is_404(client):
    assert client.get("/api/v1/scans/scn_missing/decisions").status_code == 404


def _add_finding(session, scan_id, finding_id="fnd_01", evidence_refs=None):
    now = utcnow()
    session.add(
        FindingRow(
            id=finding_id,
            investigation_id=scan_id,
            title="Advisory review target",
            category="test",
            description="A finding for VERITAS wiring tests.",
            evidence_refs=evidence_refs or [],
            severity="low",
            confidence=0.5,
            status="pending",
            discovered_by="test",
            created_at=now,
            updated_at=now,
        )
    )
    session.commit()
    return finding_id


def test_veritas_review_unknown_finding_is_404(client, session):
    scan_id = _make_scan(client)
    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/fnd_missing/veritas-review",
        params={"producer_model_id": "qwen2.5:1.5b"},
    )
    assert response.status_code == 404


def test_veritas_review_rejects_finding_from_another_scan(client, session):
    scan_a = _make_scan(client)
    scan_b = _make_scan(client)
    finding_id = _add_finding(session, scan_b)
    response = client.post(
        f"/api/v1/scans/{scan_a}/findings/{finding_id}/veritas-review",
        params={"producer_model_id": "qwen2.5:1.5b"},
    )
    assert response.status_code == 404


def test_veritas_review_without_model_gateway_is_explicit_409(client, session):
    scan_id = _make_scan(client)
    finding_id = _add_finding(session, scan_id)
    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review",
        params={"producer_model_id": "qwen2.5:1.5b"},
    )
    # No model gateway is configured in the test environment: the route must
    # fail closed with the stable consent code, never a 500.
    assert response.status_code == 409
    assert response.json()["code"] == "MODEL_CONSENT_REQUIRED"
