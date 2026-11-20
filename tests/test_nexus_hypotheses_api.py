"""HTTP coverage for the NEXUS hypothesis route's stable model-failure mapping.

The model path itself is covered in test_nexus_hypotheses.py; these tests pin
the wire contract: rejection surfaces as a stable 422 (never a bare 500, never
raw model output), rejection diagnostics are committed independently of the
failed request, and the no-consent deterministic contract is unchanged.
"""

from __future__ import annotations

import hashlib

from mobius.adapters.models import DecisionRow, EventRow, InvestigationRow


def _make_scan(client):
    from conftest import make_apk

    apk = make_apk()
    sha = hashlib.sha256(apk).hexdigest()
    app_id = client.post(
        "/api/v1/applications",
        files={"file": ("app.apk", apk, "application/vnd.android.package-archive")},
    ).json()["id"]
    auth_id = client.post(
        "/api/v1/authorizations",
        json={
            "apk_sha256": sha,
            "target_package": "com.example",
            "scope_text": "Static analysis of the supplied artefact only; no execution.",
            "statement": "I am authorised to analyse this build.",
            "max_intensity": 2,
            "expires_at": "2030-01-01T00:00:00Z",
        },
    ).json()["id"]
    return client.post(
        "/api/v1/scans",
        json={
            "application_id": app_id,
            "authorization_id": auth_id,
            "objective": "Determine whether exported components reach a privileged sink.",
            "intensity": 0,
        },
    ).json()["id"]


def _configure_gateway(ctx, response_json):
    from mobius.services.model_provider import (
        DeterministicMockProvider,
        StructuredModelGateway,
    )

    ctx.model_gateway = StructuredModelGateway(
        DeterministicMockProvider(
            response_json, model_id="nexus-test-model", prompt_tokens=30, completion_tokens=20
        ),
        model="nexus-test-model",
    )


def test_nexus_hypotheses_malformed_model_output_is_422_with_committed_rejection(
    client, session, ctx
):
    _configure_gateway(ctx, "{not valid json")
    scan_id = _make_scan(client)
    row = session.get(InvestigationRow, scan_id)
    row.llm_data_sharing = {"enabled": True, "provider": "mock"}
    session.commit()

    response = client.post(f"/api/v1/scans/{scan_id}/nexus/hypotheses")

    assert response.status_code == 422
    assert response.json()["code"] == "MODEL_OUTPUT_INVALID"
    # Stable client-facing message only: raw model output and raw parse details
    # never leave the server.
    assert "{not valid json" not in response.text
    assert "Expecting value" not in response.text

    # The failed request rolled back, but rejection diagnostics were committed
    # independently: initial attempt + exactly two repairs, then a rejection
    # decision without persisted model output.
    session.expire_all()
    events = (
        session.query(EventRow)
        .filter_by(investigation_id=scan_id, type="planner_rejected")
        .order_by(EventRow.seq)
        .all()
    )
    assert [e.payload["reason"] for e in events] == ["schema-invalid"] * 3
    assert [e.payload["final"] for e in events] == [False, False, True]
    decision = session.query(DecisionRow).filter_by(
        investigation_id=scan_id, action="generate_hypotheses_rejected"
    ).one()
    assert decision.output_json is None
    assert decision.action_args["repair_attempts"] == 2
    assert session.query(EventRow).filter_by(
        investigation_id=scan_id, type="hypotheses_generated"
    ).count() == 0


def test_nexus_hypotheses_without_consent_keeps_deterministic_contract(
    client, session, ctx
):
    _configure_gateway(ctx, "{not valid json")
    scan_id = _make_scan(client)

    response = client.post(f"/api/v1/scans/{scan_id}/nexus/hypotheses")

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "deterministic_fallback"
    assert body["repair_attempts"] == 0
    assert body["model_id"] is None
