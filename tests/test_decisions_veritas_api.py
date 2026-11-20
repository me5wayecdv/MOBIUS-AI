"""HTTP coverage for the decision-provenance replay API (D-025) and the
VERITAS advisory review route (D-026).

Decisions are seeded through the ORM (single-table adds only - see conftest),
then read back over the real app. VERITAS is exercised through its failure
modes here; the model-backed path itself is covered in test_veritas.py.
"""

from __future__ import annotations

import hashlib

from mobius.adapters.events import utcnow
from mobius.adapters.models import DecisionRow, EvidenceRow, FindingRow


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


def _add_decision(session, scan_id, suffix, created_at, *, model_id=None, action="callers_of", agent="nexus", action_args=None, output_json=None):
    row = DecisionRow(
        id=f"dec_{suffix}",
        investigation_id=scan_id,
        agent=agent,
        action=action,
        action_args=action_args or {"method": "a"},
        output_json=output_json,
        model_id=model_id,
        considered_evidence=["ev_a"],
        alternatives=[{"action": "stop", "reason": "budget"}],
        expected_outcome="Callers are enumerated",
        uncertainty=None,
        prompt_version="v1",
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


def _review_raising(exc):
    def _raise(self, *args, **kwargs):
        raise exc

    return _raise


def test_veritas_review_budget_exhaustion_is_409(client, session, monkeypatch):
    from mobius.services.model_provider import ModelBudgetExceeded
    from mobius.services.veritas import VeritasReviewService

    scan_id = _make_scan(client)
    finding_id = _add_finding(session, scan_id)
    monkeypatch.setattr(
        VeritasReviewService,
        "review",
        _review_raising(ModelBudgetExceeded("model token budget is exhausted")),
    )
    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review",
        params={"producer_model_id": "qwen2.5:1.5b"},
    )
    assert response.status_code == 409
    assert response.json()["code"] == "BUDGET_EXHAUSTED"


def test_veritas_review_provider_failure_is_503(client, session, monkeypatch):
    from mobius.services.model_provider import ModelUnavailable
    from mobius.services.veritas import VeritasReviewService

    scan_id = _make_scan(client)
    finding_id = _add_finding(session, scan_id)
    monkeypatch.setattr(
        VeritasReviewService,
        "review",
        _review_raising(ModelUnavailable("Ollama request failed: URLError")),
    )
    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review",
        params={"producer_model_id": "qwen2.5:1.5b"},
    )
    assert response.status_code == 503
    assert response.json()["code"] == "MODEL_PROVIDER_UNAVAILABLE"


def test_veritas_review_unexpected_gateway_failure_is_503_not_500(
    client, session, monkeypatch
):
    from mobius.services.model_provider import ModelProviderError
    from mobius.services.veritas import VeritasReviewService

    scan_id = _make_scan(client)
    finding_id = _add_finding(session, scan_id)
    monkeypatch.setattr(
        VeritasReviewService,
        "review",
        _review_raising(ModelProviderError("unexpected gateway failure")),
    )
    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review",
        params={"producer_model_id": "qwen2.5:1.5b"},
    )
    assert response.status_code == 503
    assert response.json()["code"] == "MODEL_PROVIDER_UNAVAILABLE"


def _rogue_client():
    """A second caller identity via dependency override of the analyst stub."""
    from fastapi.testclient import TestClient

    from mobius.api.app import create_app
    from mobius.api.deps import analyst_id

    app = create_app()
    app.dependency_overrides[analyst_id] = lambda: "analyst-2"
    return TestClient(app)


def test_decisions_replay_rejects_other_owner(client, session):
    scan_id = _make_scan(client)  # created by the default analyst-1 stub
    rogue = _rogue_client()
    assert rogue.get(f"/api/v1/scans/{scan_id}/decisions").status_code == 404


def test_veritas_review_rejects_other_owner(client, session):
    scan_id = _make_scan(client)
    finding_id = _add_finding(session, scan_id)
    rogue = _rogue_client()
    response = rogue.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review",
        params={"producer_model_id": "qwen2.5:1.5b"},
    )
    assert response.status_code == 404


def test_decisions_replay_paginates_with_bounded_keyset(client, session):
    scan_id = _make_scan(client)
    # Two rows share one timestamp: ordering must fall back to id, deterministically.
    d1 = _add_decision(session, scan_id, "21", "2026-11-19T05:00:00.000Z")
    d2 = _add_decision(session, scan_id, "22", "2026-11-19T05:00:00.000Z")
    d3 = _add_decision(session, scan_id, "23", "2026-11-19T05:01:00.000Z")

    page1 = client.get(f"/api/v1/scans/{scan_id}/decisions?limit=2").json()
    assert [item["id"] for item in page1["items"]] == [d1, d2]
    assert page1["next_cursor"] == d2

    page2 = client.get(
        f"/api/v1/scans/{scan_id}/decisions?limit=2&after={d2}"
    ).json()
    assert [item["id"] for item in page2["items"]] == [d3]
    assert page2["next_cursor"] is None


def test_decisions_replay_rejects_unknown_or_cross_scan_cursor(client, session):
    scan_a = _make_scan(client)
    scan_b = _make_scan(client)
    b1 = _add_decision(session, scan_b, "31", "2026-11-19T05:00:00.000Z")

    assert (
        client.get(f"/api/v1/scans/{scan_a}/decisions?after=dec_missing").status_code
        == 404
    )
    # A cursor from another scan leaks nothing: it is rejected, not applied.
    assert (
        client.get(f"/api/v1/scans/{scan_a}/decisions?after={b1}").status_code == 404
    )


def _configure_gateway(ctx, response_json, model_id="reviewer-v2"):
    import json as _json  # noqa: F401 - response_json arrives pre-serialized

    from mobius.services.model_provider import (
        DeterministicMockProvider,
        StructuredModelGateway,
    )

    ctx.model_gateway = StructuredModelGateway(
        DeterministicMockProvider(
            response_json, model_id=model_id, prompt_tokens=30, completion_tokens=20
        ),
        model="reviewer-v2",
    )


def _enable_consent(session, scan_id):
    from mobius.adapters.models import InvestigationRow

    row = session.get(InvestigationRow, scan_id)
    row.llm_data_sharing = {"enabled": True, "provider": "mock"}
    session.commit()


def _add_evidence(session, scan_id, evidence_id="ev_route"):
    session.add(
        EvidenceRow(
            id=evidence_id,
            investigation_id=scan_id,
            kind="code_analysis",
            sha256="b" * 64,
            object_key="evidence/route-test",
            byte_size=64,
            truncated=False,
            redacted=True,
            summary="Persisted route-test evidence of a reachable file write.",
            produced_by="SPECTRE",
            created_at=utcnow(),
        )
    )
    session.commit()
    return evidence_id


_VALID_REPLY = (
    '{"disposition": "no_material_challenge", '
    '"summary": "Persisted evidence supports the gate verdict.", "challenges": []}'
)


def test_veritas_review_http_success_with_configured_gateway(client, session, ctx):
    import json

    _configure_gateway(ctx, _VALID_REPLY)
    scan_id = _make_scan(client)
    evidence_id = _add_evidence(session, scan_id)
    finding_id = _add_finding(session, scan_id, evidence_refs=[evidence_id])
    _enable_consent(session, scan_id)

    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review",
        params={"producer_model_id": "producer-v1"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["disposition"] == "no_material_challenge"
    assert body["model_id"] == "reviewer-v2"
    assert body["advisory_only"] is True
    assert body["gate_verdict_unchanged"] is True
    # Caller-supplied producer with no persisted producer decision: not proven.
    assert body["producer_model_verified"] is False
    assert body["independence_assured"] is False

    decision = session.get(DecisionRow, body["decision_id"])
    assert decision is not None
    assert decision.agent == "VERITAS"
    assert decision.considered_evidence == [evidence_id]
    # The finding is untouched by the advisory review.
    finding = session.get(FindingRow, finding_id)
    assert finding.status == "pending"


def test_veritas_review_http_consent_disabled_is_409(client, session, ctx):
    _configure_gateway(ctx, _VALID_REPLY)
    scan_id = _make_scan(client)
    evidence_id = _add_evidence(session, scan_id)
    finding_id = _add_finding(session, scan_id, evidence_refs=[evidence_id])
    # No consent recorded on the investigation.
    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review",
        params={"producer_model_id": "producer-v1"},
    )
    assert response.status_code == 409
    assert response.json()["code"] == "MODEL_CONSENT_REQUIRED"


def test_veritas_review_http_unconvertible_output_is_captured_needs_review(client, session, ctx):
    _configure_gateway(
        ctx, '{"disposition": "challenge", "summary": "x", "challenges": "not-a-list"}'
    )
    scan_id = _make_scan(client)
    evidence_id = _add_evidence(session, scan_id)
    finding_id = _add_finding(session, scan_id, evidence_refs=[evidence_id])
    _enable_consent(session, scan_id)
    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review",
        params={"producer_model_id": "producer-v1"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "needs_review"
    assert body["disposition"] is None
    assert body["challenges"] == []
    assert body["failure_class"].startswith("model reply unconvertible")
    # the raw model reply never leaves the server
    assert "not-a-list" not in response.text


def _register_producer_actions(monkeypatch, *actions):
    from mobius.services import veritas as veritas_module

    monkeypatch.setattr(
        veritas_module, "_FINDING_PRODUCER_ACTIONS", frozenset(actions)
    )


def _seed_producer(session, scan_id, suffix, model_id, finding_id, action="propose_finding", agent="nexus", action_args=None, output_json=None):
    return _add_decision(
        session,
        scan_id,
        suffix,
        "2026-11-19T04:00:00.000Z",
        model_id=model_id,
        action=action,
        agent=agent,
        action_args=action_args if action_args is not None else {"finding_id": finding_id},
        output_json=output_json if output_json is not None else {"finding_id": finding_id},
    )


def test_veritas_review_http_conflicting_claimed_producer_is_422(client, session, ctx, monkeypatch):
    _configure_gateway(ctx, _VALID_REPLY)
    _register_producer_actions(monkeypatch, "propose_finding")
    scan_id = _make_scan(client)
    evidence_id = _add_evidence(session, scan_id)
    finding_id = _add_finding(session, scan_id, evidence_refs=[evidence_id])
    _enable_consent(session, scan_id)
    # Persisted provenance: producer-v1 produced this finding.
    _seed_producer(session, scan_id, "41", "producer-v1", finding_id)
    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review",
        params={"producer_model_id": "producer-v2"},  # lies about the producer
    )
    assert response.status_code == 422
    assert response.json()["code"] == "MODEL_OUTPUT_INVALID"
    # Stable client-facing message; no model/transport internals leak.
    assert "producer-v2" not in response.json().get("detail", "")


def test_veritas_review_http_matching_persisted_producer_proves_independence(
    client, session, ctx, monkeypatch
):
    _configure_gateway(ctx, _VALID_REPLY)
    _register_producer_actions(monkeypatch, "propose_finding")
    scan_id = _make_scan(client)
    evidence_id = _add_evidence(session, scan_id)
    finding_id = _add_finding(session, scan_id, evidence_refs=[evidence_id])
    _enable_consent(session, scan_id)
    _seed_producer(session, scan_id, "42", "producer-v1", finding_id)
    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review",
        params={"producer_model_id": "producer-v1"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["producer_model_id"] == "producer-v1"
    assert body["producer_model_verified"] is True
    assert body["independence_assured"] is True


def test_veritas_review_repeated_never_self_resolves_producer(client, session, ctx):
    """A prior VERITAS review decision references the finding and carries a
    model_id; it must NEVER be treated as the finding's producer, so repeated
    reviews behave identically."""
    _configure_gateway(ctx, _VALID_REPLY)
    scan_id = _make_scan(client)
    evidence_id = _add_evidence(session, scan_id)
    finding_id = _add_finding(session, scan_id, evidence_refs=[evidence_id])
    _enable_consent(session, scan_id)

    url = f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review"
    first = client.post(url, params={"producer_model_id": "producer-v1"})
    second = client.post(url, params={"producer_model_id": "producer-v1"})
    assert first.status_code == 200 and second.status_code == 200
    for body in (first.json(), second.json()):
        assert body["producer_model_verified"] is False
        assert body["independence_assured"] is False


def test_veritas_review_rows_excluded_even_under_registered_action(
    client, session, ctx, monkeypatch
):
    """Defense in depth: even if a review action name were ever registered,
    decisions written by VERITAS itself are structurally excluded."""
    _configure_gateway(ctx, _VALID_REPLY)
    _register_producer_actions(monkeypatch, "review_finding")
    scan_id = _make_scan(client)
    evidence_id = _add_evidence(session, scan_id)
    finding_id = _add_finding(session, scan_id, evidence_refs=[evidence_id])
    _enable_consent(session, scan_id)

    url = f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review"
    first = client.post(url, params={"producer_model_id": "producer-v1"})
    second = client.post(url, params={"producer_model_id": "producer-v1"})
    assert first.status_code == 200 and second.status_code == 200
    assert second.json()["producer_model_verified"] is False


def test_veritas_review_ambiguous_producer_candidates_fail_closed(
    client, session, ctx, monkeypatch
):
    _configure_gateway(ctx, _VALID_REPLY)
    _register_producer_actions(monkeypatch, "propose_finding")
    scan_id = _make_scan(client)
    evidence_id = _add_evidence(session, scan_id)
    finding_id = _add_finding(session, scan_id, evidence_refs=[evidence_id])
    _enable_consent(session, scan_id)
    _seed_producer(session, scan_id, "43", "producer-v1", finding_id)
    _seed_producer(session, scan_id, "44", "producer-v9", finding_id)
    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review",
        params={"producer_model_id": "producer-v1"},
    )
    assert response.status_code == 422
    assert response.json()["code"] == "MODEL_OUTPUT_INVALID"


def test_veritas_review_malformed_decision_json_never_crashes(
    client, session, ctx, monkeypatch
):
    """Unhashable/nested JSON shapes in decision fields must not raise; the
    producer simply stays unresolved."""
    _configure_gateway(ctx, _VALID_REPLY)
    _register_producer_actions(monkeypatch, "propose_finding")
    scan_id = _make_scan(client)
    evidence_id = _add_evidence(session, scan_id)
    finding_id = _add_finding(session, scan_id, evidence_refs=[evidence_id])
    _enable_consent(session, scan_id)
    _seed_producer(
        session,
        scan_id,
        "45",
        "producer-v1",
        finding_id,
        action_args={"finding_id": {"unexpected": ["nested", "structure"]}},
        output_json="not-an-object",
    )
    response = client.post(
        f"/api/v1/scans/{scan_id}/findings/{finding_id}/veritas-review",
        params={"producer_model_id": "producer-v1"},
    )
    assert response.status_code == 200
    assert response.json()["producer_model_verified"] is False
