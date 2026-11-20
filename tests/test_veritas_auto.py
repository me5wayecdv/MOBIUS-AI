"""VERITAS auto-review pass (D-026): opt-in, post-commit, advisory, fail-isolated.

The pass runs AFTER the deterministic pipeline commits, on fresh per-finding
sessions. These tests pin the contract: default-off, per-finding rechecks,
fixed failure tokens, no verdict mutation, no raw error leakage, and an
idempotent re-run that never double-reviews a finding.
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from conftest import make_apk
from mobius.adapters.models import (
    DecisionRow,
    EventRow,
    EvidenceRow,
    FindingRow,
    InvestigationRow,
    VerdictRow,
)
from mobius.core.enums import Severity
from mobius.core.schemas import Budget
from mobius.services import veritas_auto
from mobius.services.intake import IntakeService
from mobius.services.model_provider import (
    DeterministicMockProvider,
    ModelProviderError,
    StructuredModelGateway,
)
from mobius.services.validation import ValidationService
from mobius.services.veritas_auto import SENTINEL_PRODUCER_MODEL_ID, run_auto_review_pass

REPLY = json.dumps({
    "disposition": "no_material_challenge",
    "summary": "The supplied evidence supports the draft; no material challenge.",
    "challenges": [],
})
AUTO_CONSENT = {"enabled": True, "provider": "mock", "auto_veritas": True}


class CountingProvider(DeterministicMockProvider):
    def __init__(self, response_json: str = REPLY):
        super().__init__(response_json, model_id="veritas-model", prompt_tokens=30, completion_tokens=20)
        self.calls = 0

    def complete_json(self, **kwargs):
        self.calls += 1
        return super().complete_json(**kwargs)


class FailingProvider(DeterministicMockProvider):
    def __init__(self, exc: Exception):
        super().__init__(REPLY, model_id="veritas-model", prompt_tokens=30, completion_tokens=20)
        self._exc = exc
        self.calls = 0

    def complete_json(self, **kwargs):
        self.calls += 1
        raise self._exc


def _factory(session):
    return sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)


def _gateway(provider) -> StructuredModelGateway:
    return StructuredModelGateway(provider, model="reviewer-v2")


def _seed(session, store, future_iso, *, consent, discovered_by="SPECTRE", with_evidence=True, budget=None):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "auto-review.apk", uploaded_by="u")
    auth = intake.create_authorization(
        apk_sha256=app.sha256,
        target_package="com.example",
        scope_text="Static analysis of the supplied artefact only.",
        statement="s",
        max_intensity=2,
        granted_by="u",
        expires_at=future_iso,
    )
    kwargs = {}
    if budget is not None:
        kwargs["budget"] = budget
    investigation = intake.create_investigation(
        application_id=app.id,
        authorization_id=auth.id,
        objective="Auto-review pass fixture.",
        intensity=0,
        created_by="u",
        **kwargs,
    )
    row = session.get(InvestigationRow, investigation.id)
    row.llm_data_sharing = consent
    session.flush()
    evidence_id = None
    refs = ()
    if with_evidence:
        evidence_id = "ev_auto_fixture"
        session.add(EvidenceRow(
            id=evidence_id,
            investigation_id=investigation.id,
            kind="code_analysis",
            sha256="b" * 64,
            object_key="evidence/auto",
            byte_size=128,
            truncated=False,
            redacted=True,
            summary="A persisted code observation showing a reachable file write.",
            produced_by="SPECTRE",
            created_at=future_iso,
        ))
        session.flush()
        refs = (evidence_id,)
    finding, verdict = ValidationService(session).validate(
        investigation_id=investigation.id,
        category="exported-component-no-permission",
        attributes={
            "exported": True,
            "permission": None,
            "caller_check_absent": True,
            "sink_reachable": True,
        },
        title="Exported activity writes attacker-supplied path",
        description="The exported activity forwards an untrusted path to a privileged file sink.",
        evidence_refs=refs,
        discovered_by=discovered_by,
        validated_by="DETERMINISTIC_GATE",
        severity=Severity.HIGH,
    )
    session.commit()
    return finding.id, investigation.id, verdict.id, evidence_id


def _review_decisions(session, investigation_id):
    return session.execute(select(DecisionRow).where(
        DecisionRow.investigation_id == investigation_id,
        DecisionRow.agent == "VERITAS",
        DecisionRow.action == "review_finding",
    )).scalars().all()


def _failure_events(session, investigation_id):
    return session.execute(select(EventRow).where(
        EventRow.investigation_id == investigation_id,
        EventRow.type == "veritas_review_failed",
    ).order_by(EventRow.seq)).scalars().all()


def test_pass_reviews_confirmed_finding_once_and_stays_advisory(session, store, future_iso):
    finding_id, investigation_id, verdict_id, evidence_id = _seed(
        session, store, future_iso, consent=dict(AUTO_CONSENT)
    )
    provider = CountingProvider()

    summary = run_auto_review_pass(
        session_factory=_factory(session), gateway=_gateway(provider), investigation_id=investigation_id
    )

    assert (summary["attempted"], summary["completed"], summary["failed"], summary["skipped"]) == (1, 1, 0, 0)
    assert provider.calls == 1
    decisions = _review_decisions(session, investigation_id)
    assert len(decisions) == 1
    assert decisions[0].action_args["producer_model_id"] == SENTINEL_PRODUCER_MODEL_ID
    # Sentinel reviews can never claim independence: the producer is not a
    # persisted model decision, so verification stays explicitly false.
    assert decisions[0].action_args["producer_model_verified"] is False
    assert decisions[0].action_args["advisory_only"] is True
    # Advisory only: the deterministic verdict and finding rows are untouched.
    assert session.get(VerdictRow, verdict_id).verdict == "confirmed"
    assert session.get(FindingRow, finding_id).status == "confirmed"


def test_pass_is_idempotent_across_runs(session, store, future_iso):
    _, investigation_id, _, _ = _seed(session, store, future_iso, consent=dict(AUTO_CONSENT))
    provider = CountingProvider()
    factory = _factory(session)

    first = run_auto_review_pass(session_factory=factory, gateway=_gateway(provider), investigation_id=investigation_id)
    second = run_auto_review_pass(session_factory=factory, gateway=_gateway(provider), investigation_id=investigation_id)

    assert first["completed"] == 1
    assert second["attempted"] == 0
    assert second["skipped"] == 1
    assert second["skips"][0]["reason"] == "already-reviewed"
    assert provider.calls == 1
    assert len(_review_decisions(session, investigation_id)) == 1


def test_pass_skips_without_consent_or_flag(session, store, future_iso):
    _, investigation_id, _, _ = _seed(
        session, store, future_iso, consent={"enabled": True, "provider": "mock"}
    )
    provider = CountingProvider()

    summary = run_auto_review_pass(
        session_factory=_factory(session), gateway=_gateway(provider), investigation_id=investigation_id
    )

    assert summary["attempted"] == 0
    assert summary["skips"][0]["reason"] == "consent-missing"
    assert provider.calls == 0


def test_pass_skips_on_provider_mismatch(session, store, future_iso):
    _, investigation_id, _, _ = _seed(
        session, store, future_iso,
        consent={"enabled": True, "provider": "ollama", "auto_veritas": True},
    )
    provider = CountingProvider()

    summary = run_auto_review_pass(
        session_factory=_factory(session), gateway=_gateway(provider), investigation_id=investigation_id
    )

    assert summary["attempted"] == 0
    assert summary["skips"][0]["reason"] == "provider-mismatch"
    assert provider.calls == 0


def test_pass_fails_closed_without_deterministic_provenance(session, store, future_iso):
    _, investigation_id, _, _ = _seed(
        session, store, future_iso, consent=dict(AUTO_CONSENT), discovered_by="analyst"
    )
    provider = CountingProvider()

    summary = run_auto_review_pass(
        session_factory=_factory(session), gateway=_gateway(provider), investigation_id=investigation_id
    )
    assert summary["attempted"] == 0
    assert summary["skips"][0]["reason"] == "provenance-missing"
    assert provider.calls == 0


def test_provider_error_is_isolated_with_a_fixed_token(session, store, future_iso):
    finding_id, investigation_id, verdict_id, _ = _seed(
        session, store, future_iso, consent=dict(AUTO_CONSENT)
    )
    provider = FailingProvider(ModelProviderError("raw transport detail must never persist"))

    summary = run_auto_review_pass(
        session_factory=_factory(session), gateway=_gateway(provider), investigation_id=investigation_id
    )

    assert (summary["attempted"], summary["completed"], summary["failed"]) == (1, 0, 1)
    assert summary["failures"] == [{"finding_id": finding_id, "reason": "provider-error"}]
    events = _failure_events(session, investigation_id)
    assert len(events) == 1
    assert events[0].payload["reason"] == "provider-error"
    assert "raw transport detail" not in json.dumps(events[0].payload)
    # The deterministic verdict is untouched and the finding stays unreviewed
    # for a later pass (no false success, no silent skip).
    assert session.get(VerdictRow, verdict_id).verdict == "confirmed"
    assert _review_decisions(session, investigation_id) == []


def test_invalid_model_output_is_captured_needs_review_not_a_verdict(session, store, future_iso):
    _, investigation_id, _, _ = _seed(session, store, future_iso, consent=dict(AUTO_CONSENT))
    provider = CountingProvider("{not json")

    summary = run_auto_review_pass(
        session_factory=_factory(session), gateway=_gateway(provider), investigation_id=investigation_id
    )

    assert summary["failed"] == 0
    assert summary["completed"] == 0
    assert summary["needs_review"] == 1
    decisions = _review_decisions(session, investigation_id)
    assert len(decisions) == 1
    assert decisions[0].output_json["status"] == "needs_review"
    assert decisions[0].output_json["failure_class"].startswith("model reply unconvertible")


def test_budget_exhaustion_is_a_distinct_visible_token(session, store, future_iso):
    _, investigation_id, _, _ = _seed(
        session, store, future_iso, consent=dict(AUTO_CONSENT), budget=Budget(max_model_tokens=1)
    )
    provider = CountingProvider()

    summary = run_auto_review_pass(
        session_factory=_factory(session), gateway=_gateway(provider), investigation_id=investigation_id
    )

    assert summary["failed"] == 1
    assert summary["failures"][0]["reason"] == "budget-exhausted"
    events = _failure_events(session, investigation_id)
    assert [e.payload["reason"] for e in events] == ["budget-exhausted"]
    assert provider.calls == 0  # refused before any provider call


def test_run_cap_bounds_the_number_of_reviews(session, store, future_iso):
    _, investigation_id, _, _ = _seed(session, store, future_iso, consent=dict(AUTO_CONSENT))
    provider = CountingProvider()

    summary = run_auto_review_pass(
        session_factory=_factory(session), gateway=_gateway(provider),
        investigation_id=investigation_id, max_reviews=0,
    )

    assert summary["attempted"] == 0
    assert summary["skips"][0]["reason"] == "run-cap-reached"
    assert provider.calls == 0


# ---------------------------------------------------------------------------
# Route wiring: the pass is opt-in, post-commit, and can never mask the scan
# ---------------------------------------------------------------------------

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
    import hashlib

    apk = make_apk()
    sha = hashlib.sha256(apk).hexdigest()
    app_id = _upload(client, apk).json()["id"]
    auth_id = _authorize(client, sha).json()["id"]
    return _scan(client, app_id, auth_id).json()["id"]



def _apk_with_fixture_dex() -> bytes:
    import io as _io
    import pathlib
    import zipfile as _zip

    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.demo"><application>'
        '<activity android:name="AnalysisTest" android:exported="true"/>'
        "</application></manifest>"
    )
    dex = (pathlib.Path(__file__).parent / "fixtures" / "dex" / "AnalysisTest.dex").read_bytes()
    buf = _io.BytesIO()
    with _zip.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
    return buf.getvalue()


def _make_scan_ready(client):
    """A scan at SURFACE_READY: upload + authorise + RECON over a real fixture DEX."""
    app = client.post(
        "/api/v1/applications",
        files={"file": ("demo.apk", _apk_with_fixture_dex(), "application/vnd.android.package-archive")},
    ).json()
    auth = _authorize(client, app["sha256"], target_package="com.example.demo").json()
    scan = _scan(client, app["id"], auth["id"]).json()
    assert client.post(f"/api/v1/scans/{scan['id']}/recon").status_code == 200
    return scan["id"]

def test_nexus_route_without_optin_leaves_response_shape_unchanged(client):
    scan_id = _make_scan_ready(client)

    resp = client.post(f"/api/v1/scans/{scan_id}/nexus")

    assert resp.status_code == 200
    assert "veritas_auto_review" not in resp.json()


def test_nexus_route_with_optin_runs_advisory_pass_after_core_commit(
    client, session, store, future_iso, ctx, monkeypatch
):
    scan_id = _make_scan_ready(client)
    row = session.get(InvestigationRow, scan_id)
    session.add(EvidenceRow(
        id="ev_route_auto",
        investigation_id=scan_id,
        kind="code_analysis",
        sha256="c" * 64,
        object_key="evidence/route-auto",
        byte_size=128,
        truncated=False,
        redacted=True,
        summary="A persisted code observation showing a reachable file write.",
        produced_by="SPECTRE",
        created_at=future_iso,
    ))
    session.flush()
    finding, verdict = ValidationService(session).validate(
        investigation_id=scan_id,
        category="exported-component-no-permission",
        attributes={
            "exported": True,
            "permission": None,
            "caller_check_absent": True,
            "sink_reachable": True,
        },
        title="Exported activity writes attacker-supplied path",
        description="The exported activity forwards an untrusted path to a privileged file sink.",
        evidence_refs=("ev_route_auto",),
        discovered_by="SPECTRE",
        validated_by="DETERMINISTIC_GATE",
        severity=Severity.HIGH,
    )
    row.llm_data_sharing = dict(AUTO_CONSENT)
    session.commit()
    provider = CountingProvider()
    monkeypatch.setattr(ctx, "model_gateway", _gateway(provider))

    resp = client.post(f"/api/v1/scans/{scan_id}/nexus")

    assert resp.status_code == 200
    body = resp.json()
    assert body["veritas_auto_review"]["completed"] == 1
    assert body["veritas_auto_review"]["advisory_only"] is True
    assert provider.calls == 1
    # Core scan result is intact and verdict authority never moved.
    assert body["state"] == "CLOSED"
    assert session.get(VerdictRow, verdict.id).verdict == "confirmed"
    assert session.get(FindingRow, finding.id).status == "confirmed"


def test_nexus_route_never_masks_core_result_when_the_pass_breaks(
    client, session, ctx, monkeypatch
):
    scan_id = _make_scan_ready(client)
    row = session.get(InvestigationRow, scan_id)
    row.llm_data_sharing = dict(AUTO_CONSENT)
    session.commit()
    monkeypatch.setattr(ctx, "model_gateway", _gateway(CountingProvider()))

    def _broken_pass(**_kwargs):
        raise RuntimeError("unexpected review-pass failure detail stays server-side")

    monkeypatch.setattr(veritas_auto, "run_auto_review_pass", _broken_pass)

    resp = client.post(f"/api/v1/scans/{scan_id}/nexus")

    assert resp.status_code == 200
    body = resp.json()
    assert body["state"] == "CLOSED"
    block = body["veritas_auto_review"]
    assert block["status"] == "review-pass-error"
    assert block["completed"] == 0
    assert "unexpected review-pass failure" not in resp.text


def test_consent_put_rejects_auto_flag_without_enabled_consent(client):
    scan_id = _make_scan(client)

    resp = client.put(
        f"/api/v1/scans/{scan_id}/model-consent",
        json={"enabled": False, "auto_veritas": True},
    )

    assert resp.status_code == 409
    assert resp.json()["code"] == "SCAN_STATE_CONFLICT"


def test_consent_put_stores_the_optin_flag(client):
    scan_id = _make_scan(client)

    resp = client.put(
        f"/api/v1/scans/{scan_id}/model-consent",
        json={"enabled": True, "provider": "ollama", "auto_veritas": True},
    )

    assert resp.status_code == 200
    assert resp.json()["llm_data_sharing"] == {
        "enabled": True,
        "provider": "ollama",
        "auto_veritas": True,
    }
