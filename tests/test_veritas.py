"""VERITAS is an independent advisory reviewer; deterministic gates stay authoritative."""
from __future__ import annotations

import json
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
import pytest

from mobius.adapters.models import (
    DecisionRow,
    EvidenceRow,
    FindingRow, ObservationRow,
    InvestigationRow,
    VerdictRow,
)
from mobius.core.enums import Severity
from mobius.services.intake import IntakeService
from mobius.services.model_provider import (
    DeterministicMockProvider,
    ModelConsentRequired,
    ModelOutputInvalid,
    ProviderResult,
    StructuredModelGateway,
)
from mobius.services.validation import ValidationService
from mobius.services.veritas import VeritasReviewService

from conftest import make_apk


class CountingProvider(DeterministicMockProvider):
    def __init__(self, response_json: str, *, model_id: str = "veritas-model"):
        super().__init__(response_json, model_id=model_id, prompt_tokens=30, completion_tokens=20)
        self.calls = 0

    def complete_json(self, **kwargs):
        self.calls += 1
        return super().complete_json(**kwargs)


@pytest.fixture()
def reviewed_finding(session, store, future_iso):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "review.apk", uploaded_by="u")
    auth = intake.create_authorization(
        apk_sha256=app.sha256,
        target_package="com.example",
        scope_text="Static analysis of the supplied artefact only.",
        statement="s",
        max_intensity=2,
        granted_by="u",
        expires_at=future_iso,
    )
    investigation = intake.create_investigation(
        application_id=app.id,
        authorization_id=auth.id,
        objective="Review a candidate Android security finding.",
        intensity=0,
        created_by="u",
    )
    investigation_row = session.get(InvestigationRow, investigation.id)
    investigation_row.llm_data_sharing = {"enabled": True, "provider": "mock"}
    session.flush()
    evidence_id = "ev_veritas_fixture"
    session.add(EvidenceRow(
        id=evidence_id,
        investigation_id=investigation.id,
        kind="code_analysis",
        sha256="a" * 64,
        object_key="evidence/test",
        byte_size=128,
        truncated=False,
        redacted=True,
        summary="A persisted code observation showing a reachable file write.",
        produced_by="SPECTRE",
        created_at=future_iso,
    ))
    session.flush()
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
        evidence_refs=(evidence_id,),
        discovered_by="SPECTRE",
        validated_by="DETERMINISTIC_GATE",
        severity=Severity.HIGH,
    )
    session.commit()
    return finding.id, investigation.id, verdict.id, evidence_id


def _gateway(response: dict, *, requested_model="reviewer-v2", actual_model="reviewer-v2"):
    provider = CountingProvider(json.dumps(response), model_id=actual_model)
    return StructuredModelGateway(provider, model=requested_model), provider


def test_veritas_challenge_is_persisted_and_cannot_change_gate_verdict(
    session, reviewed_finding
):
    finding_id, investigation_id, verdict_id, evidence_id = reviewed_finding
    gateway, provider = _gateway({
        "disposition": "challenge",
        "summary": "The evidence establishes reachability but does not establish attacker control of the path.",
        "challenges": [{
            "challenge_type": "unsupported_claim",
            "statement": "The supplied summary does not show that the path value is attacker controlled.",
            "evidence_refs": [evidence_id],
            "requested_proof": "Provide a source-level trace from the exported input to the file sink.",
        }],
    })
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    result = VeritasReviewService(
        session, gateway=gateway, session_factory=factory
    ).review(finding_id, producer_model_id="producer-v1")

    assert result["disposition"] == "challenge"
    assert result["advisory_only"] is True
    assert result["gate_verdict_unchanged"] is True
    assert provider.calls == 1

    decision = session.execute(select(DecisionRow).where(
        DecisionRow.investigation_id == investigation_id,
        DecisionRow.agent == "VERITAS",
        DecisionRow.action == "review_finding",
    )).scalar_one()
    assert decision.model_id == "reviewer-v2"
    assert decision.provider == "mock"
    assert decision.prompt_version == "veritas-independent-review-v3"
    assert decision.considered_evidence == [evidence_id]
    assert decision.output_json["disposition"] == "challenge"
    assert decision.output_json["challenges"][0]["evidence_refs"] == [evidence_id]
    assert decision.system_prompt_sha256 and len(decision.system_prompt_sha256) == 64
    assert decision.response_sha256 and len(decision.response_sha256) == 64

    verdict = session.get(VerdictRow, verdict_id)
    finding = session.get(FindingRow, finding_id)
    assert verdict.verdict == "confirmed"
    assert verdict.gate_passed is True
    assert finding.status == "confirmed"


def test_veritas_review_mutates_no_finding_or_verdict_row(
    session, reviewed_finding
):
    """Advisory review adds a DecisionRow + event only: every column of the
    finding and every verdict row must be byte-identical afterwards."""
    finding_id, investigation_id, verdict_id, evidence_id = reviewed_finding

    def snapshot(row):
        # Every mapped column, deep-copied: JSON columns hold mutable containers,
        # so a shallow __dict__ copy would alias the live objects and unloaded
        # attributes would be silently absent instead of compared.
        from copy import deepcopy
        from sqlalchemy import inspect as sa_inspect

        return {
            attr.key: deepcopy(getattr(row, attr.key))
            for attr in sa_inspect(row).mapper.column_attrs
        }

    before_finding = snapshot(session.get(FindingRow, finding_id))
    before_verdicts = [
        snapshot(v)
        for v in session.execute(select(VerdictRow)).scalars().all()
    ]
    gateway, _ = _gateway({
        "disposition": "no_material_challenge",
        "summary": "Persisted evidence supports the gate verdict.",
        "challenges": [],
    })
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    VeritasReviewService(
        session, gateway=gateway, session_factory=factory
    ).review(finding_id, producer_model_id="producer-v1")

    session.expire_all()
    assert snapshot(session.get(FindingRow, finding_id)) == before_finding
    assert [
        snapshot(v)
        for v in session.execute(select(VerdictRow)).scalars().all()
    ] == before_verdicts


def test_veritas_refuses_same_requested_model_before_provider_call(
    session, reviewed_finding
):
    finding_id, _, _, _ = reviewed_finding
    gateway, provider = _gateway({
        "disposition": "no_material_challenge",
        "summary": "No material challenge was identified in the supplied evidence.",
        "challenges": [],
    }, requested_model="producer-v1")

    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)
    with pytest.raises(ModelConsentRequired, match="must differ"):
        VeritasReviewService(
            session, gateway=gateway, session_factory=factory
        ).review(finding_id, producer_model_id="producer-v1")
    assert provider.calls == 0


def test_veritas_refuses_provider_alias_that_resolves_to_producer_model(
    session, reviewed_finding
):
    finding_id, _, _, _ = reviewed_finding
    gateway, provider = _gateway({
        "disposition": "no_material_challenge",
        "summary": "No material challenge was identified in the supplied evidence.",
        "challenges": [],
    }, requested_model="reviewer-alias", actual_model="producer-v1")

    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)
    with pytest.raises(ModelConsentRequired, match="resolved VERITAS"):
        VeritasReviewService(
            session, gateway=gateway, session_factory=factory
        ).review(finding_id, producer_model_id="producer-v1")
    assert provider.calls == 1
    assert session.execute(select(DecisionRow).where(
        DecisionRow.agent == "VERITAS"
    )).scalars().all() == []


def test_veritas_rejects_challenge_that_invents_evidence_reference(
    session, reviewed_finding
):
    finding_id, _, _, _ = reviewed_finding
    gateway, _ = _gateway({
        "disposition": "challenge",
        "summary": "A challenge references an evidence item that was not supplied.",
        "challenges": [{
            "challenge_type": "contradictory_evidence",
            "statement": "An invented record contradicts the finding.",
            "evidence_refs": ["ev_not_in_this_investigation"],
            "requested_proof": "Retrieve the claimed evidence item.",
        }],
    })
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    with pytest.raises(ModelOutputInvalid, match="outside"):
        VeritasReviewService(
            session, gateway=gateway, session_factory=factory
        ).review(finding_id, producer_model_id="producer-v1")
    assert session.execute(select(DecisionRow).where(
        DecisionRow.agent == "VERITAS"
    )).scalars().all() == []


def test_veritas_requires_explicit_investigation_consent(
    session, reviewed_finding
):
    finding_id, investigation_id, _, _ = reviewed_finding
    from mobius.adapters.models import InvestigationRow

    investigation = session.get(InvestigationRow, investigation_id)
    investigation.llm_data_sharing = {"enabled": False, "provider": "mock"}
    session.flush()
    gateway, provider = _gateway({
        "disposition": "no_material_challenge",
        "summary": "No material challenge was identified in the supplied evidence.",
        "challenges": [],
    })
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    with pytest.raises(ModelConsentRequired, match="disabled"):
        VeritasReviewService(
            session, gateway=gateway, session_factory=factory
        ).review(finding_id, producer_model_id="producer-v1")
    assert provider.calls == 0


class SequenceProvider:
    """Mock provider returning a different raw reply per call."""

    name = "mock"

    def __init__(self, replies, *, model_id="veritas-model"):
        self.replies = list(replies)
        self.model_id = model_id
        self.calls = 0

    def complete_json(self, **kwargs):
        from mobius.services.model_provider import ProviderResult

        content = self.replies[min(self.calls, len(self.replies) - 1)]
        self.calls += 1
        return ProviderResult(
            content=content, model_id=self.model_id, prompt_tokens=30, completion_tokens=20
        )


def _challenge_reply(evidence_id, **overrides):
    reply = {
        "disposition": "challenge",
        "summary": "The evidence establishes reachability but does not establish attacker control of the path.",
        "challenges": [{
            "challenge_type": "unsupported_claim",
            "statement": "The supplied summary does not show that the path value is attacker controlled.",
            "evidence_refs": [evidence_id],
            "requested_proof": "Provide a source-level trace from the exported input to the file sink.",
        }],
    }
    reply.update(overrides)
    return reply


def test_veritas_accepts_reply_with_undeclared_decorative_fields(session, reviewed_finding):
    """The exact observed DeepSeek defect: extra 'title' on each challenge."""
    finding_id, investigation_id, _, evidence_id = reviewed_finding
    reply = _challenge_reply(evidence_id)
    reply["challenges"][0]["title"] = "Unsupported exported-component claim"
    provider = CountingProvider(json.dumps(reply))
    gateway = StructuredModelGateway(provider, model="reviewer-v2")
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    result = VeritasReviewService(
        session, gateway=gateway, session_factory=factory
    ).review(finding_id, producer_model_id="producer-v1")

    assert result["status"] == "completed"
    assert result["disposition"] == "challenge"
    assert provider.calls == 1
    assert result["normalization"]["dropped_fields"] == ["challenges.0.title"]


def test_veritas_accepts_fenced_or_prose_wrapped_reply(session, reviewed_finding):
    finding_id, investigation_id, _, evidence_id = reviewed_finding
    body = json.dumps(_challenge_reply(evidence_id))
    provider = CountingProvider(f"Here is my review.\n```json\n{body}\n```\nEnd.")
    gateway = StructuredModelGateway(provider, model="reviewer-v2")
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    result = VeritasReviewService(
        session, gateway=gateway, session_factory=factory
    ).review(finding_id, producer_model_id="producer-v1")

    assert result["status"] == "completed"
    assert result["disposition"] == "challenge"
    assert result["normalization"]["method"] == "extracted"


def test_veritas_plain_text_reply_is_repaired_by_bounded_conversion(session, reviewed_finding):
    finding_id, investigation_id, _, evidence_id = reviewed_finding
    plain = "I challenge this finding: the evidence does not show attacker control of the path."
    provider = SequenceProvider([plain, json.dumps(_challenge_reply(evidence_id))])
    gateway = StructuredModelGateway(provider, model="reviewer-v2")
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    result = VeritasReviewService(
        session, gateway=gateway, session_factory=factory
    ).review(finding_id, producer_model_id="producer-v1")

    assert result["status"] == "completed"
    assert result["disposition"] == "challenge"
    assert result["repair_attempted"] is True
    assert provider.calls == 2


def test_veritas_unconvertible_reply_is_captured_needs_review_not_fabricated(session, reviewed_finding):
    finding_id, investigation_id, _, evidence_id = reviewed_finding
    provider = SequenceProvider(["totally unparseable prose", "still not json"])
    gateway = StructuredModelGateway(provider, model="reviewer-v2")
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    result = VeritasReviewService(
        session, gateway=gateway, session_factory=factory
    ).review(finding_id, producer_model_id="producer-v1")

    assert result["status"] == "needs_review"
    assert result["disposition"] is None
    assert result["challenges"] == []
    assert result["failure_class"].startswith("model reply unconvertible")
    assert result["gate_verdict_unchanged"] is True
    assert provider.calls == 2

    decision = session.execute(select(DecisionRow).where(
        DecisionRow.investigation_id == investigation_id,
        DecisionRow.id == result["decision_id"],
    )).scalar_one()
    assert decision.output_json["status"] == "needs_review"
    assert decision.response_sha256 is not None
    # the raw reply is preserved for the operator, clipped and flagged
    assert decision.output_json["raw_response"] == "still not json"
    assert decision.output_json["raw_response_clipped"] is False


def test_veritas_needs_review_raw_preservation_is_clipped(session, store, reviewed_finding):
    from mobius.services.veritas import _NEEDS_REVIEW_RAW_LIMIT

    finding_id, investigation_id, _, evidence_id = reviewed_finding
    huge = "x" * (_NEEDS_REVIEW_RAW_LIMIT + 500)
    provider = SequenceProvider([huge, huge])
    gateway = StructuredModelGateway(provider, model="reviewer-v2")
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    result = VeritasReviewService(
        session, gateway=gateway, session_factory=factory, store=store
    ).review(finding_id, producer_model_id="producer-v1")

    assert result["status"] == "needs_review"
    decision = session.execute(select(DecisionRow).where(
        DecisionRow.id == result["decision_id"],
    )).scalar_one()
    out = decision.output_json
    # the inline copy is a clip and SAYS so; the full raw is a stored artifact
    assert len(out["raw_response"]) == _NEEDS_REVIEW_RAW_LIMIT
    assert out["raw_response_clipped"] is True
    assert out["raw_response_length"] == _NEEDS_REVIEW_RAW_LIMIT + 500
    assert out["raw_artifact_key"]
    assert store.get(out["raw_artifact_key"]).decode() == huge


def test_veritas_conflicting_payloads_are_never_silently_chosen(session, reviewed_finding):
    finding_id, investigation_id, _, evidence_id = reviewed_finding
    good = json.dumps(_challenge_reply(evidence_id))
    contradictory = json.dumps(_challenge_reply(evidence_id, disposition="no_material_challenge", challenges=[]))
    provider = SequenceProvider([good + "\n" + contradictory] * 2)
    gateway = StructuredModelGateway(provider, model="reviewer-v2")
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    result = VeritasReviewService(
        session, gateway=gateway, session_factory=factory
    ).review(finding_id, producer_model_id="producer-v1")

    assert result["status"] == "needs_review"
    assert "multiple_conflicting_payloads" in result["failure_class"]


def test_review_package_includes_component_observations(session, reviewed_finding):
    """The review package must carry the per-component facts the investigation
    established (export state, permission guard), whitelisted and bounded, so
    the reviewer challenges only what is genuinely unestablished."""
    finding_id, investigation_id, _, evidence_id = reviewed_finding
    finding = session.get(FindingRow, finding_id)
    finding.component_ref = "com.example.Entry"
    session.add(ObservationRow(
        id="obs_veritas_component",
        investigation_id=investigation_id,
        agent="RECON",
        kind="fact",
        fidelity="binary-xml",
        subject_type="component",
        subject_ref="com.example.Entry",
        statement="Entry is exported with no permission guard",
        attributes={
            "kind": "provider", "exported": True, "export_source": "declared",
            "permission": None, "internal_note": "must-not-leak",
        },
        maswe=[],
        confidence=1.0,
        evidence_refs=[evidence_id],
        created_at="2026-11-16T00:00:00Z",
    ))
    session.commit()

    captured: list[dict] = []

    class CapturingProvider(CountingProvider):
        def complete_json(self, **kwargs):
            captured.append(kwargs)
            return super().complete_json(**kwargs)

    provider = CapturingProvider(json.dumps({
        "disposition": "no_material_challenge", "summary": "s", "challenges": [],
    }), model_id="reviewer-v2")
    gateway = StructuredModelGateway(provider, model="reviewer-v2")
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    VeritasReviewService(
        session, gateway=gateway, session_factory=factory
    ).review(finding_id, producer_model_id="producer-v1")

    assert len(captured) == 1
    payload = json.loads(captured[0]["user_payload"]["input"])
    observations = payload["component_observations"]
    assert len(observations) == 1
    obs = observations[0]
    assert obs["attributes"]["exported"] is True
    assert obs["attributes"]["export_source"] == "declared"
    assert obs["attributes"]["kind"] == "provider"
    assert "internal_note" not in obs["attributes"]
    assert obs["evidence_refs"] == [evidence_id]
    assert obs["produced_by"] == "RECON"
