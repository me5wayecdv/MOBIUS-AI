from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import sessionmaker

from conftest import make_apk
from mobius.adapters.models import (
    ApplicationRow,
    DecisionRow,
    EventRow,
    HypothesisRow,
    InvestigationRow,
    ObservationRow,
)
from mobius.core.enums import EvidenceKind, Fidelity, ObservationKind
from mobius.core.ids import IdPrefix, new_id
from mobius.core.schemas import Budget
from mobius.services.artifacts import ArtifactStore
from mobius.services.evidence import EvidenceService
from mobius.services.intake import IntakeService
from mobius.services.model_provider import (
    DeterministicMockProvider,
    ModelBudgetExceeded,
    ModelConsentRequired,
    ModelOutputInvalid,
    ModelUnavailable,
    ProviderResult,
    StructuredModelGateway,
)
from mobius.services.nexus_hypotheses import NexusHypothesisService


class HypothesisReply(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: str = Field(min_length=12, max_length=1000)
    confidence: float = Field(ge=0, le=1)


class CountingProvider:
    name = "ollama"

    def __init__(self, content: str):
        self.content = content
        self.calls = 0
        self.last_call = None

    def complete_json(self, **kwargs):
        self.calls += 1
        self.last_call = kwargs
        return ProviderResult(
            content=self.content,
            model_id="local-test-model",
            prompt_tokens=7,
            completion_tokens=5,
        )


def _scan_with_observation(session, store, future_iso, *, consent=False, budget=400_000):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "nexus.apk", uploaded_by="analyst-1")
    auth = intake.create_authorization(
        apk_sha256=app.sha256,
        target_package="com.example",
        scope_text="Static analysis only for hypothesis-generation tests.",
        statement="I own this test APK",
        max_intensity=0,
        granted_by="analyst-1",
        expires_at=future_iso,
    )
    scan = intake.create_investigation(
        application_id=app.id,
        authorization_id=auth.id,
        objective="Generate a testable hypothesis from a stored call path",
        intensity=0,
        created_by="analyst-1",
        budget=Budget(max_model_tokens=budget),
    )
    row = session.get(InvestigationRow, scan.id)
    row.llm_data_sharing = {"enabled": consent, "provider": "ollama" if consent else None}
    evidence = EvidenceService(session, store).record(
        investigation_id=scan.id,
        kind=EvidenceKind.DEX_STRING,
        content=b'{"index":"fixture"}',
        summary="Bounded DEX graph fixture",
        produced_by="SPECTRE",
    )
    observation = ObservationRow(
        id=new_id(IdPrefix.OBSERVATION),
        investigation_id=scan.id,
        agent="SPECTRE",
        kind=ObservationKind.INFERENCE.value,
        fidelity=Fidelity.DECOMPILED.value,
        subject_type="component",
        subject_ref="com.example.Entry",
        statement="Static call path reaches a file output sink",
        attributes={
            "reachability": "reached-unguarded",
            "path": ["Lcom/example/Entry;->onCreate()V"],
            "sink": "Ljava/io/FileOutputStream;-><init>()V",
            "guards": [],
            "index_truncated": False,
            "exhaustive": True,
        },
        maswe=["MASWE-0001"],
        confidence=0.8,
        evidence_refs=[evidence.id],
        created_at="2026-11-16T00:00:00Z",
    )
    session.add(observation)
    session.flush()
    return scan.id, observation.id


def test_nexus_default_is_explicit_deterministic_fallback_without_consent(
    session, store, future_iso
):
    scan_id, observation_id = _scan_with_observation(session, store, future_iso)
    provider = CountingProvider('{"claim":"model should not be called","confidence":0.9}')
    gateway = StructuredModelGateway(provider, model="local-test-model")

    result = NexusHypothesisService(session, gateway=gateway).generate(scan_id)

    assert result["mode"] == "deterministic_fallback"
    assert result["model_id"] is None
    assert len(result["hypotheses"]) == 1
    assert result["hypotheses"][0]["derived_from"] == [observation_id]
    assert "attacker_controlled_input" in result["hypotheses"][0]["required_evidence"]
    assert provider.calls == 0


def test_nexus_model_generation_requires_consent_and_persists_model_decision(
    session, store, future_iso
):
    scan_id, observation_id = _scan_with_observation(
        session, store, future_iso, consent=True
    )
    response = {
        "hypotheses": [{
            "claim": "The exported entry may expose file output to attacker-controlled input.",
            "derived_from": [observation_id],
            "required_evidence": ["source_location", "attacker_controlled_input", "controlled_poc"],
            "maswe": ["MASWE-0001"],
            "priority": 0.7,
        }],
        "summary": "One hypothesis requires source and controlled validation evidence.",
    }
    provider = CountingProvider(json.dumps(response))
    gateway = StructuredModelGateway(provider, model="local-test-model")
    session.commit()
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    result = NexusHypothesisService(
        session, gateway=gateway, session_factory=factory
    ).generate(scan_id)

    assert result["mode"] == "model_gateway"
    assert result["model_id"] == "local-test-model"
    assert result["token_usage"] == {"input_tokens": 7, "output_tokens": 5}
    assert provider.calls == 1
    assert result["hypotheses"][0]["derived_from"] == [observation_id]
    assert result["hypotheses"][0]["status"] == "open"

    decision = session.query(DecisionRow).filter_by(
        investigation_id=scan_id, action="generate_hypotheses"
    ).one()
    assert decision.provider == "ollama"
    assert decision.model_role == "reasoning"
    assert decision.requested_model == "local-test-model"
    assert decision.model_id == "local-test-model"
    assert decision.prompt_version == "nexus-hypothesis-generation-v3"
    assert decision.system_prompt_sha256 and len(decision.system_prompt_sha256) == 64
    assert decision.input_sha256 and len(decision.input_sha256) == 64
    assert decision.schema_sha256 and len(decision.schema_sha256) == 64
    assert decision.response_sha256 and len(decision.response_sha256) == 64
    assert decision.schema_name == "HypothesisGenerationReply"
    assert decision.output_json["hypotheses"][0]["claim"] == response["hypotheses"][0]["claim"]
    assert decision.input_tokens == 7
    assert decision.output_tokens == 5
    assert decision.latency_ms == 0
    assert decision.temperature == 0.0
    assert decision.max_tokens == 1200


def test_model_gateway_rejects_unconsented_investigation_before_provider_call(
    session, store, future_iso
):
    from mobius.services.model_provider import InvestigationModelGateway

    scan_id, _ = _scan_with_observation(session, store, future_iso, consent=False)
    session.commit()
    provider = CountingProvider('{"claim":"not called","confidence":0.2}')
    gateway = StructuredModelGateway(provider, model="local-test-model")
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    with pytest.raises(ModelConsentRequired):
        import asyncio
        asyncio.run(InvestigationModelGateway(gateway, factory, scan_id).complete_structured(
            role="reasoning", system="s", user="u", schema=HypothesisReply, max_tokens=16
        ))
    assert provider.calls == 0



def test_investigation_gateway_accumulates_usage_across_sequential_calls(
    session, store, future_iso
):
    from mobius.services.model_provider import InvestigationModelGateway

    scan_id, _ = _scan_with_observation(
        session, store, future_iso, consent=True
    )
    session.commit()
    provider = CountingProvider('{"claim":"A valid structured model response","confidence":0.7}')
    gateway = StructuredModelGateway(provider, model="local-test-model")
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)
    bound = InvestigationModelGateway(gateway, factory, scan_id)

    import asyncio
    first = asyncio.run(bound.complete_structured(
        role="reasoning", system="short system", user="first call",
        schema=HypothesisReply, max_tokens=32,
    ))
    second = asyncio.run(bound.complete_structured(
        role="reasoning", system="short system", user="second call",
        schema=HypothesisReply, max_tokens=32,
    ))

    session.expire_all()
    row = session.get(InvestigationRow, scan_id)
    assert first["input_tokens"] + first["output_tokens"] == 12
    assert second["input_tokens"] + second["output_tokens"] == 12
    assert row.used_json["model_tokens"] == 24
    assert row.used_json["model_tokens_reserved"] == 0
    assert provider.calls == 2


def test_nexus_receives_and_records_persisted_source_excerpt(session, store, future_iso):
    scan_id, observation_id = _scan_with_observation(
        session, store, future_iso, consent=True
    )
    investigation = session.get(InvestigationRow, scan_id)
    application = session.get(ApplicationRow, investigation.application_id)
    source_text = "private void writeSecret() {\n    persistSensitiveValue();\n}"
    payload = {
        "schema_version": 1,
        "apk_sha256": application.sha256,
        "tool_version": "1.5.6",
        "class_name": "com.example.Entry",
        "component": "com.example.Entry",
        "method_name": "writeSecret",
        "method_reference": "com.example.Entry#writeSecret@6",
        "path": "com/example/Entry.java",
        "start_line": 6,
        "end_line": 8,
        "fidelity": "decompiled",
        "text": source_text,
    }
    content = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    metadata = {
        "mobius_source_evidence_version": 1,
        "apk_sha256": payload["apk_sha256"],
        "tool_version": payload["tool_version"],
        "class_name": payload["class_name"],
        "component": payload["component"],
        "method_name": payload["method_name"],
        "method_reference": payload["method_reference"],
        "path": payload["path"],
        "start_line": payload["start_line"],
        "end_line": payload["end_line"],
        "fidelity": payload["fidelity"],
    }
    source_evidence = EvidenceService(session, store).record(
        investigation_id=scan_id,
        kind=EvidenceKind.SOURCE,
        content=content,
        summary=json.dumps(metadata, sort_keys=True, separators=(",", ":")),
        produced_by="JADX",
    )
    response = {
        "hypotheses": [{
            "claim": "The decompiled method may write attacker-controlled data.",
            "derived_from": [observation_id],
            "required_evidence": ["source_location", "attacker_controlled_input"],
            "maswe": ["MASWE-0001"],
            "priority": 0.6,
        }],
        "summary": "A source excerpt is available but runtime control is not established.",
    }
    provider = CountingProvider(json.dumps(response))
    gateway = StructuredModelGateway(provider, model="local-test-model")
    session.commit()
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    result = NexusHypothesisService(
        session, gateway=gateway, session_factory=factory, store=store
    ).generate(scan_id, component="com.example.Entry")

    assert result["mode"] == "model_gateway"
    assert provider.calls == 1
    packaged = json.loads(provider.last_call["user_payload"]["input"])
    assert packaged["source_snippets"][0]["text"] == source_text
    decision = session.query(DecisionRow).filter_by(
        investigation_id=scan_id, action="generate_hypotheses"
    ).one()
    assert source_evidence.id in decision.considered_evidence


class ScriptedProvider:
    """Returns queued responses (or raises queued exceptions) in order."""

    name = "ollama"

    def __init__(self, steps):
        self.steps = list(steps)
        self.calls = 0
        self.payloads = []

    def complete_json(self, **kwargs):
        self.calls += 1
        self.payloads.append(kwargs)
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        return ProviderResult(
            content=step,
            model_id="local-test-model",
            prompt_tokens=7,
            completion_tokens=5,
        )


def _valid_reply(observation_id):
    return json.dumps({
        "hypotheses": [{
            "claim": "The exported entry may expose file output to attacker-controlled input.",
            "derived_from": [observation_id],
            "required_evidence": ["source_location", "attacker_controlled_input", "controlled_poc"],
            "maswe": ["MASWE-0001"],
            "priority": 0.7,
        }],
        "summary": "One hypothesis requires source and controlled validation evidence.",
    })


def _citation_invalid_reply():
    return json.dumps({
        "hypotheses": [{
            "claim": "The exported entry may expose file output to attacker-controlled input.",
            "derived_from": ["obs_not_in_this_package"],
            "required_evidence": ["source_location"],
            "maswe": [],
            "priority": 0.5,
        }],
        "summary": "Cites an observation that was never supplied.",
    })


def test_nexus_model_repair_succeeds_after_schema_invalid_output(
    session, store, future_iso
):
    scan_id, observation_id = _scan_with_observation(
        session, store, future_iso, consent=True
    )
    provider = ScriptedProvider(["{not valid json", _valid_reply(observation_id)])
    gateway = StructuredModelGateway(provider, model="local-test-model")
    session.commit()
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    result = NexusHypothesisService(
        session, gateway=gateway, session_factory=factory
    ).generate(scan_id)

    assert result["mode"] == "model_gateway"
    assert result["repair_attempts"] == 1
    assert provider.calls == 2
    assert result["hypotheses"][0]["derived_from"] == [observation_id]

    # The repair call carries only the fixed reason token and instruction:
    # no raw model output and no raw validation error text re-enters a prompt.
    repair_payload = json.loads(provider.payloads[1]["user_payload"]["input"])
    assert repair_payload["repair"]["error"] == "schema-invalid"
    assert "evidence_package" in repair_payload
    repair_text = json.dumps(provider.payloads[1])
    assert "{not valid json" not in repair_text
    assert "Expecting value" not in repair_text

    # One planner_rejected event per failed attempt; both attempts are charged.
    check = factory()
    try:
        events = [e for e in check.query(EventRow)
                  .filter_by(investigation_id=scan_id, type="planner_rejected").all()]
        assert len(events) == 1
        assert events[0].payload["reason"] == "schema-invalid"
        assert events[0].payload["final"] is False
        assert events[0].payload["failed_attempt"] == 0
        row = check.get(InvestigationRow, scan_id)
        assert row.used_json["model_tokens"] == 24
    finally:
        check.close()


def test_nexus_model_exhaustion_fails_closed_with_committed_rejection_evidence(
    session, store, future_iso
):
    scan_id, observation_id = _scan_with_observation(
        session, store, future_iso, consent=True
    )
    # initial: schema-invalid; repair 1: citation-invalid; repair 2: schema-invalid.
    provider = ScriptedProvider([
        "{not valid json",
        _citation_invalid_reply(),
        "{still not json",
    ])
    gateway = StructuredModelGateway(provider, model="local-test-model")
    session.commit()
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    with pytest.raises(ModelOutputInvalid):
        NexusHypothesisService(
            session, gateway=gateway, session_factory=factory
        ).generate(scan_id)

    # Initial + exactly 2 repair attempts, never more.
    assert provider.calls == 3

    # Simulate the request rollback: committed rejection evidence must survive it.
    session.rollback()
    check = factory()
    try:
        # No hypotheses and no success event: rejection can never become a result.
        assert check.query(HypothesisRow).filter_by(investigation_id=scan_id).count() == 0
        assert check.query(EventRow).filter_by(
            investigation_id=scan_id, type="hypotheses_generated"
        ).count() == 0

        events = (check.query(EventRow)
                  .filter_by(investigation_id=scan_id, type="planner_rejected")
                  .order_by(EventRow.seq).all())
        assert [e.payload["reason"] for e in events] == [
            "schema-invalid", "citation-outside-package", "schema-invalid",
        ]
        assert [e.payload["final"] for e in events] == [False, False, True]
        assert [e.payload["failed_attempt"] for e in events] == [0, 1, 2]
        # Diagnostics carry fixed tokens and hashes only.
        for event in events:
            text = json.dumps(event.payload)
            assert "{not valid json" not in text and "{still not json" not in text
            assert "Expecting value" not in text

        decision = check.query(DecisionRow).filter_by(
            investigation_id=scan_id, action="generate_hypotheses_rejected"
        ).one()
        assert decision.output_json is None
        assert decision.action_args["repair_attempts"] == 2
        assert decision.action_args["reasons"] == [
            "schema-invalid", "citation-outside-package", "schema-invalid",
        ]
        assert decision.provider == "ollama"
        assert decision.prompt_version == "nexus-hypothesis-generation-v3"
        assert events[-1].payload["decision_id"] == decision.id
    finally:
        check.close()


def test_nexus_citation_invalid_output_repaired_then_validated(
    session, store, future_iso
):
    scan_id, observation_id = _scan_with_observation(
        session, store, future_iso, consent=True
    )
    provider = ScriptedProvider([_citation_invalid_reply(), _valid_reply(observation_id)])
    gateway = StructuredModelGateway(provider, model="local-test-model")
    session.commit()
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    result = NexusHypothesisService(
        session, gateway=gateway, session_factory=factory
    ).generate(scan_id)

    assert result["mode"] == "model_gateway"
    assert result["repair_attempts"] == 1
    # Only the validated reply is persisted; the citation-invalid output is not.
    assert [h["derived_from"] for h in result["hypotheses"]] == [[observation_id]]
    decision = session.query(DecisionRow).filter_by(
        investigation_id=scan_id, action="generate_hypotheses"
    ).one()
    assert decision.output_json["hypotheses"][0]["derived_from"] == [observation_id]
    repair_payload = json.loads(provider.payloads[1]["user_payload"]["input"])
    assert repair_payload["repair"]["error"] == "citation-outside-package"


def test_nexus_transport_error_is_never_repaired(session, store, future_iso):
    scan_id, observation_id = _scan_with_observation(
        session, store, future_iso, consent=True
    )
    provider = ScriptedProvider([ModelUnavailable("provider unreachable")])
    gateway = StructuredModelGateway(provider, model="local-test-model")
    session.commit()
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    with pytest.raises(ModelUnavailable):
        NexusHypothesisService(
            session, gateway=gateway, session_factory=factory
        ).generate(scan_id)

    assert provider.calls == 1
    session.rollback()
    check = factory()
    try:
        assert check.query(EventRow).filter_by(
            investigation_id=scan_id, type="planner_rejected"
        ).count() == 0
        assert check.query(HypothesisRow).filter_by(investigation_id=scan_id).count() == 0
    finally:
        check.close()


def test_nexus_budget_exhaustion_mid_repair_fails_closed(session, store, future_iso):
    from mobius.services.evidence_package import EvidencePackageBuilder
    from mobius.services.nexus_hypotheses import (
        _SYSTEM_PROMPT,
        HypothesisGenerationReply,
        _compact_package,
    )

    scan_id, observation_id = _scan_with_observation(
        session, store, future_iso, consent=True
    )
    package_data = EvidencePackageBuilder(session, store=store).build(scan_id).as_dict()
    schema_bytes = json.dumps(
        HypothesisGenerationReply.model_json_schema(), separators=(",", ":")
    ).encode("utf-8")
    first_reservation = (
        len(_SYSTEM_PROMPT.encode("utf-8"))
        + len(_compact_package(package_data).encode("utf-8"))
        + len(schema_bytes)
        + 1024
        + 1200
    )
    row = session.get(InvestigationRow, scan_id)
    budget = dict(row.budget_json or {})
    # Exactly one reservation fits; the repair attempt's reservation cannot.
    budget["max_model_tokens"] = first_reservation
    row.budget_json = budget
    provider = ScriptedProvider(["{not valid json", _valid_reply(observation_id)])
    gateway = StructuredModelGateway(provider, model="local-test-model")
    session.commit()
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    with pytest.raises(ModelBudgetExceeded):
        NexusHypothesisService(
            session, gateway=gateway, session_factory=factory
        ).generate(scan_id)

    # The provider was hit once (initial attempt); the repair never reached it.
    assert provider.calls == 1
    session.rollback()
    check = factory()
    try:
        assert check.query(HypothesisRow).filter_by(investigation_id=scan_id).count() == 0
        assert check.query(EventRow).filter_by(
            investigation_id=scan_id, type="hypotheses_generated"
        ).count() == 0
    finally:
        check.close()
