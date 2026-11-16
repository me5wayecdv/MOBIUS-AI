from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import sessionmaker

from conftest import make_apk
from mobius.adapters.models import InvestigationRow, ObservationRow
from mobius.core.enums import EvidenceKind, Fidelity, ObservationKind
from mobius.core.ids import IdPrefix, new_id
from mobius.core.schemas import Budget
from mobius.services.artifacts import ArtifactStore
from mobius.services.evidence import EvidenceService
from mobius.services.intake import IntakeService
from mobius.services.model_provider import (
    DeterministicMockProvider,
    ModelConsentRequired,
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

    def complete_json(self, **kwargs):
        self.calls += 1
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


def test_model_gateway_rejects_unconsented_investigation_before_provider_call(
    session, store, future_iso
):
    from mobius.services.model_provider import InvestigationModelGateway

    scan_id, _ = _scan_with_observation(session, store, future_iso, consent=False)
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
