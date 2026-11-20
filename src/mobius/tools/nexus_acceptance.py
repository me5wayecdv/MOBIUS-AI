"""Executable acceptance harness for a candidate NEXUS hypothesis model.

NEXUS proposes testable hypotheses from a persisted evidence package; it never
executes tests and never upgrades findings. This harness answers a narrower
question than "is the model smart": does the generation path accept ONLY
replies that satisfy the integrity contract (schema, package-confined
citations, supported evidence requests, bounded repair), and (in live mode)
does a specific candidate model satisfy it in practice?

Modes:

- ``mock`` (default, free, deterministic): scripted provider responses prove
  that every integrity guard on the generation path fires when it must and
  that well-formed replies persist as open hypotheses. A green mock run pins
  the acceptance BAR. It says nothing about any real model's quality.
- ``ollama`` (operator action, local only): runs a live probe against a
  locally installed Ollama model and reports measured latency, token usage
  and repair behaviour against the acceptance criteria. Never downloads a
  model, never calls a hosted provider.

Exit code 0 means every case met its expected outcome; 1 means at least one
did not. A failing mock run means a GUARD regressed. A failing live run means
the candidate model does not currently meet the bar; it is not a pipeline
defect by itself. Live mode measures ONE seeded fixture: a minimum quality
floor for hypothesis generation, not a quality endorsement, and not evidence
about investigation-wide intelligence.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ..adapters.models import DecisionRow, HypothesisRow, InvestigationRow, ObservationRow
from ..core.enums import EvidenceKind, Fidelity, ObservationKind
from ..core.ids import IdPrefix, new_id
from ..services.artifacts import ArtifactStore
from ..services.evidence import EvidenceService
from ..services.intake import IntakeService
from ..services.model_provider import (
    DeterministicMockProvider,
    ModelBudgetExceeded,
    ModelConsentRequired,
    ModelOutputInvalid,
    OllamaProvider,
    StructuredModelGateway,
)
from ..services.nexus_hypotheses import NexusHypothesisService

MODEL = "candidate-generator"


def _future_iso() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=7)).isoformat().replace("+00:00", "Z")


def _make_apk() -> bytes:
    """Minimal structurally valid APK (ZIP with a manifest), mirroring tests/conftest."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", "<manifest package='com.example'/>")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32)
    return buf.getvalue()


@dataclass(frozen=True, slots=True)
class Fixture:
    investigation_id: str
    observation_id: str
    evidence_id: str


def build_fixture(session: Session, store: ArtifactStore, *, provider: str = "mock") -> Fixture:
    """One investigation with a persisted reachability observation whose ID is the
    only legitimate citation target in the evidence package."""
    intake = IntakeService(session, store)
    app, _ = intake.create_application(_make_apk(), "nexus-fixture.apk", uploaded_by="u")
    auth = intake.create_authorization(
        apk_sha256=app.sha256,
        target_package="com.example",
        scope_text="Static analysis of the supplied artefact only.",
        statement="s",
        max_intensity=0,
        granted_by="u",
        expires_at=_future_iso(),
    )
    investigation = intake.create_investigation(
        application_id=app.id,
        authorization_id=auth.id,
        objective="Generate a testable hypothesis from a stored call path.",
        intensity=0,
        created_by="u",
    )
    row = session.get(InvestigationRow, investigation.id)
    row.llm_data_sharing = {"enabled": True, "provider": provider}
    row.budget_json = {"max_model_tokens": 1_000_000}
    evidence = EvidenceService(session, store).record(
        investigation_id=investigation.id,
        kind=EvidenceKind.DEX_STRING,
        content=b'{"index":"fixture"}',
        summary="Bounded DEX graph fixture",
        produced_by="SPECTRE",
    )
    observation = ObservationRow(
        id=new_id(IdPrefix.OBSERVATION),
        investigation_id=investigation.id,
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
    session.commit()
    return Fixture(investigation.id, observation.id, evidence.id)


class SequencedProvider(DeterministicMockProvider):
    """Returns a different scripted payload per call (repair-loop cases)."""

    def __init__(self, payloads: list[str], *, model_id: str = MODEL):
        super().__init__(payloads[0], model_id=model_id, prompt_tokens=30, completion_tokens=20)
        self.payloads = payloads
        self.calls = 0

    def complete_json(self, **kwargs):
        content = self.payloads[min(self.calls, len(self.payloads) - 1)]
        self.calls += 1
        self.response_json = content
        return super().complete_json(**kwargs)


@dataclass(frozen=True, slots=True)
class Case:
    name: str
    criterion: str
    responses: list[Any]  # dicts serialised to JSON, or raw strings for malformed payloads
    expected: str  # "accepted:model_gateway" | "accepted:deterministic_fallback" | "refused:<exception>"
    expected_provider_calls: int
    consent: dict[str, Any] | None = None  # overrides the fixture's consent when set
    max_model_tokens: int | None = None  # overrides the fixture's budget when set
    detail: str = ""


@dataclass(slots=True)
class CaseResult:
    case: Case
    ok: bool
    observed: str
    detail: str = ""


def _valid_reply(observation_id: str) -> dict[str, Any]:
    return {
        "summary": "One reachability-derived hypothesis is justified by the packaged observation.",
        "hypotheses": [{
            "claim": "The exported entry component may reach the file sink with attacker-influenced data.",
            "derived_from": [observation_id],
            "required_evidence": ["attacker_controlled_input", "source_location"],
            "maswe": ["MASWE-0001"],
            "priority": 0.7,
        }],
    }


def cases(fx: Fixture) -> list[Case]:
    valid = _valid_reply(fx.observation_id)
    return [
        Case("valid-hypothesis-persisted", "schema-validity", [valid],
             "accepted:model_gateway", 1,
             detail="a well-formed, package-confined hypothesis is the accept path"),
        Case("empty-hypotheses-persisted", "disposition-discipline",
             [{"summary": "The packaged evidence does not justify a useful hypothesis.",
               "hypotheses": []}],
             "accepted:model_gateway", 1,
             detail="declining to hypothesise is a valid, honest outcome"),
        Case("malformed-json-refused", "schema-validity",
             ["{ not json"], "refused:ModelOutputInvalid", 3,
             detail="initial call plus two bounded repairs, then fail closed"),
        Case("truncated-json-refused", "schema-validity",
             ['{"summary": "cut off mid-pay'], "refused:ModelOutputInvalid", 3,
             detail="a token-cap truncation must fail closed, not be salvaged"),
        Case("fabricated-citation-refused", "evidence-confinement",
             [_valid_reply("obs_fabricated_not_supplied")], "refused:ModelOutputInvalid", 3,
             detail="citing an observation outside the package is rejected through repair exhaustion"),
        Case("unsupported-evidence-type-refused", "schema-validity",
             [{**valid, "hypotheses": [{**valid["hypotheses"][0],
                                        "required_evidence": ["shell_access"]}]}],
             "refused:ModelOutputInvalid", 3,
             detail="only the fixed evidence-type vocabulary may be requested"),
        Case("claim-too-short-refused", "schema-validity",
             [{**valid, "hypotheses": [{**valid["hypotheses"][0], "claim": "short"}]}],
             "refused:ModelOutputInvalid", 3),
        Case("extra-field-refused", "schema-validity",
             [{**valid, "verdict_override": "confirmed"}], "refused:ModelOutputInvalid", 3,
             detail="the reply schema forbids extra fields; an escalation attempt fails"),
        Case("repair-recovers", "repair-loop",
             ["{ not json", valid], "accepted:model_gateway", 2,
             detail="one malformed reply repaired once within the bound persists with repair_attempts=1"),
        Case("consent-missing-falls-back", "consent-gating", [valid],
             "accepted:deterministic_fallback", 0,
             consent={"enabled": False, "provider": None},
             detail="without consent the deterministic fallback runs and the provider is never called"),
        Case("budget-exhausted-refused", "budget-gating", [valid],
             "refused:ModelBudgetExceeded", 0, max_model_tokens=0,
             detail="a zero budget refuses before any provider call"),
    ]


_EXCEPTIONS = {
    "ModelConsentRequired": ModelConsentRequired,
    "ModelOutputInvalid": ModelOutputInvalid,
    "ModelBudgetExceeded": ModelBudgetExceeded,
}


def run_case(session: Session, fx: Fixture, case: Case) -> CaseResult:
    row = session.get(InvestigationRow, fx.investigation_id)
    if case.consent is not None:
        row.llm_data_sharing = case.consent
    if case.max_model_tokens is not None:
        row.budget_json = {"max_model_tokens": case.max_model_tokens}
    session.commit()

    payloads = [r if isinstance(r, str) else json.dumps(r) for r in case.responses]
    provider = SequencedProvider(payloads)
    gateway = StructuredModelGateway(provider, model=MODEL)
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    expected_kind, _, expected_value = case.expected.partition(":")
    observed = ""
    detail = case.detail
    try:
        result = NexusHypothesisService(
            session, gateway=gateway, session_factory=factory
        ).generate(fx.investigation_id)
        observed = f"accepted:{result['mode']}"
        ok = expected_kind == "accepted" and observed == case.expected
        if ok and result["mode"] == "model_gateway":
            rows = session.execute(select(HypothesisRow).where(
                HypothesisRow.investigation_id == fx.investigation_id,
            )).scalars().all()
            expected_claims = 0
            if case.name not in ("empty-hypotheses-persisted",):
                expected_claims = len(case.responses[-1]["hypotheses"])
            if len(rows) != expected_claims:
                ok = False
                detail = f"persisted {len(rows)} hypotheses, expected {expected_claims}"
            if case.name == "repair-recovers" and result["repair_attempts"] != 1:
                ok = False
                detail = f"repair_attempts={result['repair_attempts']}, expected 1"
        if ok and result["mode"] == "deterministic_fallback":
            if provider.calls != 0:
                ok = False
                detail = "provider called on the fallback path"
    except tuple(_EXCEPTIONS.values()) as exc:
        observed = f"refused:{type(exc).__name__}"
        ok = expected_kind == "refused" and observed == case.expected
        if ok:
            persisted = session.execute(select(HypothesisRow).where(
                HypothesisRow.investigation_id == fx.investigation_id,
            )).scalars().all()
            if persisted:
                ok = False
                detail = "a refused generation persisted hypotheses anyway"
            rejection = session.execute(select(DecisionRow).where(
                DecisionRow.investigation_id == fx.investigation_id,
                DecisionRow.agent == "NEXUS",
                DecisionRow.action == "generate_hypotheses_rejected",
            )).scalars().all()
            if ok and not rejection:
                ok = False
                detail = "the bounded rejection diagnostics were not persisted"
    if provider.calls != case.expected_provider_calls:
        ok = False
        detail = (detail + "; " if detail else "") + (
            f"provider called {provider.calls}x, expected {case.expected_provider_calls}x")
    session.rollback()  # undo any partial state; each case starts from the fixture
    # restore fixture consent/budget for the next case
    row = session.get(InvestigationRow, fx.investigation_id)
    row.llm_data_sharing = {"enabled": True, "provider": "mock"}
    row.budget_json = {"max_model_tokens": 1_000_000}
    session.commit()
    return CaseResult(case=case, ok=ok, observed=observed, detail=detail)


@dataclass(slots=True)
class Report:
    mode: str
    results: list[CaseResult] = field(default_factory=list)
    probes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(result.ok for result in self.results)

    def render(self) -> str:
        lines = [f"nexus_acceptance mode={self.mode} ok={self.ok}"]
        for result in self.results:
            mark = "PASS" if result.ok else "FAIL"
            line = (f"[{mark}] {result.case.name} ({result.case.criterion}): "
                    f"expected {result.case.expected}, observed {result.observed}")
            if result.detail:
                line += f" -- {result.detail}"
            lines.append(line)
        for probe in self.probes:
            lines.append(f"note: {probe}")
        lines.append("VERDICT: " + ("every expected guard held and every accept path persisted"
                                     if self.ok else "AT LEAST ONE CASE FAILED - read FAIL lines above"))
        return "\n".join(lines)


def _mock_report() -> Report:
    with tempfile.TemporaryDirectory() as tmp:
        from ..api.config import Settings
        from ..api.deps import AppContext, set_context

        settings = Settings(
            db_url="sqlite+pysqlite:///:memory:",
            artifact_root=Path(tmp) / "artifacts",
            env="test",
        )
        context = AppContext(settings)
        set_context(context)
        try:
            store = ArtifactStore(Path(tmp) / "artifacts")
            session = context.session()
            try:
                fx = build_fixture(session, store)
                report = Report(mode="mock")
                for case in cases(fx):
                    report.results.append(run_case(session, fx, case))
                session.close()
                return report
            finally:
                session.close()
        finally:
            set_context(None)


def _live_report(mode: str = "ollama") -> Report:
    """Live probe: one seeded fixture, measured against the acceptance floor.

    ``ollama`` drives a local Ollama model; ``opencode`` drives an OpenCode
    free-tier model through the official CLI (eval-only adapter, see
    mobius.tools.opencode_provider). Both measure the same acceptance floor.
    """
    from ..api.config import Settings
    from ..api.deps import AppContext, set_context
    from .opencode_provider import OpenCodeCliProvider

    model = os.environ.get("MOBIUS_MODEL_NAME", "")
    if not model.strip():
        raise SystemExit("MOBIUS_MODEL_NAME is required for live mode; the model must already be available")
    timeout = int(os.environ.get("MOBIUS_MODEL_TIMEOUT_SECONDS", "120"))
    if mode == "opencode":
        provider = OpenCodeCliProvider()
        fx_provider = "opencode"
    else:
        base_url = os.environ.get("MOBIUS_MODEL_BASE_URL", "http://127.0.0.1:11434")
        provider = OllamaProvider(base_url)
        fx_provider = "ollama"

    with tempfile.TemporaryDirectory() as tmp:
        settings = Settings(
            db_url="sqlite+pysqlite:///:memory:",
            artifact_root=Path(tmp) / "artifacts",
            env="test",
        )
        context = AppContext(settings)
        set_context(context)
        try:
            store = ArtifactStore(Path(tmp) / "artifacts")
            session = context.session()
            try:
                fx = build_fixture(session, store, provider=fx_provider)
                gateway = StructuredModelGateway(provider, model=model, timeout_seconds=timeout)
                factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)
                report = Report(mode=mode)
                started = time.monotonic()
                try:
                    result = NexusHypothesisService(
                        session, gateway=gateway, session_factory=factory, store=store
                    ).generate(fx.investigation_id)
                    elapsed = time.monotonic() - started
                    # The floor requires at least one hypothesis: a schema-valid
                    # but EMPTY reply is a quality failure, not an accept.
                    accepted = result["mode"] == "model_gateway" and len(result["hypotheses"]) >= 1
                    grounded = sum(
                        1 for h in result["hypotheses"] if h.get("derived_from")
                    )
                    claims = " | ".join(
                        str(h.get("claim", ""))[:80] for h in result["hypotheses"][:5]
                    )
                    report.results.append(CaseResult(
                        case=Case("live-seeded-fixture", "quality-floor", [],
                                  "accepted:model_gateway", 1),
                        ok=accepted,
                        observed=(f"accepted:{result['mode']}, "
                                  f"hypotheses={len(result['hypotheses'])}"),
                        detail=(f"measured {elapsed:.1f}s (timeout budget {timeout}s); "
                                f"repair_attempts={result['repair_attempts']}; "
                                f"tokens in/out: {result['token_usage'].get('input_tokens')}"
                                f"/{result['token_usage'].get('output_tokens')}; "
                                f"hypotheses={len(result['hypotheses'])} "
                                f"({grounded} with evidence refs); "
                                f"claims: {claims}"),
                    ))
                except (ModelConsentRequired, ModelOutputInvalid, ModelBudgetExceeded) as exc:
                    elapsed = time.monotonic() - started
                    report.results.append(CaseResult(
                        case=Case("live-seeded-fixture", "quality-floor", [],
                                  "accepted:model_gateway", 1),
                        ok=False,
                        observed=f"refused:{type(exc).__name__}",
                        detail=f"guards rejected the live response after {elapsed:.1f}s",
                    ))
                report.probes.append(
                    "note: live mode measures ONE seeded fixture; a pass is a minimum "
                    "quality floor for hypothesis generation, not a quality endorsement, "
                    "and not evidence about investigation-wide intelligence")
                session.close()
                return report
            finally:
                session.close()
        finally:
            set_context(None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["mock", "ollama", "opencode"], default="mock")
    args = parser.parse_args(argv)
    report = _mock_report() if args.mode == "mock" else _live_report(args.mode)
    print(report.render())
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
