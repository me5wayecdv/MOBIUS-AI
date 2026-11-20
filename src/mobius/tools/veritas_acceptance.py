"""Executable acceptance harness for a candidate VERITAS reviewer model.

VERITAS is advisory only; deterministic gates remain the sole verdict authority.
This harness answers a narrower question than "is the model good": does the review
path accept ONLY reviews that satisfy the integrity contract, and (in live mode)
does a specific candidate model satisfy it in practice?

Modes:

- ``mock`` (default, free, deterministic): scripted provider responses prove that
  every integrity guard on the review path fires when it must and that well-formed
  reviews persist without touching gate verdicts. A green mock run pins the
  acceptance BAR. It says nothing about any real model's quality.
- ``ollama`` (operator action, local only): runs live probes against a locally
  installed Ollama model and reports measured latency and token usage against the
  acceptance criteria. Never downloads a model, never calls a hosted provider.

Exit code 0 means every case met its expected outcome; 1 means at least one did
not. A failing mock run means a GUARD regressed. A failing live run means the
candidate model does not currently meet the bar; it is not a pipeline defect by
itself.
"""
from __future__ import annotations

import argparse
import io
import json
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

from ..adapters.models import DecisionRow, EvidenceRow, FindingRow, InvestigationRow, VerdictRow
from ..core.schemas import SourceRef
from ..core.enums import Severity
from ..services.artifacts import ArtifactStore
from ..services.intake import IntakeService
from ..services.model_provider import (
    DeterministicMockProvider,
    ModelBudgetExceeded,
    ModelConsentRequired,
    ModelOutputInvalid,
    OllamaProvider,
    OpenCodeCliProvider,
    StructuredModelGateway,
)
from ..services.validation import ValidationService
from ..services.veritas import VeritasReviewService

PRODUCER_MODEL = "producer-v1"
REVIEWER_MODEL = "candidate-reviewer"


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
    finding_id: str
    investigation_id: str
    verdict_id: str
    evidence_id: str
    other_evidence_id: str


def build_fixture(session: Session, store: ArtifactStore, *, variant: str = "challengeable") -> Fixture:
    """A confirmed finding with persisted evidence, plus a second investigation whose
    evidence ID exists but is OUTSIDE the finding's investigation (for the
    cross-investigation citation case). ``variant`` selects the oracle:
    challengeable (thin evidence under a strong claim; a challenge is correct)
    or solid (evidence covers every claim element; no material challenge is
    correct - the review false-positive control)."""
    future = _future_iso()

    def _one(suffix: str) -> tuple[str, str, str, str]:
        intake = IntakeService(session, store)
        app, _ = intake.create_application(_make_apk(), f"fixture-{suffix}.apk", uploaded_by="u")
        auth = intake.create_authorization(
            apk_sha256=app.sha256,
            target_package="com.example",
            scope_text="Static analysis of the supplied artefact only.",
            statement="s",
            max_intensity=2,
            granted_by="u",
            expires_at=future,
        )
        investigation = intake.create_investigation(
            application_id=app.id,
            authorization_id=auth.id,
            objective="Review a candidate Android security finding.",
            intensity=0,
            created_by="u",
        )
        row = session.get(InvestigationRow, investigation.id)
        row.llm_data_sharing = {"enabled": True, "provider": "mock"}
        row.budget_json = {"max_model_tokens": 1_000_000}
        session.flush()
        evidence_id = f"ev_acceptance_{variant}_{suffix}"
        summary = (
            "A persisted code observation showing a reachable file write."
            if variant == "challengeable"
            else "Decompiled code shows exported activity com.example.Entry with no "
                 "android:permission attribute and no runtime caller check, reading the "
                 "untrusted Intent extra 'path' without validation and using it as the "
                 "filename passed directly to java.io.FileOutputStream inside the app's "
                 "private files directory on the main onCreate path; the sink is "
                 "reachable from the attacker-supplied extra, so another app can make "
                 "this app overwrite its own private files (privileged sink: writes to "
                 "app-private storage the calling app could not write itself)."
        )
        session.add(EvidenceRow(
            id=evidence_id,
            investigation_id=investigation.id,
            kind="code_analysis",
            sha256="a" * 64,
            object_key=f"evidence/{suffix}",
            byte_size=128,
            truncated=False,
            redacted=True,
            summary=summary,
            produced_by="SPECTRE",
            created_at=future,
        ))
        session.flush()
        extra_evidence: tuple[str, ...] = ()
        if variant == "solid":
            manifest_evidence_id = f"ev_acceptance_{variant}_manifest_{suffix}"
            session.add(EvidenceRow(
                id=manifest_evidence_id,
                investigation_id=investigation.id,
                kind="manifest_excerpt",
                sha256="b" * 64,
                object_key=f"evidence/{suffix}-manifest",
                byte_size=256,
                truncated=False,
                redacted=True,
                summary=(
                    "AndroidManifest excerpt: <activity android:name=\".Entry\" "
                    "android:exported=\"true\"> with an intent-filter and no "
                    "android:permission attribute; no protectionLevel declared."
                ),
                produced_by="SPECTRE",
                created_at=future,
            ))
            session.flush()
            extra_evidence = (manifest_evidence_id,)
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
            evidence_refs=(evidence_id,) + extra_evidence,
            discovered_by="SPECTRE",
            validated_by="DETERMINISTIC_GATE",
            severity=Severity.HIGH,
            component_ref=("com.example.Entry" if variant == "solid" else None),
            source_ref=(SourceRef(file="com/example/Entry.java",
                                  class_name="com.example.Entry",
                                  method="onCreate", lines=(41, 58))
                        if variant == "solid" else None),
        )
        session.flush()
        return finding.id, investigation.id, verdict.id, evidence_id

    finding_id, investigation_id, verdict_id, evidence_id = _one("main")
    _, _, _, other_evidence_id = _one("other")
    session.commit()
    return Fixture(finding_id, investigation_id, verdict_id, evidence_id, other_evidence_id)


class CountingProvider(DeterministicMockProvider):
    def __init__(self, response_json: str, *, model_id: str = REVIEWER_MODEL):
        super().__init__(response_json, model_id=model_id, prompt_tokens=30, completion_tokens=20)
        self.calls = 0

    def complete_json(self, **kwargs):
        self.calls += 1
        return super().complete_json(**kwargs)


@dataclass(frozen=True, slots=True)
class Case:
    name: str
    criterion: str
    response: Any  # dict serialised to JSON, or a raw string for malformed payloads
    expected: str  # "persisted:<disposition>" or "refused:<exception class name>"
    expected_provider_calls: int = 1
    requested_model: str = REVIEWER_MODEL
    actual_model: str = REVIEWER_MODEL
    consent: dict[str, Any] | None = None  # overrides the fixture's consent when set
    max_model_tokens: int | None = None  # overrides the fixture's budget when set
    detail: str = ""


@dataclass(slots=True)
class CaseResult:
    case: Case
    ok: bool
    observed: str
    detail: str = ""


def _valid_challenge(evidence_id: str) -> dict[str, Any]:
    return {
        "disposition": "challenge",
        "summary": "The evidence establishes reachability but does not establish attacker control of the path.",
        "challenges": [{
            "challenge_type": "unsupported_claim",
            "statement": "The supplied summary does not show that the path value is attacker controlled.",
            "evidence_refs": [evidence_id],
            "requested_proof": "Provide a source-level trace from the exported input to the file sink.",
        }],
    }


def cases(fx: Fixture) -> list[Case]:
    valid = _valid_challenge(fx.evidence_id)
    fabricated = _valid_challenge("ev_fabricated_not_supplied")
    cross = _valid_challenge(fx.other_evidence_id)
    unicode_ref = _valid_challenge(fx.evidence_id + "​")  # zero-width space
    return [
        Case("valid-challenge-persisted", "schema-validity", valid, "persisted:challenge",
             detail="a well-formed, evidence-confined challenge is the accept path"),
        Case("no-material-challenge-persisted", "schema-validity",
             {"disposition": "no_material_challenge",
              "summary": "No concrete contradiction, missing proof, or alternative explanation identified.",
              "challenges": []},
             "persisted:no_material_challenge",
             detail="a lack of challenge is not confirmation; only the disposition is recorded"),
        Case("insufficient-evidence-persisted", "schema-validity",
             {"disposition": "insufficient_evidence",
              "summary": "The supplied summaries cannot support a meaningful review.",
              "challenges": []},
             "persisted:insufficient_evidence"),
        Case("malformed-json-needs-review", "schema-validity",
             "{ not json", "needs_review", expected_provider_calls=2,
             detail="unconvertible reply is captured as needs-review after one bounded repair pass; no verdict is fabricated"),
        Case("truncated-json-needs-review", "schema-validity",
             '{"disposition": "challenge", "summary": "cut off mid-pay', "needs_review", expected_provider_calls=2,
             detail="a token-cap truncation can never become a verdict; captured needs-review after repair"),
        Case("fabricated-evidence-ref-refused", "evidence-confinement",
             fabricated, "refused:ModelOutputInvalid"),
        Case("cross-investigation-ref-refused", "evidence-confinement",
             cross, "refused:ModelOutputInvalid",
             detail="a REAL evidence id from another investigation is still outside the supplied set"),
        Case("unicode-confusable-ref-refused", "evidence-confinement",
             unicode_ref, "refused:ModelOutputInvalid",
             detail="a zero-width-space suffix makes the ref a different string; no normalisation rescue"),
        Case("challenge-without-challenges-refused", "disposition-discipline",
             {**valid, "challenges": []}, "refused:ModelOutputInvalid"),
        Case("no-material-challenge-with-challenges-refused", "disposition-discipline",
             {"disposition": "no_material_challenge",
              "summary": "Claims nothing while still attaching a challenge.",
              "challenges": valid["challenges"]}, "refused:ModelOutputInvalid"),
        Case("disposition-enum-abuse-needs-review", "disposition-discipline",
             {**valid, "disposition": "confirmed"}, "needs_review", expected_provider_calls=2,
             detail="a model can never pronounce a finding confirmed; the invalid disposition cannot be converted and is captured needs-review"),
        Case("statement-too-short-needs-review", "schema-validity",
             {**valid, "challenges": [{**valid["challenges"][0], "statement": "too short"}]},
             "needs_review", expected_provider_calls=2),
        Case("extra-field-dropped-persisted", "schema-validity",
             {**valid, "verdict_override": "confirmed"}, "persisted:challenge",
             detail="undeclared fields are presentation noise: dropped and recorded in normalization provenance; verdict authority stays with deterministic gates"),
        Case("same-requested-model-refused", "independence",
             valid, "refused:ModelConsentRequired", expected_provider_calls=0,
             requested_model=PRODUCER_MODEL,
             detail="requested reviewer equal to the producer is refused before any provider call"),
        Case("producer-alias-resolution-refused", "independence",
             valid, "refused:ModelConsentRequired", expected_provider_calls=1,
             actual_model=PRODUCER_MODEL,
             detail="an alias that RESOLVES to the producer is refused after the response, not persisted"),
        Case("consent-missing-refused", "consent-gating",
             valid, "refused:ModelConsentRequired", expected_provider_calls=0,
             consent={"enabled": False, "provider": "mock"}),
        Case("budget-exhausted-refused", "budget-gating",
             valid, "refused:ModelBudgetExceeded", expected_provider_calls=0,
             max_model_tokens=0,
             detail="a zero budget refuses before any provider call"),
        Case("usage-over-ceiling-refused", "budget-gating",
             valid, "refused:ModelBudgetExceeded", expected_provider_calls=1,
             detail="provider reporting more output tokens than the cap is charged and refused",
             ),
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

    payload = case.response if isinstance(case.response, str) else json.dumps(case.response)
    provider = CountingProvider(payload, model_id=case.actual_model)
    if case.name == "usage-over-ceiling-refused":
        provider.completion_tokens = 5000  # over the 1200-token review cap
    gateway = StructuredModelGateway(provider, model=case.requested_model)
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)

    expected_kind, _, expected_value = case.expected.partition(":")
    observed = ""
    detail = case.detail
    try:
        result = VeritasReviewService(
            session, gateway=gateway, session_factory=factory
        ).review(fx.finding_id, producer_model_id=PRODUCER_MODEL)
        if result.get("status") == "needs_review":
            observed = "needs_review"
            ok = case.expected == "needs_review"
            if ok:
                row = session.get(DecisionRow, result["decision_id"])
                if row is None or row.output_json.get("status") != "needs_review":
                    ok = False
                    detail = "needs-review result without a persisted needs-review record"
            return _finish(session, fx, case, provider, CaseResult(case=case, ok=ok, observed=observed, detail=detail))
        observed = f"persisted:{result['disposition']}"
        ok = expected_kind == "persisted" and observed == case.expected
        if ok and result["disposition"] == "challenge":
            verdict = session.get(VerdictRow, fx.verdict_id)
            finding = session.get(FindingRow, fx.finding_id)
            if verdict.verdict != "confirmed" or finding.status != "confirmed":
                ok = False
                detail = "verdict-authority violated: gate verdict or finding status changed"
    except tuple(_EXCEPTIONS.values()) as exc:
        observed = f"refused:{type(exc).__name__}"
        ok = expected_kind == "refused" and observed == case.expected
        if ok:
            persisted = session.execute(select(DecisionRow).where(
                DecisionRow.investigation_id == fx.investigation_id,
                DecisionRow.agent == "VERITAS",
                DecisionRow.action == "review_finding",
            )).scalars().all()
            if persisted:
                ok = False
                detail = "a refused review was persisted anyway"
    return _finish(session, fx, case, provider, CaseResult(case=case, ok=ok, observed=observed, detail=detail))


def _finish(session: Session, fx: Fixture, case: Case, provider: CountingProvider, result: CaseResult) -> CaseResult:
    ok, detail = result.ok, result.detail
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
    return CaseResult(case=case, ok=ok, observed=result.observed, detail=detail)


@dataclass(slots=True)
class Report:
    mode: str
    results: list[CaseResult] = field(default_factory=list)
    probes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(r.ok for r in self.results)

    def render(self) -> str:
        lines = [f"VERITAS acceptance harness ({self.mode} mode)"]
        for r in self.results:
            mark = "PASS" if r.ok else "FAIL"
            line = f"[{mark}] {r.case.name} ({r.case.criterion}): expected {r.case.expected}, observed {r.observed}"
            if r.detail:
                line += f" -- {r.detail}"
            lines.append(line)
        lines.extend(self.probes)
        lines.append("VERDICT: " + ("every expected guard held and every accept path persisted"
                                     if self.ok else "AT LEAST ONE CASE FAILED ITS EXPECTATION"))
        return "\n".join(lines)


def _mock_report() -> Report:
    from ..api.config import Settings
    from ..api.deps import AppContext, set_context

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
    """Live probes against a real model. Operator action only.

    ``ollama`` drives a local Ollama model; ``opencode`` drives an OpenCode
    free-tier model through the official CLI (eval-only adapter, see
    mobius.services.model_provider). Both measure the same acceptance floor.
    """
    import os

    from ..api.config import Settings
    from ..api.deps import AppContext, set_context

    model = os.environ.get("MOBIUS_MODEL_NAME", "")
    if not model.strip():
        raise SystemExit("MOBIUS_MODEL_NAME is required for live mode; the model must already be available")
    timeout = int(os.environ.get("MOBIUS_MODEL_TIMEOUT_SECONDS", "120"))
    if mode == "opencode":
        provider = OpenCodeCliProvider()
    else:
        base_url = os.environ.get("MOBIUS_MODEL_BASE_URL", "http://127.0.0.1:11434")
        provider = OllamaProvider(base_url)

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
                gateway = StructuredModelGateway(provider, model=model, timeout_seconds=timeout)
                factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)
                report = Report(mode=mode)
                # challengeable: the discriminating floor (must challenge).
                # solid: semantic control floor. The package fully covers every
                # claim element, so answering insufficient_evidence is a REVIEW
                # FAILURE (ducking a complete package). challenge vs
                # no_material_challenge is a legitimate materiality judgment and
                # is reported informationally, never marketed as a quality pass.
                for variant, expected_disp in (
                    ("challengeable", "challenge"),
                    ("solid", "any"),
                ):
                    fx = build_fixture(session, store, variant=variant)
                    row = session.get(InvestigationRow, fx.investigation_id)
                    row.llm_data_sharing = {"enabled": True, "provider": mode}
                    session.commit()
                    started = time.monotonic()
                    try:
                        result = VeritasReviewService(
                            session, gateway=gateway, session_factory=factory
                        ).review(fx.finding_id, producer_model_id=PRODUCER_MODEL)
                        elapsed = time.monotonic() - started
                        accepted = (
                            result["disposition"] == expected_disp
                            if expected_disp != "any"
                            else result["disposition"] in {
                                "challenge", "no_material_challenge"
                            }
                        )
                        report.results.append(CaseResult(
                            case=Case(f"live-{variant}-fixture", "quality-floor",
                                      {}, f"persisted:{expected_disp if expected_disp != 'any' else 'challenge-or-no_material_challenge (insufficient_evidence=review failure)'}"),
                            ok=accepted,
                            observed=f"persisted:{result['disposition']}",
                            detail=(f"measured {elapsed:.1f}s (timeout budget {timeout}s); "
                                    f"tokens in/out: {result.get('input_tokens')}/{result.get('output_tokens')}" + (
                                        f"; CLI totals in/out: "
                                        f"{provider.last_cli_input_tokens}/"
                                        f"{provider.last_cli_output_tokens} "
                                        f"(includes OpenCode platform overhead)"
                                        if mode == "opencode" else ""
                                    )),
                        ))
                    except (ModelConsentRequired, ModelOutputInvalid, ModelBudgetExceeded) as exc:
                        elapsed = time.monotonic() - started
                        report.results.append(CaseResult(
                            case=Case(f"live-{variant}-fixture", "quality-floor",
                                      {}, f"persisted:{expected_disp}"),
                            ok=False,
                            observed=f"refused:{type(exc).__name__}",
                            detail=f"guards rejected the live response after {elapsed:.1f}s",
                        ))
                report.probes.append(
                    "note: live mode measures small seeded fixtures; a pass is a "
                    "minimum quality floor, not a quality endorsement")
                session.close()
                return report
            finally:
                session.close()
        finally:
            set_context(None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=["mock", "ollama", "opencode"], default="mock")
    args = parser.parse_args(argv)
    report = _mock_report() if args.mode == "mock" else _live_report(args.mode)
    print(report.render())
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
