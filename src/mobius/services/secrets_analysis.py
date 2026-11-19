"""SECRETS ANALYSIS APPLY: push validated worker candidate facts through the gate.

Phase-1 candidate-only contract, server side. The isolated worker transports
redacted structural facts; this service applies them the only way this
platform allows: one finding per transported candidate, every attribute
derived API-side by ``mobius.adapters.secrets_payload``, every conclusion
decided by the hardcoded-secret validation gate - never by the worker.

What it establishes:

* CANDIDATES ONLY. ``format_and_entropy_ok`` is never written, so CONFIRMED
  is unreachable; no clause is ever written False, so REJECTED is
  unreachable. Every finding lands MANUAL_REVIEW_REQUIRED /
  INSUFFICIENT_EVIDENCE with an explicit conservative severity and a
  confidence cap below the partial-establishment maximum.
* Scan-level truth regardless of candidate count: the completion event
  carries the full accounting (screened / evidence-less / conversion-failed /
  merged / transported / placeholder-dropped / truncated /
  transport-complete), the worker-asserted DEX ledger state, the
  flow-incomplete candidate count and the detector's coverage limits as
  separate fields. ``transport_complete`` describes payload transport only;
  it is never a scan-complete, safe or no-secrets label, and an empty result
  is never a no-secrets claim.

What it does not do:

* It never parses the APK. The only artifact-bytes use is the bounded zip
  metadata cross-check (entry names and sizes) in the route.
* It never stores the literal, a literal hash or worker prose. Evidence
  documents are API-rendered from enumerated facts and marked
  worker-reported.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from sqlalchemy.orm import Session

from ..adapters.events import SqlEventStore
from ..adapters.models import ApplicationRow, AuthorizationRow, InvestigationRow
from ..adapters.secrets_payload import (
    SecretsAnalysisResult,
    accounting,
    derive_candidate_attributes,
)
from ..core.enums import EvidenceKind, Severity
from .artifacts import ArtifactStore
from .errors import AuthorizationRequired, NotFound, ScanStateConflict
from .evidence import EvidenceService
from .intake import is_expired
from .validation import ValidationService

AGENT = "SPECTRE"
CATEGORY = "hardcoded-secret"
KIND = "secrets_analysis"


def _tier(basis: str | None) -> tuple[Severity, float]:
    """Explicit per-basis severity and confidence cap.

    Candidates never inherit the gate's HIGH severity hint: the
    credential-format clause is never established in phase 1. Tiers use only
    the platform's existing Severity enum and distinguish evidence roles:
    direct key-material evidence is MEDIUM; a MAY-depend derived-only route
    is LOW with a lower cap (transform output unmodelled, uncertainty
    explicit); comparison-suspect evidence alone is a review signal with no
    key-role evidence, tiered INFO. Severity is the field that
    distinguishes the three bases: derived-only and comparison-only share
    the 0.2 cap, so they are NOT distinguishable by confidence. Every cap
    sits below the validator's partial-establishment maximum so no
    candidate reaches 1.0. All tiers stay MANUAL_REVIEW_REQUIRED; every
    fact is worker-reported and never independently verified API-side."""
    if basis == "direct-key-material-evidence":
        return Severity.MEDIUM, 0.3
    if basis == "may-depend-derived-route-only":
        return Severity.LOW, 0.2
    return Severity.INFO, 0.2

DETECTOR_COVERAGE_LIMITS = (
    "Direct const-string literals are matched only at the screened sinks: "
    "key-material sinks `SecretKeySpec.<init>` and `PBEKeySpec.<init>` "
    "argument 1, `KeyStore.load` argument 2, and `String` "
    "`equals`, `equalsIgnoreCase`, `contentEquals` or `compareTo` "
    "comparisons (review-signal only).",
    "One bounded MAY-depend route is also flagged: a closed-world pure "
    "transform whose input reads a const-string and whose return may reach "
    "a key-material argument. The transform's output bytes are not "
    "modelled: these are possible dependencies, never proven derived keys.",
    "Secrets that are split, computed, loaded from resources or native "
    "code, decrypted at runtime, passed through arbitrary or chained "
    "transforms, or otherwise not a const-string input to a screened sink "
    "or its bounded MAY-depend route are outside coverage. An empty result "
    "is not a no-secrets result.",
    "transport_complete describes payload transport only - never a "
    "scan-complete, safe or no-secrets label.",
)


class SecretsAnalysisService:
    def __init__(self, session: Session, store: ArtifactStore) -> None:
        self._session = session
        self._store = store
        self._evidence = EvidenceService(session, store)

    def _authorized_application(self, investigation_id: str):
        """Every check that binds this analysis to the authorized artifact.

        Identical gate to the provider apply path: the payload's digest
        binding is validated by the route before this is called, and the
        package check is repeated against the worker result's package."""
        row = self._session.get(InvestigationRow, investigation_id)
        if row is None:
            raise NotFound(f"investigation {investigation_id} not found")
        application = self._session.get(ApplicationRow, row.application_id)
        if application is None:  # pragma: no cover - FK makes this unreachable
            raise NotFound(f"application {row.application_id} not found")

        authorization = (
            self._session.get(AuthorizationRow, row.authorization_id)
            if row.authorization_id else None
        )
        if authorization is None:
            raise AuthorizationRequired("investigation has no active APK authorization")
        if authorization.revoked_at is not None or is_expired(authorization.expires_at):
            raise AuthorizationRequired("APK authorization is revoked or expired")
        if authorization.apk_sha256 != application.sha256:
            raise AuthorizationRequired("APK authorization is bound to a different artifact")
        return application, authorization

    def _already_applied_job(self, investigation_id: str, exclude_job_id: str | None):
        from ..adapters.models import WorkerJobRow
        from sqlalchemy import select as _select
        stmt = _select(WorkerJobRow).where(
            WorkerJobRow.investigation_id == investigation_id,
            WorkerJobRow.kind == KIND,
            WorkerJobRow.applied_at.is_not(None),
        )
        if exclude_job_id is not None:
            stmt = stmt.where(WorkerJobRow.id != exclude_job_id)
        return self._session.execute(stmt.limit(1)).scalar_one_or_none()

    def run_from_payload(
        self, investigation_id: str, result: SecretsAnalysisResult, *,
        validated_by: str, applied_job_id: str | None = None,
    ) -> dict[str, object]:
        """Apply a validated isolated-worker payload: same authorization
        gates, same lifecycle gate, same gate. The API never parses the APK."""
        _, authorization = self._authorized_application(investigation_id)
        if authorization.target_package != result.package_name:
            raise AuthorizationRequired(
                "authorized target package does not match the package in the worker result"
            )
        # Lifecycle state gate: a second application would duplicate findings
        # and evidence. The current job, already claimed by claim_apply, is
        # excluded from its own gate.
        other = self._already_applied_job(investigation_id, applied_job_id)
        if other is not None:
            raise ScanStateConflict(
                f"secrets analysis was already applied for this investigation "
                f"(worker job {other.id})"
            )

        derived = derive_candidate_attributes(result)
        acc = accounting(result, derived)

        validator = ValidationService(self._session)
        results = []
        for d in derived:
            if d.dropped:
                continue  # placeholder-screened: counted in accounting, never a finding
            cls, name, desc, off = d.candidate.candidate_id
            severity, cap = _tier(d.candidate.security_use_basis)
            document = {
                "candidate_identity": {
                    "class": cls, "method": name,
                    "descriptor": desc, "literal_offset": off,
                },
                "transport": "worker-reported; not independently verified",
                "attributes": d.attributes,
                "title": d.title,
                "description": d.description,
                "evidence": [asdict(e) for e in d.candidate.evidence],
                "placeholder_screening": d.candidate.placeholder_screening,
                "flow_complete": d.candidate.flow_complete,
                "dex_complete": result.dex_complete,
                "dex_coverage": [b.describe() for b in result.ledger],
            }
            evidence = self._evidence.record(
                investigation_id=investigation_id,
                kind=EvidenceKind.TOOL_OUTPUT,
                content=json.dumps(document, indent=2).encode(),
                summary=(
                    f"secrets-analysis candidate: {cls}->{name} "
                    "(worker-reported, manual review)"
                ),
                produced_by=AGENT,
            )
            finding, verdict = validator.validate(
                investigation_id=investigation_id,
                category=CATEGORY,
                attributes=d.attributes,
                title=d.title,
                description=d.description,
                evidence_refs=(evidence.id,),
                discovered_by=AGENT,
                validated_by=validated_by,
                severity=severity,
                confidence_cap=cap,
                component_ref=cls,
            )
            results.append(
                {
                    "candidate_id": [cls, name, desc, off],
                    "attributes": d.attributes,
                    "finding_id": finding.id,
                    "finding_status": finding.status.value,
                    "verdict": verdict.verdict.value,
                    "evidence_id": evidence.id,
                }
            )

        flow_incomplete = sum(
            1 for d in derived if not d.dropped and not d.candidate.flow_complete
        )
        SqlEventStore(self._session).emit(
            investigation_id,
            "secrets_analysis_completed",
            {
                "package_name": result.package_name,
                "methods_adapted": result.methods_adapted,
                "accounting": asdict(acc),
                "dex_complete": result.dex_complete,
                "dex_coverage": [b.describe() for b in result.ledger],
                "flow_incomplete_candidates": flow_incomplete,
                "detector_coverage_limits": list(DETECTOR_COVERAGE_LIMITS),
                "findings": [
                    {"candidate_id": r["candidate_id"], "verdict": r["verdict"]}
                    for r in results
                ],
            },
            actor=AGENT,
        )
        self._session.flush()
        return {
            "package_name": result.package_name,
            "methods_adapted": result.methods_adapted,
            "dex_complete": result.dex_complete,
            "accounting": asdict(acc),
            "flow_incomplete_candidates": flow_incomplete,
            "detector_coverage_limits": list(DETECTOR_COVERAGE_LIMITS),
            "results": results,
        }
