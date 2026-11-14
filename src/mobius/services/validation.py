"""Independent validation: gate evaluation -> verdict -> finding.

This is the module that embodies the project's thesis. A model may *propose* a finding;
only a deterministic gate over evidence may *confirm* one (ADR-012).

Three rules enforced here, each corresponding to a documented failure of scanner-style
tools:

1. All gate clauses must pass. There is no partial credit and no score threshold, because
   a threshold is a way of averaging away the clause you could not establish.
2. A missing attribute is not the same as a failed one. Missing -> INSUFFICIENT_EVIDENCE,
   failed -> REJECTED. Collapsing them makes the tool look certain about things it never
   checked.
3. The validator must differ from the discoverer. Same-model self-review produces
   correlated errors: it tends to agree with its own framing (ADR-010).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..adapters.events import SqlEventStore, utcnow
from ..adapters.models import FindingRow, VerdictRow
from ..core import gates
from ..core.enums import (
    FindingStatus,
    RejectionReason,
    Severity,
    Verdict,
)
from ..core.schemas import Finding, SourceRef, VerdictRecord
from .errors import MissingEvidence, ValidatorMustDiffer

# When a clause fails outright, which rejection reason best explains it? Explicit mapping
# rather than free text, so rejections aggregate into a taxonomy instead of prose.
_CLAUSE_TO_REASON: dict[str, RejectionReason] = {
    "permission": RejectionReason.MITIGATED_BY_PLATFORM,
    "caller_check_absent": RejectionReason.NOT_REACHABLE,
    "sink_reachable": RejectionReason.NOT_REACHABLE,
    "data_is_sensitive": RejectionReason.NOT_SENSITIVE_DATA,
    "not_placeholder": RejectionReason.TEST_ONLY_VALUE,
    "not_encrypted_first": RejectionReason.MITIGATED_BY_PLATFORM,
    "path_not_canonicalised": RejectionReason.SANITISED,
    "no_validation_on_path": RejectionReason.SANITISED,
    "no_integrity_check": RejectionReason.MITIGATED_BY_PLATFORM,
    "content_attacker_influenceable": RejectionReason.NOT_REACHABLE,
    "used_in_security_context": RejectionReason.NOT_SENSITIVE_DATA,
    "used_for_security_purpose": RejectionReason.NOT_SENSITIVE_DATA,
}


class ValidationService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def validate(
        self,
        *,
        investigation_id: str,
        category: str,
        attributes: dict[str, object],
        title: str,
        description: str,
        evidence_refs: tuple[str, ...],
        discovered_by: str,
        validated_by: str,
        severity: Severity | None = None,
        component_ref: str | None = None,
        source_ref: SourceRef | None = None,
        model_id: str | None = None,
        rejection_reason: RejectionReason | None = None,
    ) -> tuple[Finding, VerdictRecord]:
        """Evaluate the gate for ``category`` and persist a finding plus its verdict."""
        if discovered_by == validated_by:
            raise ValidatorMustDiffer(
                "the validator must differ from the discoverer (ADR-010); "
                f"both are {discovered_by!r}"
            )
        if not evidence_refs:
            raise MissingEvidence(
                "a finding cannot be validated without evidence_refs: there would be "
                "nothing for the verdict to be about"
            )

        gate = gates.get_gate(category)
        result = gates.evaluate(category, attributes)

        if result.passed:
            verdict = Verdict.CONFIRMED
            status = FindingStatus.CONFIRMED
            reason = None
        elif result.missing_attributes:
            # We did not establish some clauses. That is not a refutation.
            verdict = Verdict.INSUFFICIENT_EVIDENCE
            status = FindingStatus.MANUAL_REVIEW_REQUIRED
            reason = None
        else:
            verdict = Verdict.REJECTED
            status = FindingStatus.REJECTED
            reason = rejection_reason or self._reason_for(result.failed)

        store = SqlEventStore(self._session)
        store.emit(
            investigation_id,
            "validation_started",
            {"category": category, "gate": list(gate.required_evidence())},
            actor=validated_by,
        )

        confidence = 1.0 if result.passed else 0.0
        if not result.passed and result.missing_attributes:
            # Partial establishment: report the fraction of clauses we actually settled.
            settled = len(gate.clauses) - len(result.missing_attributes)
            confidence = round(max(settled / len(gate.clauses), 0.0) * 0.5, 2)

        finding_domain = Finding(
            investigation_id=investigation_id,
            title=title,
            category=category,
            description=description,
            component_ref=component_ref,
            source_ref=source_ref,
            evidence_refs=evidence_refs,
            masvs=gate.masvs,
            maswe=gate.maswe,
            severity=severity or gate.severity_hint,
            confidence=confidence,
            status=status,
            discovered_by=discovered_by,
            validated_by=validated_by,
            gate_evidence=result.as_gate_evidence(),
        )

        now = utcnow()
        finding_row = FindingRow(
            id=finding_domain.id,
            investigation_id=investigation_id,
            title=title,
            category=category,
            description=description,
            component_ref=component_ref,
            source_ref=source_ref.model_dump(by_alias=True) if source_ref else None,
            evidence_refs=list(evidence_refs),
            masvs=list(gate.masvs),
            maswe=list(gate.maswe),
            mastg=[],
            severity=finding_domain.severity.value,
            severity_vector=None,
            confidence=confidence,
            status=status.value,
            discovered_by=discovered_by,
            validated_by=validated_by,
            gate_evidence=result.as_gate_evidence(),
            remediation=None,
            created_at=now,
            updated_at=now,
        )
        self._session.add(finding_row)
        self._session.flush()
        store.emit(
            investigation_id,
            "finding_created",
            {
                "finding_id": finding_domain.id,
                "title": title,
                "severity": finding_domain.severity.value,
                "confidence": confidence,
            },
            actor=discovered_by,
        )

        record = VerdictRecord(
            finding_id=finding_domain.id,
            verdict=verdict,
            rejection_reason=reason,
            rationale=self._rationale(gate, result),
            gate_passed=result.passed,
            gate_detail=result.as_gate_evidence(),
            validated_by=validated_by,
            model_id=model_id,
        )
        self._session.add(
            VerdictRow(
                id=record.id,
                finding_id=finding_domain.id,
                verdict=verdict.value,
                rejection_reason=reason.value if reason else None,
                rationale=record.rationale,
                gate_passed=result.passed,
                gate_detail=result.as_gate_evidence(),
                validated_by=validated_by,
                model_id=model_id,
                created_at=utcnow(),
            )
        )
        self._session.flush()

        event = {
            Verdict.CONFIRMED: "finding_confirmed",
            Verdict.REJECTED: "finding_rejected",
        }.get(verdict, "finding_validated")
        store.emit(
            investigation_id,
            event,
            {
                "finding_id": finding_domain.id,
                "verdict_id": record.id,
                "verdict": verdict.value,
                "rejection_reason": reason.value if reason else None,
            },
            actor=validated_by,
        )
        return finding_domain, record

    @staticmethod
    def _reason_for(failed: tuple[str, ...]) -> RejectionReason:
        for clause in failed:
            if clause in _CLAUSE_TO_REASON:
                return _CLAUSE_TO_REASON[clause]
        return RejectionReason.MISREAD_CODE

    @staticmethod
    def _rationale(gate: gates.Gate, result: gates.GateResult) -> str:
        if result.passed:
            return (
                f"All {len(gate.clauses)} gate clauses for '{gate.category}' were satisfied "
                f"({', '.join(gate.required_evidence())})."
            )
        if result.missing_attributes:
            return (
                f"Gate '{gate.category}' could not be decided: no evidence for "
                f"{', '.join(result.missing_attributes)}. Reported as insufficient evidence "
                "rather than rejected, because absence of proof is not proof of absence."
            )
        return (
            f"Gate '{gate.category}' refuted: failed clause(s) {', '.join(result.failed)}."
        )
