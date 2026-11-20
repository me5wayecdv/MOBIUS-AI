"""PROVIDER ANALYSIS: push static provider-exposure evidence through the gate.

This service runs the deterministic provider detector (core.providers) over the
APK a scan was created for and records the outcome the only way this platform
allows: one finding per exported provider operation, every attribute it claims
backed by an evidence document, every conclusion decided by the validation gate
- never by the detector itself.

What it establishes:

* Manifest protection facts from the verified protection model (core.manifest),
  consulted per operation and per discovered path instance. A representative
  path that is UNPROTECTED is evidence; an all-protected representative set is
  not proof other paths are protected (UNKNOWN), and a path set the model
  cannot resolve is UNKNOWN.
* Code evidence: caller-controlled flows into the provider's database sinks and
  guard-call classification (enforcing / ignored / checked-but-not-dominating /
  polarity-inverted / helper-unresolved / catch-unknown). Guards whose
  enforcement cannot be resolved keep the caller-check clause unknown.

What it does not do:

* It does not decide findings. Attributes in, gate evaluated, verdict out.
  UNPROTECTED protection plus an enforcing-check absence plus a reachable sink
  confirms; a PROTECTED path refutes; anything unresolved lands in
  INSUFFICIENT_EVIDENCE.
* It does not analyse non-exported providers into findings. They are counted in
  the run summary so a reviewer can see they were considered.
"""

from __future__ import annotations

import json
from dataclasses import replace

from sqlalchemy.orm import Session

from ..adapters.android_manifest import parse_apk
from ..adapters.events import SqlEventStore
from ..adapters.flow_adapt import adapt_code
from ..adapters.provider_payload import ProviderAnalysisResult, dex_ledger_complete
from ..adapters.models import ApplicationRow, AuthorizationRow, InvestigationRow
from ..core.enums import EvidenceKind
from ..core.flow import flow_scan_from_androguard
from ..core.providers import ProviderExposure, detect_provider_exposures
from ..core.reachability import MethodRef
from .artifacts import ArtifactStore
from .errors import AuthorizationRequired, NotFound
from .evidence import EvidenceService
from .intake import is_expired
from .validation import ValidationService

AGENT = "SPECTRE"
CATEGORY = "exported-provider-unprotected-sink"
def _gate_attributes(exposure: ProviderExposure, operation) -> dict[str, object]:
    """Map detector evidence onto the exported-component-no-permission clauses.

    None is never written: unknown stays missing, so the gate can distinguish
    "no evidence was offered" from "the evidence contradicts the clause".
    """
    attributes: dict[str, object] = {"exported": exposure.exported}
    if operation.protection_status == "unprotected":
        attributes["permission"] = None
    elif operation.protection_status == "protected":
        attributes["permission"] = operation.protection_permission
    # "unknown" protection leaves the permission clause without evidence.
    if operation.caller_check_absent is not None:
        attributes["caller_check_absent"] = operation.caller_check_absent
    if operation.sink_flows:
        attributes["sink_reachable"] = True
    return attributes


class ProviderAnalysisService:
    def __init__(self, session: Session, store: ArtifactStore) -> None:
        self._session = session
        self._store = store
        self._evidence = EvidenceService(session, store)

    def _authorized_application(self, investigation_id: str):
        """Every check that binds this analysis to the authorized artifact.

        Applies to the inline path and to worker-produced payloads alike: the
        payload's digest binding is validated by the route before this is
        called, and the package check below is repeated against whichever
        package name the analysis itself produced."""
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

    def run(self, investigation_id: str, *, validated_by: str) -> dict[str, object]:
        """In-process path: local development only (gated at the route)."""
        application, authorization = self._authorized_application(investigation_id)
        apk_bytes = self._store.get(application.artifact_key)
        surface = parse_apk(apk_bytes)
        if authorization.target_package != surface.package_name:
            raise AuthorizationRequired(
                "authorized target package does not match the package parsed from this APK"
            )

        methods, registers_sizes, superclasses, try_regions, ledger = adapt_code(
            apk_bytes, app_package=surface.package_name
        )
        # The same predicate as the API result DTO (shared helper): an
        # ambiguous duplicate class downgrades coverage exactly like a failed
        # parse, in both directions (no false confirmation, no false refutation).
        dex_complete = dex_ledger_complete(ledger)
        exposures = detect_provider_exposures(
            surface, methods, registers_sizes, superclasses, try_regions
        )
        return self._finish(
            investigation_id,
            package_name=surface.package_name,
            methods_adapted=len(methods),
            ledger=ledger,
            exposures=list(exposures),
            dex_complete=dex_complete,
            validated_by=validated_by,
        )

    def run_from_payload(
        self, investigation_id: str, result: ProviderAnalysisResult, *, validated_by: str,
        applied_job_id: str | None = None,
    ) -> dict[str, object]:
        """Apply a validated isolated-worker payload: same authorization gates,
        same downgrade rules, same gate. The API never parses the APK here."""
        _, authorization = self._authorized_application(investigation_id)
        if authorization.target_package != result.package_name:
            raise AuthorizationRequired(
                "authorized target package does not match the package in the worker result"
            )
        return self._finish(
            investigation_id,
            package_name=result.package_name,
            methods_adapted=result.methods_adapted,
            ledger=list(result.ledger),
            exposures=list(result.exposures),
            dex_complete=result.dex_complete,
            validated_by=validated_by,
            exclude_applied_job_id=applied_job_id,
        )

    def _already_applied_job(self, investigation_id: str, exclude_job_id: str | None):
        from ..adapters.models import WorkerJobRow
        from sqlalchemy import select as _select
        stmt = _select(WorkerJobRow).where(
            WorkerJobRow.investigation_id == investigation_id,
            WorkerJobRow.kind == "provider_analysis",
            WorkerJobRow.applied_at.is_not(None),
        )
        if exclude_job_id is not None:
            stmt = stmt.where(WorkerJobRow.id != exclude_job_id)
        return self._session.execute(stmt.limit(1)).scalar_one_or_none()

    def _finish(
        self,
        investigation_id: str,
        *,
        package_name: str,
        methods_adapted: int,
        ledger,
        exposures,
        dex_complete: bool,
        validated_by: str,
        exclude_applied_job_id: str | None = None,
    ) -> dict[str, object]:
        # Lifecycle state gate: a second application (inline repeat or a fresh
        # worker job after one was already applied) would duplicate findings
        # and evidence. The current job, already claimed by claim_apply, is
        # excluded from its own gate.
        other = self._already_applied_job(investigation_id, exclude_applied_job_id)
        if other is not None:
            from .errors import ScanStateConflict
            raise ScanStateConflict(
                f"provider analysis was already applied for this investigation "
                f"(worker job {other.id})"
            )
        if not dex_complete:
            # A DEX that could not be selected or parsed is code we never saw.
            # The runtime resolves a class from the FIRST dex, so the analysed
            # copy may be one the device never loads: on partial bytecode no
            # caller-check claim stands in EITHER direction. True would be a
            # false confirm; False would be a false refutation (an "enforcing"
            # guard found in a shadowed later copy). Both become UNKNOWN.
            exposures = [
                replace(
                    exposure,
                    operations=tuple(
                        replace(op, caller_check_absent=None)
                        if op.caller_check_absent is not None else op
                        for op in exposure.operations
                    ),
                )
                for exposure in exposures
            ]

        validator = ValidationService(self._session)
        results = []
        considered_not_exported = []
        for exposure in exposures:
            if not exposure.exported:
                considered_not_exported.append(exposure.provider)
                continue
            for operation in exposure.operations:
                document = {
                    "provider": exposure.provider,
                    "dex_coverage": [b.describe() for b in ledger],
                    "grant_uri_permissions": exposure.grant_uri_permissions,
                    "uri_patterns": list(exposure.uri_patterns),
                    "numeric_uri_patterns": list(exposure.numeric_uri_patterns),
                    "operation": operation.operation,
                    "protection_status": operation.protection_status,
                    "protection_permission": operation.protection_permission,
                    "protection_basis": operation.protection_basis,
                    "caller_check_absent": operation.caller_check_absent,
                    "coverage_complete": operation.coverage_complete,
                    "flow_complete": operation.flow_complete,
                    "guard_findings": [
                        {"api": g.api, "outcome": g.outcome, "detail": g.detail}
                        for g in operation.guard_findings
                    ],
                    "sink_flows": [
                        {"method": s.method, "sink": s.sink, "detail": s.detail}
                        for s in operation.sink_flows
                    ],
                }
                evidence = self._evidence.record(
                    investigation_id=investigation_id,
                    kind=EvidenceKind.TOOL_OUTPUT,
                    content=json.dumps(document, indent=2).encode(),
                    summary=(
                        f"provider-analysis: {exposure.provider} {operation.operation} - "
                        f"protection {operation.protection_status}, "
                        f"caller_check_absent {operation.caller_check_absent}"
                    ),
                    produced_by=AGENT,
                )
                attributes = _gate_attributes(exposure, operation)
                finding, verdict = validator.validate(
                    investigation_id=investigation_id,
                    category=CATEGORY,
                    attributes=attributes,
                    title=(
                        f"Exported provider {exposure.provider} {operation.operation} "
                        "operation"
                    ),
                    description=(
                        f"{operation.protection_basis}; caller-check absent: "
                        f"{operation.caller_check_absent}; sink flows: "
                        f"{len(operation.sink_flows)}; coverage complete: "
                        f"{operation.coverage_complete}; flow complete: "
                        f"{operation.flow_complete}."
                    ),
                    evidence_refs=(evidence.id,),
                    discovered_by=AGENT,
                    validated_by=validated_by,
                    component_ref=exposure.provider,
                )
                results.append(
                    {
                        "provider": exposure.provider,
                        "operation": operation.operation,
                        "attributes": attributes,
                        "finding_id": finding.id,
                        "finding_status": finding.status.value,
                        "verdict": verdict.verdict.value,
                        "evidence_id": evidence.id,
                    }
                )

        SqlEventStore(self._session).emit(
            investigation_id,
            "provider_analysis_completed",
            {
                "providers": [e.provider for e in exposures],
                "methods_adapted": methods_adapted,
                "dex_coverage": [b.describe() for b in ledger],
                "findings": [
                    {"provider": r["provider"], "operation": r["operation"],
                     "verdict": r["verdict"]}
                    for r in results
                ],
                "considered_not_exported": considered_not_exported,
            },
            actor=AGENT,
        )
        self._session.flush()
        return {
            "package_name": package_name,
            "methods_adapted": methods_adapted,
            "dex_complete": dex_complete,
            "dex_coverage": [b.describe() for b in ledger],
            "providers": len(exposures),
            "considered_not_exported": considered_not_exported,
            "results": results,
        }
