"""Versioned, bounded wire format for provider-analysis results from isolated workers.

The worker runs the deterministic provider detector (core.providers) over the
staged APK inside a networkless OCI container and emits this payload. The API
validates it here before anything it claims touches a finding: strict schema,
per-field bounds, closed enum sets, and a SHA-256 binding to the authorized
artifact. The validation gate still decides every finding API-side; the worker
output is evidence transport, never a verdict.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..core.providers import (
    GuardFinding,
    OperationExposure,
    ProviderExposure,
    SinkFlowEvidence,
)
from .flow_adapt import DexBlobCoverage

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_PROVIDER_JSON_BYTES = 4 * 1024 * 1024

_ALLOWED_LEDGER_STATUS = {"parsed", "failed-parse", "skipped-oversized",
                         "skipped-aggregate", "duplicate-entry"}
_ALLOWED_PROTECTION = {"protected", "unprotected", "unknown"}
_ALLOWED_OPERATION = {"read", "write"}
# Verbatim from core.providers guard classification; a worker emitting anything
# else is schema-invalid, not "a new outcome".
_ALLOWED_GUARD_OUTCOME = {
    "enforcing", "ignored", "checked-not-dominating", "non-dominating",
    "polarity-inverted", "unknown-polarity", "helper-unresolved", "catch-unknown",
    "unmodelled-check",
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LedgerDTO(StrictModel):
    entry: str = Field(min_length=1, max_length=256)
    status: str
    size_bytes: int = Field(ge=0, le=64 * 1024 * 1024)
    methods: int = Field(default=0, ge=0, le=50000)
    duplicates: int = Field(default=0, ge=0, le=50000)
    ambiguous: bool = False
    error: str | None = Field(default=None, max_length=2000)


class GuardFindingDTO(StrictModel):
    api: str = Field(min_length=1, max_length=1000)
    outcome: str
    detail: str = Field(max_length=4000)


class SinkFlowDTO(StrictModel):
    method: str = Field(min_length=1, max_length=1000)
    sink: str = Field(min_length=1, max_length=1000)
    detail: str = Field(max_length=4000)


class OperationDTO(StrictModel):
    operation: str
    protection_status: str
    protection_permission: str | None = Field(default=None, max_length=1000)
    protection_basis: str = Field(max_length=4000)
    caller_check_absent: bool | None = None
    guard_findings: list[GuardFindingDTO] = Field(default_factory=list, max_length=64)
    coverage_complete: bool = False
    sink_flows: list[SinkFlowDTO] = Field(default_factory=list, max_length=256)
    flow_complete: bool = False


class ExposureDTO(StrictModel):
    provider: str = Field(min_length=1, max_length=1000)
    exported: bool
    grant_uri_permissions: bool = False
    uri_patterns: list[str] = Field(default_factory=list, max_length=512)
    numeric_uri_patterns: list[str] = Field(default_factory=list, max_length=512)
    operations: list[OperationDTO] = Field(default_factory=list, max_length=8)


class ProviderAnalysisDTO(StrictModel):
    schema_version: int = Field(ge=1, le=1)
    artifact_sha256: str
    package_name: str = Field(min_length=1, max_length=500)
    methods_adapted: int = Field(ge=0, le=50000)
    dex_coverage: list[LedgerDTO] = Field(min_length=1, max_length=64)
    exposures: list[ExposureDTO] = Field(default_factory=list, max_length=256)


@dataclass(frozen=True, slots=True)
class ProviderAnalysisResult:
    """Validated worker output, reconstructed into core dataclasses."""

    package_name: str
    methods_adapted: int
    ledger: tuple[DexBlobCoverage, ...]
    exposures: tuple[ProviderExposure, ...]

    @property
    def dex_complete(self) -> bool:
        """Recomputed API-side from the ledger alone; the worker's word is
        never taken for which DEX bytes were seen."""
        return dex_ledger_complete(self.ledger)


def dex_ledger_complete(ledger) -> bool:
    """The single coverage predicate shared by the API result DTO and the
    in-process service path. Any non-parsed or ambiguous entry downgrades
    coverage: an ambiguous duplicate class is treated exactly like a failed
    parse, never guessed complete (no false confirmation, no false refutation).
    """
    ledger = tuple(ledger)
    return bool(ledger) and all(b.status == "parsed" and not b.ambiguous for b in ledger)


def provider_analysis_payload(
    *,
    artifact_sha256: str,
    package_name: str,
    methods_adapted: int,
    ledger: list[DexBlobCoverage],
    exposures: list[ProviderExposure],
) -> dict[str, Any]:
    if not _SHA256.fullmatch(artifact_sha256):
        raise ValueError("artifact SHA-256 must be lowercase hexadecimal")
    return {
        "schema_version": 1,
        "artifact_sha256": artifact_sha256,
        "package_name": package_name,
        "methods_adapted": methods_adapted,
        "dex_coverage": [b.describe() for b in ledger],
        "exposures": [
            {
                "provider": e.provider,
                "exported": e.exported,
                "grant_uri_permissions": e.grant_uri_permissions,
                "uri_patterns": list(e.uri_patterns),
                "numeric_uri_patterns": list(e.numeric_uri_patterns),
                "operations": [
                    {
                        "operation": op.operation,
                        "protection_status": op.protection_status,
                        "protection_permission": op.protection_permission,
                        "protection_basis": op.protection_basis,
                        "caller_check_absent": op.caller_check_absent,
                        "guard_findings": [
                            {"api": g.api, "outcome": g.outcome, "detail": g.detail}
                            for g in op.guard_findings
                        ],
                        "coverage_complete": op.coverage_complete,
                        "sink_flows": [
                            {"method": s.method, "sink": s.sink, "detail": s.detail}
                            for s in op.sink_flows
                        ],
                        "flow_complete": op.flow_complete,
                    }
                    for op in e.operations
                ],
            }
            for e in exposures
        ],
    }


def validate_provider_analysis_payload(
    raw: bytes, expected_sha256: str
) -> ProviderAnalysisResult:
    if len(raw) > MAX_PROVIDER_JSON_BYTES:
        raise ValueError("provider analysis worker output exceeds the API size limit")
    try:
        decoded = json.loads(raw)
        dto = ProviderAnalysisDTO.model_validate(decoded)
    except (UnicodeDecodeError, ValueError, ValidationError) as exc:
        raise ValueError("provider analysis worker returned an invalid schema payload") from exc
    if not _SHA256.fullmatch(dto.artifact_sha256) or dto.artifact_sha256 != expected_sha256:
        raise ValueError("provider analysis result is not bound to the authorized APK SHA-256")

    ledger: list[DexBlobCoverage] = []
    for item in dto.dex_coverage:
        if item.status not in _ALLOWED_LEDGER_STATUS:
            raise ValueError("provider analysis payload has an unknown DEX coverage status")
        ledger.append(DexBlobCoverage(
            entry=item.entry, status=item.status, size_bytes=item.size_bytes,
            methods=item.methods, duplicates=item.duplicates,
            ambiguous=item.ambiguous, error=item.error,
        ))
    # A zip may legitimately carry the same classesN.dex name twice; every
    # repeat after the first must be marked duplicate-entry, nothing else.
    counted = [b.entry for b in ledger if b.status != "duplicate-entry"]
    if len(set(counted)) != len(counted):
        raise ValueError("duplicate DEX coverage entry in provider analysis payload")
    if any(b.status == "duplicate-entry" and b.entry not in counted for b in ledger):
        raise ValueError("duplicate-entry ledger row without a counted original")
    if sum(b.methods for b in ledger if b.status == "parsed") != dto.methods_adapted:
        raise ValueError("provider analysis methods-adapted count contradicts the DEX ledger")

    if len({e.provider for e in dto.exposures}) != len(dto.exposures):
        raise ValueError("duplicate provider entry in worker payload")
    exposures: list[ProviderExposure] = []
    for e in dto.exposures:
        if len({op.operation for op in e.operations}) != len(e.operations):
            raise ValueError("duplicate provider operation in worker payload")
        operations: list[OperationExposure] = []
        for op in e.operations:
            if op.operation not in _ALLOWED_OPERATION:
                raise ValueError("provider analysis payload has an unknown operation kind")
            if op.protection_status not in _ALLOWED_PROTECTION:
                raise ValueError("provider analysis payload has an unknown protection status")
            if op.protection_status == "unprotected" and op.protection_permission is not None:
                raise ValueError("unprotected operation carries a permission in worker payload")
            if op.protection_status == "protected" and op.protection_permission is None:
                raise ValueError("protected operation without a permission in worker payload")
            if op.caller_check_absent is True:
                # Absence may only be claimed on complete, uncontradicted
                # evidence; anything else is a cross-field inconsistency.
                if not (op.coverage_complete and op.flow_complete):
                    raise ValueError(
                        "caller_check_absent claimed with incomplete coverage/flow")
                if any(g.outcome == "enforcing" for g in op.guard_findings):
                    raise ValueError(
                        "caller_check_absent contradicted by an enforcing guard")
            for g in op.guard_findings:
                if g.outcome not in _ALLOWED_GUARD_OUTCOME:
                    raise ValueError("provider analysis payload has an unknown guard outcome")
            operations.append(OperationExposure(
                operation=op.operation,
                protection_status=op.protection_status,
                protection_permission=op.protection_permission,
                protection_basis=op.protection_basis,
                caller_check_absent=op.caller_check_absent,
                guard_findings=tuple(
                    GuardFinding(api=g.api, outcome=g.outcome, detail=g.detail)
                    for g in op.guard_findings
                ),
                coverage_complete=op.coverage_complete,
                sink_flows=tuple(
                    SinkFlowEvidence(method=s.method, sink=s.sink, detail=s.detail)
                    for s in op.sink_flows
                ),
                flow_complete=op.flow_complete,
            ))
        exposures.append(ProviderExposure(
            provider=e.provider,
            exported=e.exported,
            grant_uri_permissions=e.grant_uri_permissions,
            uri_patterns=tuple(e.uri_patterns),
            numeric_uri_patterns=tuple(e.numeric_uri_patterns),
            operations=tuple(operations),
        ))

    return ProviderAnalysisResult(
        package_name=dto.package_name,
        methods_adapted=dto.methods_adapted,
        ledger=tuple(ledger),
        exposures=tuple(exposures),
    )
