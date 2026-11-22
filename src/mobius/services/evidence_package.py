"""Build bounded, provenance-preserving evidence packages for targeted reasoning.

Source excerpts enter only through immutable evidence captured from the verified,
APK-digest/JADX-version cache. Packages revalidate their stored content hash and retain
the source evidence ID and locator.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.models import (
    ApplicationRow,
    EvidenceRow,
    FindingRow,
    InvestigationRow,
    ObservationRow,
)
from .artifacts import ArtifactStore
from .errors import NotFound


@dataclass(frozen=True, slots=True)
class EvidencePackage:
    investigation_id: str
    component: str | None
    observations: tuple[dict[str, Any], ...]
    findings: tuple[dict[str, Any], ...]
    evidence: tuple[dict[str, Any], ...]
    method_references: tuple[str, ...]
    sink_references: tuple[str, ...]
    guard_references: tuple[str, ...]
    source_snippets: tuple[dict[str, Any], ...]
    limitations: tuple[str, ...]
    truncated: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "component": self.component,
            "observations": list(self.observations),
            "findings": list(self.findings),
            "evidence": list(self.evidence),
            "method_references": list(self.method_references),
            "sink_references": list(self.sink_references),
            "guard_references": list(self.guard_references),
            "source_snippets": list(self.source_snippets),
            "limitations": list(self.limitations),
            "truncated": self.truncated,
            "provenance": "persisted MOBIUS rows only",
        }


class EvidencePackageBuilder:
    """Collect only persisted, investigation-scoped context under explicit budgets."""

    def __init__(
        self,
        session: Session,
        *,
        max_observations: int = 40,
        max_findings: int = 30,
        max_evidence: int = 40,
        max_text_chars: int = 48_000,
        max_methods: int = 500,
        store: ArtifactStore | None = None,
        max_source_snippets: int = 20,
        max_source_chars: int = 24_000,
    ) -> None:
        limits = (
            max_observations, max_findings, max_evidence, max_text_chars,
            max_methods, max_source_snippets, max_source_chars,
        )
        if min(limits) < 1:
            raise ValueError("evidence package limits must be positive")
        self.session = session
        self.max_observations = max_observations
        self.max_findings = max_findings
        self.max_evidence = max_evidence
        self.max_text_chars = max_text_chars
        self.max_methods = max_methods
        self.store = store
        self.max_source_snippets = max_source_snippets
        self.max_source_chars = max_source_chars

    def build(self, investigation_id: str, *, component: str | None = None) -> EvidencePackage:
        investigation = self.session.get(InvestigationRow, investigation_id)
        if investigation is None:
            raise NotFound(f"investigation {investigation_id} not found")

        obs_stmt = (
            select(ObservationRow)
            .where(ObservationRow.investigation_id == investigation_id)
            .order_by(ObservationRow.created_at.asc(), ObservationRow.id.asc())
        )
        finding_stmt = (
            select(FindingRow)
            .where(FindingRow.investigation_id == investigation_id)
            .order_by(FindingRow.created_at.asc(), FindingRow.id.asc())
        )
        if component:
            obs_stmt = obs_stmt.where(ObservationRow.subject_ref == component)
            finding_stmt = finding_stmt.where(FindingRow.component_ref == component)

        all_obs = list(self.session.execute(obs_stmt).scalars())
        all_findings = list(self.session.execute(finding_stmt).scalars())
        truncated = len(all_obs) > self.max_observations or len(all_findings) > self.max_findings
        obs_rows = all_obs[: self.max_observations]
        finding_rows = all_findings[: self.max_findings]

        # Source evidence is separately persisted from the verified JADX cache. Its
        # compact summary carries the component/method locator; content is re-hashed
        # before any excerpt is admitted to the package.
        all_source_rows = list(self.session.execute(
            select(EvidenceRow)
            .where(
                EvidenceRow.investigation_id == investigation_id,
                EvidenceRow.kind.in_(("source", "smali")),
            )
            .order_by(EvidenceRow.created_at.asc(), EvidenceRow.id.asc())
        ).scalars())
        application = self.session.get(ApplicationRow, investigation.application_id)
        expected_apk_sha256 = application.sha256 if application is not None else None
        source_rows: list[tuple[EvidenceRow, dict[str, Any]]] = []
        invalid_source_metadata = False
        for source_row in all_source_rows:
            try:
                metadata = json.loads(source_row.summary)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(metadata, dict) or metadata.get("mobius_source_evidence_version") != 1:
                continue
            if metadata.get("apk_sha256") != expected_apk_sha256:
                invalid_source_metadata = True
                continue
            if component and metadata.get("component") != component:
                continue
            source_rows.append((source_row, metadata))
        eligible_source_count = len(source_rows)
        if eligible_source_count > self.max_source_snippets:
            truncated = True
        source_rows = source_rows[: self.max_source_snippets]

        evidence_ids: set[str] = {row.id for row, _ in source_rows}
        methods: set[str] = set()
        sinks: set[str] = set()
        guards: set[str] = set()
        observations: list[dict[str, Any]] = []
        for row in obs_rows:
            refs = [str(ref) for ref in (row.evidence_refs or [])]
            evidence_ids.update(refs)
            attrs = row.attributes or {}
            path = [str(item)[:1000] for item in attrs.get("path", []) if isinstance(item, str)]
            methods.update(path)
            # Provider flow locations are an unordered set, not a caller chain.
            explicit_methods = [str(item)[:1000] for item in attrs.get('method_references', []) if isinstance(item,str)][:self.max_methods]
            explicit_sinks = [str(item)[:1000] for item in attrs.get('sink_references', []) if isinstance(item,str)][:100]
            methods.update(explicit_methods); sinks.update(explicit_sinks)
            sink = attrs.get("sink")
            if isinstance(sink, str) and sink:
                sinks.add(sink[:1000])
            guards.update(str(item)[:1000] for item in attrs.get("guards", []) if isinstance(item, str))
            observations.append({
                "id": row.id,
                "agent": row.agent,
                "kind": row.kind,
                "fidelity": row.fidelity,
                "subject_type": row.subject_type,
                "subject_ref": row.subject_ref,
                "statement": row.statement[:4000],
                "attributes": {
                    "reachability": attrs.get("reachability"),
                    "path": path[: self.max_methods],
                    "method_references": explicit_methods,
                    "sink_references": explicit_sinks,
                    "sink": sink,
                    "guards": list(attrs.get("guards", []))[:100],
                    "index_truncated": bool(attrs.get("index_truncated", False)),
                    "exhaustive": attrs.get("exhaustive"),
                },
                "maswe": list(row.maswe or []),
                "confidence": row.confidence,
                "evidence_refs": refs,
            })

        findings: list[dict[str, Any]] = []
        for row in finding_rows:
            refs = [str(ref) for ref in (row.evidence_refs or [])]
            evidence_ids.update(refs)
            if isinstance(row.source_ref, dict):
                for value in row.source_ref.values():
                    if isinstance(value, str) and ("." in value or "->" in value):
                        methods.add(value[:1000])
            findings.append({
                "id": row.id,
                "title": row.title[:1000],
                "category": row.category,
                "description": row.description[:4000],
                "component_ref": row.component_ref,
                "source_ref": row.source_ref,
                "status": row.status,
                "severity": row.severity,
                "confidence": row.confidence,
                "maswe": list(row.maswe or []),
                "masvs": list(row.masvs or []),
                "evidence_refs": refs,
                "gate_evidence": row.gate_evidence or {},
            })

        all_evidence = list(self.session.execute(
            select(EvidenceRow)
            .where(
                EvidenceRow.investigation_id == investigation_id,
                EvidenceRow.id.in_(evidence_ids) if evidence_ids else EvidenceRow.id == "__none__",
            )
            .order_by(EvidenceRow.created_at.asc(), EvidenceRow.id.asc())
        ).scalars())
        source_evidence_ids = {row.id for row, _ in source_rows}
        all_evidence.sort(
            key=lambda row: (
                row.id not in source_evidence_ids,
                row.created_at,
                row.id,
            )
        )
        if len(all_evidence) > self.max_evidence:
            truncated = True
        evidence_rows = all_evidence[: self.max_evidence]
        remaining_chars = self.max_text_chars
        evidence: list[dict[str, Any]] = []
        for row in evidence_rows:
            summary = row.summary[: min(2000, remaining_chars)]
            remaining_chars -= len(summary)
            evidence.append({
                "id": row.id,
                "kind": row.kind,
                "sha256": row.sha256,
                "byte_size": row.byte_size,
                "truncated": row.truncated,
                "redacted": row.redacted,
                "summary": summary,
                "produced_by": row.produced_by,
                "created_at": row.created_at,
            })
        if remaining_chars <= 0:
            truncated = True

        source_snippets: list[dict[str, Any]] = []
        remaining_source_chars = self.max_source_chars
        source_integrity_limited = invalid_source_metadata
        if source_rows and self.store is None:
            source_integrity_limited = True
        elif self.store is not None:
            for source_row, metadata in source_rows:
                try:
                    raw = self.store.get(source_row.object_key)
                    if hashlib.sha256(raw).hexdigest() != source_row.sha256:
                        source_integrity_limited = True
                        continue
                    payload = json.loads(raw.decode("utf-8"))
                    if (
                        not isinstance(payload, dict)
                        or payload.get("schema_version") != 1
                        or payload.get("apk_sha256") != metadata.get("apk_sha256")
                        or payload.get("tool_version") != metadata.get("tool_version")
                        or payload.get("path") != metadata.get("path")
                        or payload.get("class_name") != metadata.get("class_name")
                        or payload.get("component") != metadata.get("component")
                        or payload.get("method_name") != metadata.get("method_name")
                        or payload.get("method_reference") != metadata.get("method_reference")
                        or payload.get("start_line") != metadata.get("start_line")
                        or payload.get("end_line") != metadata.get("end_line")
                        or payload.get("fidelity") != metadata.get("fidelity")
                        or not isinstance(payload.get("text"), str)
                    ):
                        source_integrity_limited = True
                        continue
                    text_value = payload["text"]
                    if remaining_source_chars <= 0:
                        truncated = True
                        break
                    included_text = text_value[:remaining_source_chars]
                    if len(included_text) < len(text_value):
                        truncated = True
                    remaining_source_chars -= len(included_text)
                    source_snippets.append({
                        "evidence_id": source_row.id,
                        "sha256": source_row.sha256,
                        "apk_sha256": metadata.get("apk_sha256"),
                        "tool_version": metadata.get("tool_version"),
                        "class_name": metadata.get("class_name"),
                        "method_name": metadata.get("method_name"),
                        "method_reference": metadata.get("method_reference"),
                        "path": metadata.get("path"),
                        "start_line": metadata.get("start_line"),
                        "end_line": metadata.get("end_line"),
                        "fidelity": metadata.get("fidelity"),
                        "text": included_text,
                        "truncated": len(included_text) < len(text_value),
                    })
                except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
                    source_integrity_limited = True

        limitations = [
            "Method references are bytecode-derived identifiers; reachability does not prove tainted data flow or exploitability.",
        ]
        if not source_snippets:
            limitations.insert(0, "No persisted verified JADX source excerpts were selected for this package.")
        if source_integrity_limited:
            limitations.append("One or more persisted source evidence records could not be integrity-verified or read.")
        if eligible_source_count > len(source_rows):
            limitations.append("Source evidence selection was capped; omitted excerpts are not evidence of absence.")
        if any(bool((row.attributes or {}).get("index_truncated")) for row in obs_rows):
            limitations.append("At least one selected observation came from a truncated DEX index.")
        if truncated:
            limitations.append("Package limits were reached; omitted rows are not evidence of absence.")

        return EvidencePackage(
            investigation_id=investigation_id,
            component=component,
            observations=tuple(observations),
            findings=tuple(findings),
            evidence=tuple(evidence),
            method_references=tuple(sorted(methods)[: self.max_methods]),
            sink_references=tuple(sorted(sinks)),
            guard_references=tuple(sorted(guards)),
            source_snippets=tuple(source_snippets),
            limitations=tuple(limitations),
            truncated=truncated,
        )
