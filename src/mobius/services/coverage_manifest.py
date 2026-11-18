"""Build a truthful, persisted-evidence-backed APK code coverage manifest (D-016)."""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from io import BytesIO
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.models import (
    ApplicationRow,
    EvidenceRow,
    InvestigationRow,
    ObservationRow,
    WorkerJobRow,
)
from ..core.enums import EvidenceKind
from .artifacts import ArtifactStore
from .errors import NotFound

_DEX_ENTRY = re.compile(r"^classes\d*\.dex$")
_MAX_INVENTORY_ENTRIES = 20_000
_SAMPLE_LIMIT = 50
_JADX_SAMPLE_LIMIT = 20


class CoverageManifestBuilder:
    """Describe what was inventoried, indexed, truncated, or never analyzed."""

    def __init__(self, session: Session, store: ArtifactStore) -> None:
        self.session = session
        self.store = store

    def build(self, investigation_id: str) -> dict[str, Any]:
        investigation = self.session.get(InvestigationRow, investigation_id)
        if investigation is None:
            raise NotFound(f"investigation {investigation_id} not found")
        application = self.session.get(ApplicationRow, investigation.application_id)
        if application is None:
            raise NotFound(f"application {investigation.application_id} not found")

        inventory = self._apk_inventory(application)
        dex_row, dex_payload = self._dex_index_evidence(investigation_id)
        dex_analysis = self._dex_analysis(inventory, dex_row, dex_payload)
        recon = self._recon_coverage(investigation_id)
        jadx = self._jadx_coverage(investigation_id, application.sha256)
        reachability = self._reachability_coverage(investigation_id)

        truncated = bool(
            inventory.get("truncated")
            or dex_analysis.get("truncated")
            or inventory.get("dex_entries_truncated")
            or reachability.get("truncated_observations", 0)
            or jadx.get("source_files_truncated")
        )
        if any(
            item.get("status") in {"failed", "skipped", "truncated", "not_indexed"}
            for item in dex_analysis.get("entries", [])
        ):
            truncated = True

        limitations = [
            {
                "capability": "reflection",
                "status": "unsupported",
                "detail": "Reflective method/class resolution is not modeled; reflective edges may be missed.",
            },
            {
                "capability": "dynamic_loading",
                "status": "unsupported",
                "detail": "Code loaded at runtime (DexClassLoader, downloaded DEX/JAR, native loaders) is not enumerated.",
            },
            {
                "capability": "native_code",
                "status": "inventory_only",
                "detail": "lib/*.so entries are listed; native disassembly, symbol analysis and native data flow are not performed.",
            },
            {
                "capability": "assets_and_resources",
                "status": "inventory_only",
                "detail": "Asset/resource names are inventoried; embedded code, scripts and configuration semantics are not analyzed.",
            },
            {
                "capability": "obfuscation",
                "status": "not_deobfuscated",
                "detail": "No deobfuscation or name recovery is performed; identifiers retain the names exposed by DEX/JADX.",
            },
            {
                "capability": "control_flow",
                "status": "not_implemented",
                "detail": "Path-sensitive CFG reasoning and guard-order/effectiveness proof are not part of this main baseline.",
            },
            {
                "capability": "data_flow",
                "status": "not_implemented",
                "detail": "No taint propagation proves that attacker-controlled data reaches a sensitive sink.",
            },
            {
                "capability": "framework_calls",
                "status": "boundary_only",
                "detail": "Framework calls are recorded as boundary calls and are not traversed into framework implementation code.",
            },
            {
                "capability": "truncation",
                "status": "reported_per_entry",
                "detail": "DEX entry failures/skips/budget truncation and incomplete reachability are exposed below; omitted work is not evidence of absence.",
            },
        ]
        return {
            "schema_version": 1,
            "investigation_id": investigation_id,
            "overall_status": "partial",
            "truncated": truncated,
            "artifact": {
                "application_id": application.id,
                "apk_sha256": application.sha256,
                "package_name": application.package_name,
                "version_name": application.version_name,
                "version_code": application.version_code,
                "file_size_bytes": application.file_size,
            },
            "apk_inventory": inventory,
            "recon": recon,
            "dex_analysis": dex_analysis,
            "jadx": jadx,
            "reachability": reachability,
            "limitations": limitations,
            "interpretation": (
                "Coverage describes only the recorded inventory and analysis. "
                "A missing entry, failed parse, unsupported capability, or truncated search "
                "must not be interpreted as safe or absent."
            ),
        }

    def _apk_inventory(self, application: ApplicationRow) -> dict[str, Any]:
        try:
            raw = self.store.get(application.artifact_key)
        except (OSError, ValueError):
            return {"status": "unavailable", "error_code": "APK_ARTIFACT_UNREADABLE"}
        if hashlib.sha256(raw).hexdigest() != application.sha256:
            return {"status": "integrity_failed", "error_code": "APK_SHA256_MISMATCH"}

        try:
            with zipfile.ZipFile(BytesIO(raw)) as archive:
                all_infos = archive.infolist()
                infos = all_infos[:_MAX_INVENTORY_ENTRIES]
                dex_infos = [item for item in infos if _DEX_ENTRY.fullmatch(item.filename)]
                native_infos = [
                    item for item in infos
                    if item.filename.startswith("lib/") and item.filename.endswith(".so")
                ]
                asset_infos = [item for item in infos if item.filename.startswith("assets/")]
                resource_infos = [item for item in infos if item.filename.startswith("res/")]
                truncated = len(all_infos) > _MAX_INVENTORY_ENTRIES
                return {
                    "status": "partial" if truncated else "complete",
                    "archive_entry_count": len(all_infos),
                    "processed_entry_count": len(infos),
                    "truncated": truncated,
                    "dex_entries": [
                        {"entry": item.filename, "size_bytes": item.file_size}
                        for item in dex_infos[:64]
                    ],
                    "dex_entries_truncated": len(dex_infos) > 64,
                    "native_libraries": {
                        "count": len(native_infos),
                        "sample": [item.filename for item in native_infos[:_SAMPLE_LIMIT]],
                        "sample_truncated": len(native_infos) > _SAMPLE_LIMIT,
                        "analysis": "inventory_only",
                    },
                    "assets": {
                        "count": len(asset_infos),
                        "sample": [item.filename for item in asset_infos[:_SAMPLE_LIMIT]],
                        "sample_truncated": len(asset_infos) > _SAMPLE_LIMIT,
                        "analysis": "inventory_only",
                    },
                    "resources": {
                        "count": len(resource_infos),
                        "sample": [item.filename for item in resource_infos[:_SAMPLE_LIMIT]],
                        "sample_truncated": len(resource_infos) > _SAMPLE_LIMIT,
                        "analysis": "inventory_only",
                    },
                }
        except (OSError, RuntimeError, zipfile.BadZipFile):
            return {"status": "invalid_archive", "error_code": "APK_ZIP_INVALID"}

    def _dex_index_evidence(
        self, investigation_id: str
    ) -> tuple[EvidenceRow | None, dict[str, Any] | None]:
        rows = self.session.execute(
            select(EvidenceRow)
            .where(
                EvidenceRow.investigation_id == investigation_id,
                EvidenceRow.kind == EvidenceKind.DEX_STRING.value,
            )
            .order_by(EvidenceRow.created_at.desc(), EvidenceRow.id.desc())
        ).scalars()
        for row in rows:
            try:
                raw = self.store.get(row.object_key)
                if hashlib.sha256(raw).hexdigest() != row.sha256:
                    continue
                payload = json.loads(raw.decode("utf-8"))
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict) and isinstance(payload.get("dex_coverage"), list):
                return row, payload
        return None, None

    @staticmethod
    def _dex_analysis(
        inventory: dict[str, Any],
        evidence: EvidenceRow | None,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if payload is None or evidence is None:
            return {
                "status": "not_run",
                "complete": False,
                "truncated": False,
                "entries": [
                    {**item, "status": "not_indexed"}
                    for item in inventory.get("dex_entries", [])
                ],
                "evidence": None,
            }
        coverage = {
            str(item.get("entry")): item
            for item in payload.get("dex_coverage", [])
            if isinstance(item, dict) and isinstance(item.get("entry"), str)
        }
        entries = []
        for item in inventory.get("dex_entries", []):
            entry = item["entry"]
            result = coverage.get(entry)
            entries.append({
                **item,
                "status": str(result.get("status")) if result else "not_indexed",
                "classes": int(result.get("classes", 0)) if result else 0,
                "methods": int(result.get("methods", 0)) if result else 0,
                "error": str(result.get("error"))[:500] if result and result.get("error") else None,
            })
        inventory_names = {item["entry"] for item in inventory.get("dex_entries", [])}
        unexpected = sorted(set(coverage) - inventory_names)
        failed = sum(item["status"] == "failed" for item in entries)
        skipped = sum(item["status"] == "skipped" for item in entries)
        entry_truncated = sum(item["status"] == "truncated" for item in entries)
        truncated = bool(payload.get("truncated")) or entry_truncated > 0
        complete = (
            bool(payload.get("complete"))
            and inventory.get("status") == "complete"
            and not unexpected
            and len(entries) == len(coverage)
        )
        return {
            "status": "complete" if complete else "partial",
            "complete": complete,
            "truncated": truncated,
            "classes": int(payload.get("classes", 0)),
            "methods": int(payload.get("methods", 0)),
            "graph_nodes": int(payload.get("graph_nodes", 0)),
            "internal_calls": int(payload.get("internal_calls", 0)),
            "dex_entry_count": len(coverage),
            "indexed_entries": sum(item.get("status") == "indexed" for item in coverage.values()),
            "failed_entries": failed,
            "skipped_entries": skipped,
            "truncated_entries": entry_truncated,
            "entries": entries,
            "index_entries_not_in_archive": unexpected,
            "evidence": {"id": evidence.id, "sha256": evidence.sha256},
        }

    def _recon_coverage(self, investigation_id: str) -> dict[str, Any]:
        manifest_rows = list(self.session.execute(
            select(EvidenceRow).where(
                EvidenceRow.investigation_id == investigation_id,
                EvidenceRow.kind == EvidenceKind.MANIFEST.value,
            )
        ).scalars())
        recon_observations = list(self.session.execute(
            select(ObservationRow).where(
                ObservationRow.investigation_id == investigation_id,
                ObservationRow.agent == "RECON",
            )
        ).scalars())
        return {
            "status": "recorded" if manifest_rows else "not_recorded",
            "manifest_evidence_count": len(manifest_rows),
            "recon_observation_count": len(recon_observations),
            "evidence": [
                {"id": row.id, "sha256": row.sha256}
                for row in manifest_rows[:_SAMPLE_LIMIT]
            ],
            "evidence_truncated": len(manifest_rows) > _SAMPLE_LIMIT,
        }

    def _jadx_coverage(self, investigation_id: str, expected_sha256: str) -> dict[str, Any]:
        job = self.session.execute(
            select(WorkerJobRow)
            .where(
                WorkerJobRow.investigation_id == investigation_id,
                WorkerJobRow.kind == "jadx_decompile",
            )
            .order_by(WorkerJobRow.created_at.desc(), WorkerJobRow.id.desc())
            .limit(1)
        ).scalar_one_or_none()
        if job is None:
            return {"status": "not_requested", "source_file_count": 0, "source_files_sample": []}
        result = job.result_json if isinstance(job.result_json, dict) else {}
        if job.status == "succeeded" and result.get("apk_sha256") != expected_sha256:
            return {
                "status": "result_digest_mismatch",
                "job_id": job.id,
                "source_file_count": None,
                "source_files_sample": [],
            }
        source_files = result.get("source_files") if isinstance(result.get("source_files"), list) else []
        source_count = result.get("source_file_count")
        if not isinstance(source_count, int) or source_count < 0:
            source_count = len(source_files)
        sample = [str(item)[:1000] for item in source_files[:_JADX_SAMPLE_LIMIT]]
        return {
            "status": job.status,
            "job_id": job.id,
            "attempts": job.attempts,
            "error_code": job.error_code,
            "tool_version": result.get("tool_version"),
            "fidelity": result.get("fidelity"),
            "source_file_count": source_count,
            "source_files_sample": sample,
            "source_files_truncated": source_count > len(sample),
        }

    def _reachability_coverage(self, investigation_id: str) -> dict[str, Any]:
        rows = list(self.session.execute(
            select(ObservationRow).where(
                ObservationRow.investigation_id == investigation_id,
                ObservationRow.agent == "SPECTRE",
            )
        ).scalars())
        truncated = sum(
            bool((row.attributes or {}).get("index_truncated"))
            or (row.attributes or {}).get("reachability") == "truncated"
            for row in rows
        )
        return {
            "observation_count": len(rows),
            "truncated_observations": truncated,
            "truncated": truncated > 0,
        }
