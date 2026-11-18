"""Persist bounded, integrity-verified JADX method excerpts as investigation evidence."""
from __future__ import annotations

import json
from typing import Any

from ..adapters.events import SqlEventStore
from ..core.enums import EvidenceKind
from .code_lookup import JadxCodeLookup
from .evidence import EvidenceService


AGENT = "JADX"


def capture_method_source(
    *,
    session,
    store,
    lookup: JadxCodeLookup,
    investigation_id: str,
    class_name: str,
    method_name: str,
    max_lines: int = 40,
) -> dict[str, Any]:
    """Capture one unambiguous method excerpt from the verified digest/version cache.

    The evidence payload is canonical JSON so its content hash binds the exact source text
    to the APK digest, JADX version, relative path, line range, fidelity and method identity.
    No decompilation is started here; lookup is cache-only and fails closed on a cache miss.
    """
    excerpt = lookup.method_excerpt(
        investigation_id,
        class_name=class_name,
        method_name=method_name,
        max_lines=max_lines,
    )
    payload = {
        "schema_version": 1,
        "apk_sha256": excerpt["apk_sha256"],
        "tool_version": excerpt["tool_version"],
        "class_name": class_name,
        "method_name": method_name,
        "method_reference": excerpt["method_reference"],
        "path": excerpt["path"],
        "start_line": excerpt["start_line"],
        "end_line": excerpt["end_line"],
        "fidelity": excerpt["fidelity"],
        "text": excerpt["text"],
    }
    content = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    summary = json.dumps(
        {
            "mobius_source_evidence_version": 1,
            "apk_sha256": payload["apk_sha256"],
            "tool_version": payload["tool_version"],
            "class_name": class_name,
            "method_name": method_name,
            "method_reference": payload["method_reference"],
            "path": payload["path"],
            "start_line": payload["start_line"],
            "end_line": payload["end_line"],
            "fidelity": payload["fidelity"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    evidence = EvidenceService(session, store).record(
        investigation_id=investigation_id,
        kind=EvidenceKind.SOURCE if payload["fidelity"] == "decompiled" else EvidenceKind.SMALI,
        content=content,
        summary=summary,
        produced_by=AGENT,
    )
    SqlEventStore(session).emit(
        investigation_id,
        "source_evidence_persisted",
        {
            "evidence_id": evidence.id,
            "sha256": evidence.sha256,
            "apk_sha256": payload["apk_sha256"],
            "tool_version": payload["tool_version"],
            "method_reference": payload["method_reference"],
            "path": payload["path"],
            "start_line": payload["start_line"],
            "end_line": payload["end_line"],
            "fidelity": payload["fidelity"],
        },
        actor=AGENT,
    )
    return {
        "investigation_id": investigation_id,
        "evidence_id": evidence.id,
        "sha256": evidence.sha256,
        "byte_size": evidence.byte_size,
        "kind": evidence.kind.value,
        "method_reference": payload["method_reference"],
        "path": payload["path"],
        "start_line": payload["start_line"],
        "end_line": payload["end_line"],
        "fidelity": payload["fidelity"],
    }
