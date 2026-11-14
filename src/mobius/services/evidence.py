"""Evidence storage.

Evidence is content-addressed and immutable. Corrections are new evidence, never edits:
an evidence chain that can be edited is not an evidence chain (ADR-009).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.events import SqlEventStore, utcnow
from ..adapters.models import EvidenceRow
from ..core.enums import EvidenceKind
from ..core.schemas import Evidence
from .artifacts import ArtifactStore


class EvidenceService:
    def __init__(self, session: Session, store: ArtifactStore) -> None:
        self._session = session
        self._store = store

    def record(
        self,
        *,
        investigation_id: str,
        kind: EvidenceKind,
        content: bytes,
        summary: str,
        produced_by: str,
        truncated: bool = False,
    ) -> Evidence:
        """Store bytes and return evidence metadata. Idempotent on identical content.

        Deduplication is by (investigation, sha256) so the same manifest extracted twice
        does not create two evidence rows - but the same bytes in two different
        investigations are two separate rows, because evidence is scoped to a case.
        """
        sha = ArtifactStore.digest(content)
        existing = self._session.execute(
            select(EvidenceRow).where(
                EvidenceRow.investigation_id == investigation_id,
                EvidenceRow.sha256 == sha,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return self._to_domain(existing)

        key, size = self._store.put(content, sha)
        domain = Evidence(
            investigation_id=investigation_id,
            kind=kind,
            sha256=sha,
            object_key=key,
            byte_size=size,
            truncated=truncated,
            summary=summary[:2000],
            produced_by=produced_by,
        )
        row = EvidenceRow(
            id=domain.id,
            investigation_id=investigation_id,
            kind=kind.value,
            sha256=sha,
            object_key=key,
            byte_size=size,
            truncated=truncated,
            redacted=False,
            summary=domain.summary,
            produced_by=produced_by,
            created_at=utcnow(),
        )
        self._session.add(row)
        self._session.flush()
        SqlEventStore(self._session).emit(
            investigation_id,
            "evidence_collected",
            {"evidence_id": domain.id, "kind": kind.value, "sha256": sha, "byte_size": size},
            actor=produced_by,
        )
        return domain

    def get(self, evidence_id: str) -> Evidence:
        from .errors import NotFound

        row = self._session.get(EvidenceRow, evidence_id)
        if row is None:
            raise NotFound(f"evidence {evidence_id} not found")
        return self._to_domain(row)

    def read_bytes(self, evidence_id: str) -> bytes:
        domain = self.get(evidence_id)
        return self._store.get(domain.object_key)

    def list_for(self, investigation_id: str, *, limit: int = 200) -> list[Evidence]:
        rows = self._session.execute(
            select(EvidenceRow)
            .where(EvidenceRow.investigation_id == investigation_id)
            .order_by(EvidenceRow.created_at.asc())
            .limit(limit)
        ).scalars()
        return [self._to_domain(r) for r in rows]

    @staticmethod
    def _to_domain(row: EvidenceRow) -> Evidence:
        return Evidence(
            id=row.id,
            investigation_id=row.investigation_id,
            kind=EvidenceKind(row.kind),
            sha256=row.sha256,
            object_key=row.object_key,
            byte_size=row.byte_size,
            truncated=row.truncated,
            redacted=row.redacted,
            summary=row.summary,
            produced_by=row.produced_by,
        )
