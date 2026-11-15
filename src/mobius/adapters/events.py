"""The append-only event store.

Every state change appends exactly one event, in the same transaction. That is the
mechanism behind "the frontend must not fabricate activity" (docs/EVENT_ARCHITECTURE.md 1):
if a mutation produced no event, the UI would have to guess.

Sequence numbers are allocated by incrementing ``investigations.event_seq`` under the row
lock, then inserted. Two consequences worth stating:

* ``UNIQUE(investigation_id, seq)`` is the real guarantee. If two writers raced, the
  constraint would reject the loser rather than silently duplicate a sequence number.
* On SQLite the row lock is a database-level write lock, so this is serialised anyway.
  On Postgres the ``SELECT ... FOR UPDATE`` on the counter row is what makes it correct
  with concurrent workers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import EventRow, InvestigationRow


class EventStoreError(Exception):
    """Raised when an event cannot be appended to an investigation."""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class StoredEvent:
    seq: int
    type: str
    payload: dict[str, Any]
    actor: str | None
    causation_id: str | None
    correlation_id: str | None
    created_at: str


class SqlEventStore:
    """EventStore implementation bound to one session.

    Deliberately takes the session rather than creating one: the caller owns the
    transaction, so the state write and the event write commit or roll back together.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def _lock_counter(self, investigation_id: str) -> InvestigationRow:
        # with_for_update() is a no-op on SQLite and a row lock on Postgres. Either way
        # the UNIQUE constraint is the backstop.
        stmt = (
            select(InvestigationRow)
            .where(InvestigationRow.id == investigation_id)
            .with_for_update()
        )
        row = self._session.execute(stmt).scalar_one_or_none()
        if row is None:
            raise EventStoreError(f"unknown investigation {investigation_id}")
        return row

    def emit(
        self,
        investigation_id: str,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        actor: str | None = None,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> int:
        """Append one event and return its sequence number."""
        if not event_type:
            raise EventStoreError("event_type must not be empty")

        row = self._lock_counter(investigation_id)
        row.event_seq = int(row.event_seq or 0) + 1
        self._session.flush()

        ev = EventRow(
            investigation_id=investigation_id,
            seq=row.event_seq,
            type=event_type,
            payload=payload or {},
            actor=actor,
            causation_id=causation_id,
            correlation_id=correlation_id,
            created_at=utcnow(),
        )
        self._session.add(ev)
        self._session.flush()
        return ev.seq

    def read_after(
        self, investigation_id: str, after_seq: int = 0, limit: int = 500
    ) -> list[StoredEvent]:
        stmt = (
            select(EventRow)
            .where(EventRow.investigation_id == investigation_id, EventRow.seq > after_seq)
            .order_by(EventRow.seq.asc())
            .limit(limit)
        )
        return [
            StoredEvent(
                seq=r.seq,
                type=r.type,
                payload=r.payload,
                actor=r.actor,
                causation_id=r.causation_id,
                correlation_id=r.correlation_id,
                created_at=r.created_at,
            )
            for r in self._session.execute(stmt).scalars()
        ]

    def current_seq(self, investigation_id: str) -> int:
        value = self._session.execute(
            select(func.coalesce(func.max(EventRow.seq), 0)).where(
                EventRow.investigation_id == investigation_id
            )
        ).scalar_one()
        return int(value)

    def count(self, investigation_id: str) -> int:
        return int(
            self._session.execute(
                select(func.count(EventRow.id)).where(
                    EventRow.investigation_id == investigation_id
                )
            ).scalar_one()
        )
