"""The append-only event store.

Every state change appends exactly one event, in the same transaction. That is the
mechanism behind "the frontend must not fabricate activity" (docs/EVENT_ARCHITECTURE.md 1):
if a mutation produced no event, the UI would have to guess.

Sequence numbers are allocated with one atomic
``UPDATE ... SET event_seq = event_seq + 1 ... RETURNING event_seq`` and then inserted.
Two consequences worth stating:

* ``UNIQUE(investigation_id, seq)`` is the real guarantee. If two writers raced, the
  constraint would reject the loser rather than silently duplicate a sequence number.
* The increment is atomic in the database itself, so a stale ORM snapshot of the
  investigation row in this session's identity map can never resurrect an old counter
  value. The previous ``SELECT ... FOR UPDATE`` + ORM attribute increment read through
  the identity map: if another session had already loaded or bumped the row, this
  session kept its stale ``event_seq`` and collided on the unique constraint instead of
  allocating the next sequence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import func, select, update
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

    def _next_seq(self, investigation_id: str) -> int:
        # One atomic UPDATE is the allocator: the database increments and returns the
        # counter in a single statement, so concurrent sessions serialize on the row
        # write lock and no session can allocate from a stale identity-map snapshot.
        # synchronize_session="fetch" expires any locally cached investigation row so a
        # later flush cannot write the pre-increment value back over the new counter.
        stmt = (
            update(InvestigationRow)
            .where(InvestigationRow.id == investigation_id)
            .values(event_seq=func.coalesce(InvestigationRow.event_seq, 0) + 1)
            .returning(InvestigationRow.event_seq)
            .execution_options(synchronize_session="fetch")
        )
        seq = self._session.execute(stmt).scalar_one_or_none()
        if seq is None:
            raise EventStoreError(f"unknown investigation {investigation_id}")
        return int(seq)

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

        seq = self._next_seq(investigation_id)

        ev = EventRow(
            investigation_id=investigation_id,
            seq=seq,
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
