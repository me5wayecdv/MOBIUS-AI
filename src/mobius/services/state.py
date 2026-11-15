"""Shared FSM write path.

Every service that moves an investigation must do three things in one transaction: validate
the edge against the FSM, write the new state, and append the event the transition describes.
Doing that inline in each service is how the event and the state drift apart, so it lives
here instead.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..adapters.events import SqlEventStore
from ..adapters.models import InvestigationRow
from ..core import fsm
from ..core.enums import InvestigationState


def advance(
    session: Session,
    row: InvestigationRow,
    target: InvestigationState,
    *,
    actor: str,
    reason: str | None = None,
) -> None:
    """Validate and persist one transition, emitting its event.

    Raises:
        IllegalTransition: the edge does not exist (caller bug, not user input).
        MissingAuthorization: leaving INTAKE without a live authorisation.
    """
    result = fsm.transition(
        InvestigationState(row.state),
        target,
        reason=reason,
        authorization_id=row.authorization_id,
    )
    row.state = result.current.value
    SqlEventStore(session).emit(row.id, result.event_type, result.event_payload, actor=actor)
    session.flush()
