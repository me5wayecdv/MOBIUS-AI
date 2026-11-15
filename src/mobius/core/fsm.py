"""The investigation state machine.

Control flow is deterministic code, not a prompt (ADR-003). The model decides *what* to
look at; this module decides *whether* the investigation may move, and in what direction.

Two properties matter:

* Every legal transition is enumerated. There is no "any state to any state".
* Every transition produces an event. ``transition()`` returns the payload the caller must
  append; it does not append it itself, so the event write and the state write can share
  one database transaction (docs/EVENT_ARCHITECTURE.md 2).
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .enums import InvestigationState as S

# Terminal states: no outgoing edges, ever.
TERMINAL: frozenset[S] = frozenset({S.CLOSED, S.CANCELLED, S.FAILED, S.SCOPE_BLOCKED})

# States from which the investigation has not yet left INTAKE and therefore may not yet
# be required to hold an authorisation. SCOPE_BLOCKED exists precisely so that a refused
# scan is still an auditable row (AC-FR-AUTH-2).
PRE_AUTHORISATION: frozenset[S] = frozenset({S.INTAKE, S.SCOPE_BLOCKED})

_TRANSITIONS: Mapping[S, frozenset[S]] = MappingProxyType(
    {
        S.INTAKE: frozenset({S.RECON, S.SCOPE_BLOCKED}),
        S.SCOPE_BLOCKED: frozenset(),
        S.RECON: frozenset({S.SURFACE_READY}),
        S.SURFACE_READY: frozenset({S.SELECTING}),
        S.SELECTING: frozenset({S.DISPATCHING, S.CORRELATING, S.BUDGET_EXHAUSTED}),
        S.DISPATCHING: frozenset({S.OBSERVING}),
        S.OBSERVING: frozenset({S.SELECTING, S.VALIDATING}),
        S.VALIDATING: frozenset({S.SELECTING, S.CORRELATING, S.AWAITING_APPROVAL}),
        S.AWAITING_APPROVAL: frozenset({S.SELECTING, S.CORRELATING}),
        S.CORRELATING: frozenset({S.REPORTING}),
        S.REPORTING: frozenset({S.CLOSED}),
        S.BUDGET_EXHAUSTED: frozenset({S.REPORTING}),
        S.CLOSED: frozenset(),
        S.CANCELLED: frozenset(),
        S.FAILED: frozenset(),
    }
)

# CANCELLED and FAILED are reachable from anywhere that is not already terminal. They are
# modelled separately rather than as edges in the table above so they cannot be forgotten
# when a new state is added.
_ALWAYS_ESCAPABLE = frozenset({S.CANCELLED, S.FAILED})


class IllegalTransition(Exception):
    """Raised when a caller attempts a transition the FSM does not permit."""

    def __init__(self, current: S, target: S) -> None:
        super().__init__(f"illegal transition {current} -> {target}")
        self.current = current
        self.target = target


class MissingAuthorization(Exception):
    """Raised when an investigation tries to leave INTAKE without an authorisation."""


def allowed_from(state: S) -> frozenset[S]:
    """Return the set of states reachable from ``state`` in one step."""
    if state in TERMINAL:
        return frozenset()
    return _TRANSITIONS[state] | _ALWAYS_ESCAPABLE


def can_transition(current: S, target: S) -> bool:
    return target in allowed_from(current)


@dataclass(frozen=True, slots=True)
class TransitionResult:
    """What the caller must persist. Returned, not performed, to keep this pure."""

    previous: S
    current: S
    event_type: str
    event_payload: dict[str, str]

    @property
    def is_terminal(self) -> bool:
        return self.current in TERMINAL


def transition(
    current: S,
    target: S,
    *,
    reason: str | None = None,
    authorization_id: str | None = None,
) -> TransitionResult:
    """Validate a transition and describe the event it produces.

    Raises:
        IllegalTransition: the edge does not exist, or the source is terminal.
        MissingAuthorization: leaving INTAKE for a working state with no authorisation.
    """
    if current in TERMINAL:
        raise IllegalTransition(current, target)
    if target not in allowed_from(current):
        raise IllegalTransition(current, target)

    if current in PRE_AUTHORISATION and target not in PRE_AUTHORISATION:
        if not authorization_id:
            raise MissingAuthorization(
                "an investigation may not leave INTAKE without a live authorization "
                "(FR-AUTH-2); see docs/DATABASE_SCHEMA.md for the backstop trigger"
            )

    payload: dict[str, str] = {"from": str(current), "to": str(target)}
    if reason:
        payload["reason"] = reason
    return TransitionResult(
        previous=current,
        current=target,
        event_type="investigation_updated",
        event_payload=payload,
    )


def is_terminal(state: S) -> bool:
    return state in TERMINAL


def path_is_legal(states: list[S], *, authorization_id: str | None = "ath_test") -> bool:
    """Convenience predicate used by tests and by the report's coverage calculation."""
    for current, target in zip(states, states[1:]):
        try:
            transition(current, target, authorization_id=authorization_id)
        except (IllegalTransition, MissingAuthorization):
            return False
    return True
