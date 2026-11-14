from __future__ import annotations

import pytest

from mobius.core import fsm
from mobius.core.enums import InvestigationState as S


def test_happy_path_is_legal():
    path = [S.INTAKE, S.RECON, S.SURFACE_READY, S.SELECTING, S.DISPATCHING,
            S.OBSERVING, S.VALIDATING, S.CORRELATING, S.REPORTING, S.CLOSED]
    assert fsm.path_is_legal(path)


def test_skipping_a_phase_is_illegal():
    with pytest.raises(fsm.IllegalTransition):
        fsm.transition(S.INTAKE, S.SELECTING, authorization_id="ath_x")


def test_terminal_states_have_no_exits():
    for state in fsm.TERMINAL:
        assert fsm.allowed_from(state) == frozenset()
        with pytest.raises(fsm.IllegalTransition):
            fsm.transition(state, S.RECON)


def test_cancel_and_fail_reachable_from_every_non_terminal_state():
    for state in S:
        if state in fsm.TERMINAL:
            continue
        assert S.CANCELLED in fsm.allowed_from(state)
        assert S.FAILED in fsm.allowed_from(state)


def test_leaving_intake_without_authorization_raises():
    # FR-AUTH-2: the investigation may not start working without a live authorisation.
    with pytest.raises(fsm.MissingAuthorization):
        fsm.transition(S.INTAKE, S.RECON)
    ok = fsm.transition(S.INTAKE, S.RECON, authorization_id="ath_1")
    assert ok.current is S.RECON


def test_scope_blocked_does_not_need_authorization():
    result = fsm.transition(S.INTAKE, S.SCOPE_BLOCKED)
    assert result.current is S.SCOPE_BLOCKED
    assert result.is_terminal


def test_transition_describes_its_event():
    result = fsm.transition(S.SELECTING, S.CORRELATING, authorization_id="ath_1", reason="frontier empty")
    assert result.event_type == "investigation_updated"
    assert result.event_payload == {"from": "SELECTING", "to": "CORRELATING", "reason": "frontier empty"}


def test_pause_is_not_a_state():
    # ADR-017: pause is a flag. If someone adds PAUSED to the enum this fails, which is
    # the point - the three documents that disagreed about it should not diverge again.
    assert "PAUSED" not in {s.name for s in S}
    assert len(list(S)) == 15


def test_transition_returns_terminal_flag():
    assert fsm.transition(S.REPORTING, S.CLOSED, authorization_id="a").is_terminal
    assert not fsm.transition(S.RECON, S.SURFACE_READY, authorization_id="a").is_terminal
