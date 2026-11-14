"""The frontier is a best-first search with a hand-written evaluation function.

These tests pin the arithmetic and, more importantly, the safety property: an action the
authorisation does not permit must be unselectable, and it must be so by returning -inf
rather than by a large cost, because a cost can be outbid by a high enough probability.
"""

from __future__ import annotations

import math

import pytest

from mobius.core.enums import Intensity
from mobius.core.frontier import (
    UNREACHABLE,
    ScoreContext,
    impact_weight,
    pop_best,
    rank,
    risk_penalty,
    score,
)
from mobius.core.ids import new_id
from mobius.core.schemas import FrontierEntry


def _entry(**kw) -> FrontierEntry:
    base = dict(
        investigation_id="inv_1",
        action="find_api_refs",
        required_agent="SPECTRE",
        relates_to_maswe=("MASWE-0029",),
    )
    base.update(kw)
    return FrontierEntry(**base)


def test_risk_penalty_is_unreachable_below_required_intensity():
    assert risk_penalty("frida_instrument", Intensity.PASSIVE) == UNREACHABLE
    assert risk_penalty("frida_instrument", Intensity.INTERACTIONAL) < 1.0


def test_static_actions_carry_no_risk():
    for action in ("parse_manifest", "find_string", "callers_of"):
        assert risk_penalty(action, Intensity.PASSIVE) == 0.0


def test_forbidden_action_scores_minus_infinity():
    # Not "expensive": unselectable.
    entry = _entry(action="frida_instrument", required_agent="PHANTOM")
    assert score(entry, ScoreContext(intensity=Intensity.PASSIVE)) == UNREACHABLE


def test_depth_cap_makes_entries_unreachable():
    deep = _entry(depth=9)
    assert score(deep, ScoreContext(max_depth=4)) == UNREACHABLE


def test_deeper_entries_score_lower():
    ctx = ScoreContext()
    shallow = score(_entry(depth=1), ctx)
    deeper = score(_entry(depth=3), ctx)
    assert shallow > deeper > 0


def test_impact_weight_prefers_the_most_severe_mapping():
    assert impact_weight(("MASWE-0029",)) > impact_weight(("MASWE-0001",))
    assert impact_weight(()) == 0.5
    assert impact_weight(("MASWE-9999",)) == 0.5


def test_impact_weight_is_bounded():
    for tag in filter(None, [f"MASWE-{n:04d}" for n in range(1, 80)]):
        assert 0.0 <= impact_weight((tag,)) <= 1.0


def test_expensive_action_scores_below_a_cheap_one():
    ctx = ScoreContext()
    cheap = score(_entry(action="parse_manifest"), ctx)
    dear = score(_entry(action="frida_instrument", required_agent="PHANTOM"), ScoreContext(intensity=Intensity.INTERACTIONAL))
    assert cheap > dear


def test_prior_raises_the_score():
    entry = _entry(action="find_class")
    cold = score(entry, ScoreContext(priors={"find_class": 0.1}))
    hot = score(entry, ScoreContext(priors={"find_class": 0.9}))
    assert hot > cold


def test_priors_are_clamped():
    ctx = ScoreContext(priors={"find_class": 5.0})
    assert 0.0 <= ctx.prior_of("find_class") <= 1.0


def test_rank_is_deterministic():
    entries = [_entry(action=a) for a in ("parse_manifest", "find_class", "callers_of", "find_string")]
    ctx = ScoreContext()
    first = [e.id for e in rank(entries, ctx)]
    second = [e.id for e in rank(entries, ctx)]
    assert first == second


def test_rank_places_unreachable_entries_last():
    ctx = ScoreContext(intensity=Intensity.PASSIVE)
    entries = [
        _entry(action="frida_instrument", required_agent="PHANTOM"),
        _entry(action="parse_manifest"),
    ]
    ordered = rank(entries, ctx)
    assert ordered[-1].action == "frida_instrument"


def test_pop_best_ignores_non_queued_entries():
    ctx = ScoreContext()
    entries = [
        _entry(action="parse_manifest", state="done"),
        _entry(action="find_class", state="queued"),
    ]
    best = pop_best(entries, ctx)
    assert best is not None and best.action == "find_class"


def test_pop_best_returns_none_when_everything_is_forbidden():
    ctx = ScoreContext(intensity=Intensity.PASSIVE)
    entries = [_entry(action="frida_instrument", required_agent="PHANTOM")]
    assert pop_best(entries, ctx) is None


def test_scores_are_never_nan():
    ctx = ScoreContext()
    for action in ("parse_manifest", "send_intent", "unknown_action"):
        value = score(_entry(action=action), ctx)
        assert not math.isnan(value)
