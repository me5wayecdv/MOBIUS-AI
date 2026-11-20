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


def test_ties_break_on_content_not_on_generated_ids():
    """Regression: two runs over the same APK dispatched in different orders.

    Ids are ULIDs, so a tie broken on id is a tie broken on a clock and a random number.
    The same frontier must order the same way on a machine that generates different ids.
    """
    from mobius.core.frontier import rank

    def frontier(first_id: str, second_id: str):
        return [
            _entry(id=first_id, action="find_api_refs", action_args={"component": "com.x.B"}),
            _entry(id=second_id, action="find_api_refs", action_args={"component": "com.x.A"}),
        ]

    ctx = ScoreContext()
    one = rank(frontier("fro_00000000000000000000000000", "fro_00000000000000000000000001"), ctx)
    two = rank(frontier("fro_00000000000000000000000001", "fro_00000000000000000000000000"), ctx)

    assert [e.action_args["component"] for e in one] == ["com.x.A", "com.x.B"]
    assert [e.action_args["component"] for e in two] == ["com.x.A", "com.x.B"]


# --- Gate-taxonomy correction (2026-11-20): scoring regression pins ---------------
#
# The taxonomy fix changed each gate's MASWE tags but must not change the score of
# any gate's own candidates: under the old (mis-tagged) gates every category resolved
# to the weights below, and the new exact-ID entries were chosen to reproduce them.
# Measured by running impact_weight from both code versions over both tag sets.

GATE_WEIGHT_PRESERVATION = {
    "exported-component-no-permission": 0.95,
    "exported-provider-unprotected-sink": 0.95,
    "hardcoded-secret": 0.7,
    "insecure-storage": 0.7,
    "weak-crypto": 0.8,
    "webview-rce-surface": 0.95,
    "cleartext-transport": 0.8,
    "exported-provider-path-traversal": 0.95,
    "dynamic-code-loading": 0.95,
    "implicit-intent-sensitive-data": 0.95,
    "deeplink-unvalidated-input": 0.95,
}


def test_every_gate_keeps_its_pre_correction_impact_weight():
    from mobius.core.gates import _GATES
    from mobius.core.frontier import impact_weight

    for gate in _GATES:
        assert impact_weight(gate.maswe) == GATE_WEIGHT_PRESERVATION[gate.category], gate.category


def test_legacy_id_resolution_is_unchanged_for_historical_tags():
    """Tags stored on pre-correction findings/seeds must resolve exactly as before."""
    from mobius.core.frontier import impact_weight

    assert impact_weight(("MASWE-0029",)) == 0.95
    assert impact_weight(("MASWE-0030",)) == 0.90
    assert impact_weight(("MASWE-0001",)) == 0.70
    assert impact_weight(("MASWE-0002",)) == 0.70
    assert impact_weight(("MASWE-001",)) == 0.80   # raw prefix string, as stored by old gates
    assert impact_weight(("MASWE-005",)) == 0.80   # raw prefix string, as stored by old gates
    assert impact_weight(("MASWE-0034",)) == 0.5   # known ID with no weight entry
    assert impact_weight(("MASWE-9999",)) == 0.5   # unknown ID default
    assert impact_weight(()) == 0.5


def test_mixed_legacy_and_new_tuple_resolves_by_max_and_is_unchanged():
    """Catalogue tuple (0029, 0032, 0050): max semantics keep it at 0.95 on both versions."""
    from mobius.core.frontier import impact_weight

    assert impact_weight(("MASWE-0029", "MASWE-0032", "MASWE-0050")) == 0.95
    assert impact_weight(("MASWE-0029", "MASWE-0050")) == 0.95


def test_new_exact_id_weights_are_the_documented_known_delta():
    """KNOWN DELTA, pinned deliberately: these IDs resolved lower before the correction
    (0.5 default, or 0.80 via the raw "MASWE-001"/"MASWE-005" prefix strings). Candidates
    outside the 11 gates that carry them - 15 catalogue families tagged MASWE-0050 alone,
    plus webview-js-interface (0033), webview-load (0035) and dynamic-load (0049) - now
    score higher. Preserving both the old per-ID resolution AND the old per-gate scores
    is impossible: the old gates were mis-tagged, so the two conflict. This test pins the
    chosen values so the delta is explicit and reviewable, not silent."""
    from mobius.core.frontier import impact_weight

    assert impact_weight(("MASWE-0018",)) == 0.95  # was 0.80 (via "MASWE-001" prefix)
    assert impact_weight(("MASWE-0050",)) == 0.95  # was 0.80 (via "MASWE-005" prefix)
    assert impact_weight(("MASWE-0032",)) == 0.95  # was 0.5 (no entry)
    assert impact_weight(("MASWE-0033",)) == 0.95  # was 0.5
    assert impact_weight(("MASWE-0035",)) == 0.95  # was 0.5
    assert impact_weight(("MASWE-0049",)) == 0.95  # was 0.5
    assert impact_weight(("MASWE-0004",)) == 0.70  # was 0.5
    assert impact_weight(("MASWE-0007",)) == 0.80  # was 0.5
    assert impact_weight(("MASWE-0008",)) == 0.80  # was 0.5
    assert impact_weight(("MASWE-0026",)) == 0.80  # was 0.5
