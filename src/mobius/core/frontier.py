"""Frontier scoring: the one place the investigation is "adaptive".

This is a best-first search over an open action space with a hand-written evaluation
function. Calling it "adaptive planning" would be overclaiming; the honest description is
what docs/AGENT_DESIGN.md 4 says: a priority queue whose ranking is arithmetic, not a
model call. Arithmetic means it is cheap, deterministic, explainable and replayable -
which is exactly what a reviewer asking "why did it look at *that* class?" needs.

    EV = P(informative) * info_gain * impact * depth_decay / (cost * (1 + risk))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from .enums import Intensity
from .schemas import FrontierEntry

# Cost is a normalised wall-clock percentile per action, from measured runs. These are
# initial estimates; the doc requires them to be replaced with measurements.
_DEFAULT_COST: Mapping[str, float] = MappingProxyType(
    {
        "parse_manifest": 0.05,
        "list_dex": 0.05,
        "parse_cert": 0.05,
        "parse_nsc": 0.05,
        "find_class": 0.10,
        "find_string": 0.10,
        "find_api_refs": 0.20,
        "decompile_method": 0.35,
        "callers_of": 0.40,
        "smali_fallback": 0.50,
        "launch_component": 0.70,
        "send_intent": 0.70,
        "frida_instrument": 0.95,
        "capture_traffic": 0.80,
        "replay_request": 0.80,
    }
)

# Actions that execute the target. They are unavailable below their intensity threshold,
# so safety lives in the scorer rather than in a prompt an injection could talk around.
_DYNAMIC_ACTIONS: frozenset[str] = frozenset(
    {"launch_component", "send_intent", "frida_instrument", "capture_traffic", "replay_request"}
)

# Which actions need which intensity.
_INTENSITY_REQUIRED: Mapping[str, int] = MappingProxyType(
    {
        "launch_component": Intensity.OBSERVATIONAL,
        "send_intent": Intensity.INTERACTIONAL,
        "frida_instrument": Intensity.INTERACTIONAL,
        "capture_traffic": Intensity.INTERACTIONAL,
        "replay_request": Intensity.INTERACTIONAL,
    }
)

# Static impact weight per MASWE prefix. A cheap, honest stand-in for CVSS: it separates
# "leaks a preference" from "reaches a privileged data write".
_IMPACT_BY_MASWE_PREFIX: Mapping[str, float] = MappingProxyType(
    {
        "MASWE-0029": 0.95,  # platform / exported component to privileged sink
        "MASWE-0030": 0.90,
        "MASWE-0001": 0.70,  # insecure storage
        "MASWE-0002": 0.70,
        "MASWE-001": 0.80,   # crypto
        "MASWE-005": 0.80,   # network
    }
)

UNREACHABLE = float("-inf")


@dataclass(frozen=True, slots=True)
class ScoreContext:
    """Everything the scorer needs. Supplied by the caller so scoring stays pure."""

    intensity: int = Intensity.PASSIVE
    priors: Mapping[str, float] = field(default_factory=dict)
    costs: Mapping[str, float] = field(default_factory=lambda: _DEFAULT_COST)
    max_depth: int = 4
    depth_decay: float = 0.85

    def cost_of(self, action: str) -> float:
        return max(self.costs.get(action, 0.5), 1e-6)

    def prior_of(self, action: str) -> float:
        value = self.priors.get(action, 0.5)
        return min(max(value, 0.0), 1.0)


def impact_weight(maswe: tuple[str, ...]) -> float:
    """Highest impact among the weaknesses an action relates to; 0.5 if unknown."""
    if not maswe:
        return 0.5
    best = 0.0
    for tag in maswe:
        for prefix, weight in _IMPACT_BY_MASWE_PREFIX.items():
            if tag.startswith(prefix):
                best = max(best, weight)
    return best if best else 0.5


def risk_penalty(action: str, intensity: int) -> float:
    """0 for passive actions, a finite penalty when permitted, infinite when not.

    Returning ``inf`` (rather than filtering earlier) means an entry that is not permitted
    can still sit in the frontier and be *reported* as skipped - the report's "what we did
    not do" section depends on that, and silently dropping it would hide the gap.
    """
    if action not in _DYNAMIC_ACTIONS:
        return 0.0
    required = _INTENSITY_REQUIRED.get(action, Intensity.INTERACTIONAL)
    if intensity < required:
        return UNREACHABLE
    return 0.25


def score(entry: FrontierEntry, ctx: ScoreContext) -> float:
    """Expected value of performing this action.

    Returns ``-inf`` for actions the current intensity forbids and for entries already
    beyond the depth cap, so they sort last without special-casing at the call site.
    """
    if entry.depth > ctx.max_depth:
        return UNREACHABLE

    risk = risk_penalty(entry.action, ctx.intensity)
    if risk == UNREACHABLE:
        return UNREACHABLE

    p_informative = ctx.prior_of(entry.action)
    # An action that is expected to confirm what is already believed is worth less.
    info_gain = min(max(1.0 - entry.score if entry.score else 1.0, 0.05), 1.0)
    impact = impact_weight(entry.relates_to_maswe)
    decay = ctx.depth_decay**entry.depth

    return (p_informative * info_gain * impact * decay) / (ctx.cost_of(entry.action) * (1.0 + risk))


def rank(entries: list[FrontierEntry], ctx: ScoreContext) -> list[FrontierEntry]:
    """Return entries best-first, with a deterministic tie-break.

    Ties are broken newest-first then by id, so two runs over the same frontier produce the
    same order. Non-deterministic ranking would make an investigation unreproducible.
    """
    scored = [(score(e, ctx), e) for e in entries]
    return [e for s, e in sorted(scored, key=lambda p: (-p[0], -p[1].depth, p[1].id))]


def pop_best(entries: list[FrontierEntry], ctx: ScoreContext) -> FrontierEntry | None:
    ranked = rank([e for e in entries if e.state == "queued"], ctx)
    if not ranked:
        return None
    best = ranked[0]
    return None if score(best, ctx) == UNREACHABLE else best
