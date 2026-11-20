# VERITAS model-quality acceptance

**Status:** executable harness implemented 2026-11-20 (`python -m mobius.tools.veritas_acceptance`,
test-pinned in `tests/test_veritas_acceptance.py`). No real model currently meets the bar,
because no real model has been run against it; the harness defines the bar and proves the
guards enforce it.

## What "acceptance" means here

VERITAS is advisory only; deterministic gates remain the sole verdict authority. Accepting a
reviewer model therefore does NOT mean trusting its judgement. It means two narrower things:

1. **The integrity contract holds** (mock mode, deterministic, free): every guard on the
   review path fires when it must, and well-formed reviews persist without touching gate
   verdicts. This is pinned by 18 scripted cases across six criteria:
   - *schema-validity*: malformed, truncated, undersized or over-furnished replies fail closed.
   - *evidence-confinement*: challenges citing fabricated, cross-investigation, or
     unicode-confusable evidence references are refused and never persisted.
   - *disposition-discipline*: `challenge` requires challenges, `no_material_challenge`
     forbids them, and no reply can pronounce a finding `confirmed`.
   - *independence*: a requested reviewer equal to the producer is refused before any provider
     call; an alias that resolves to the producer is refused after the response.
   - *consent-gating*: no investigation consent, no provider call.
   - *budget-gating*: an exhausted budget refuses before the call; a provider reporting usage
     over the pre-call ceiling is charged conservatively and refused.
2. **A candidate model clears the quality floor in practice** (live mode, operator action):
   `python -m mobius.tools.veritas_acceptance --mode ollama` with `MOBIUS_MODEL_NAME` set runs
   one seeded challengeable fixture through the real review path and reports the measured
   latency and token usage against the investigation's timeout/budget. A pass is a minimum
   floor (the model produced a schema-valid, evidence-confined challenge on a fixture built
   to be challengeable), not a quality endorsement.

## Measured standing (provenance, not fresh runs)

- 2026-11-19, owner host, Ollama 0.40.16: `qwen2.5:0.5b`, `qwen2.5:1.5b`,
  `qwen2.5-coder:1.5b` all produced schema-valid JSON for NEXUS hypothesis generation and all
  were rejected by the integrity guards (fabricated/wrong-kind citations); the deterministic
  fallback engaged. See TASK_BOARD.md.
- 2026-11-19 post-closeout bounded probe, single-finding fixture: `qwen2.5-coder:1.5b`
  returned schema-valid, evidence-confined VERITAS reviews 2/2 at ~51s/review (700-token cap)
  with generic, low-value challenge content; `qwen2.5:1.5b` 0/2 (timeout at the 1200-token
  cap on CPU). See IMPLEMENTATION_STATUS.md.
- Whether a larger local model passes the guards is unknown; it has never been tried. Running
  one is an operator action: install the model in Ollama, set `MOBIUS_MODEL_NAME`, run live
  mode. The API never downloads models and never calls a hosted provider.

## Boundaries

- A green mock run pins the bar. It is not evidence about any real model.
- A green live run on one fixture is a floor, not an endorsement; challenge-content quality
  remains human-judged.
- The harness never lowers a guard to make a case pass; a failing case is a red bar, and the
  battery itself is pinned by tests so a silent guard regression turns the suite red.
