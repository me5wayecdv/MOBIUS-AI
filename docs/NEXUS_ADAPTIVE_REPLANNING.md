# Adaptive NEXUS re-planning — D-024

## Current deterministic loop

The current bounded policy implements one evidence-driven transition:

1. NEXUS dispatches `find_api_refs` through the typed action registry.
2. SPECTRE records the reachability result, including the ordered method path.
3. If the result is `reached`, NEXUS selects the final application method on that path (the method containing the sink call).
4. NEXUS validates a `callers_of` action against the closed registry and creates a frontier entry with typed class, method and descriptor fields.
5. NEXUS persists a `DecisionRow` and `nexus_replanned` event, then returns to frontier selection.
6. SPECTRE records the direct application callers as an observation. The caller list is marked exhaustive only when the DEX index is complete.

No follow-up is created for `not-reached`, `truncated`, `no-entry-point`, or missing method paths. Duplicate queued/completed caller actions are not re-created. Depth and normal NEXUS step budgets still apply.

## Testable invariant

`test_reachable_sink_result_changes_next_action_to_direct_caller_inspection` fixes the graph and verifies:
- the first SPECTRE result is a reachable sink path,
- the next queued action changes to `callers_of`,
- the action carries the exact sink-bearing method reference,
- the caller observation is persisted,
- a decision row and durable `nexus_replanned` event record why the next action changed.

## Scope boundary

This is deterministic evidence-driven replanning, not yet model-generated plan synthesis. Model hypotheses remain separate and consent-gated. NEXUS still cannot dispatch arbitrary actions; every follow-up must pass the typed registry. No caller relationship proves runtime execution, tainted input or exploitability.
