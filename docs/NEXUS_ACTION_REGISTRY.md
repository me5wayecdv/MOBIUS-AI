# NEXUS typed action registry — D-023

NEXUS dispatch accepts only actions registered in `mobius.core.actions.ActionRegistry`. The registry is server-owned and closed; model output is never interpreted as a command, binary path, URL, arbitrary target or free-form tool invocation.

## Registered actions

| Action | Agent | Typed arguments | Minimum intensity |
|---|---|---|---:|
| `find_api_refs` | SPECTRE | `component: Android component/class identifier` | 0 |
| `callers_of` | SPECTRE | `component: Android component/class identifier` | 0 |

Component identifiers are bounded and validated against a conservative Java/Android identifier pattern. Unknown actions, extra JSON fields, URL/path-like values, agent mismatches and insufficient intensity are rejected before dispatch. Rejected frontier work is persisted as dropped with the policy reason; it is not silently discarded.

## API discovery

`GET /api/v1/nexus/actions` returns the registered action names, owning agent, policy floor, description and JSON Schema for the arguments.

## Security boundary

- No command, argv, executable, shell, network URL or external target field exists in the action schema.
- The registry is not a substitute for ToolRunner's server-owned binary registry and OCI isolation; it only governs NEXUS-level analysis actions.
- Adding an action requires a server-side schema, owning agent, minimum intensity, tests and implementation. Model output cannot add registry entries.
- The current registry contains only the two SPECTRE static graph actions. It does not claim PHANTOM, VECTOR or PoC execution support.
