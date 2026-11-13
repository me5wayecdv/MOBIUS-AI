# AGENT DESIGN & INVESTIGATION ENGINE

**Status:** Proposed
**Audience:** Members 1, 2, 3, 5 (see `TEAM_RESPONSIBILITIES.md`)
**Companions:** `ARCHITECTURE.md` §4, `DATABASE_SCHEMA.md`, `EVENT_ARCHITECTURE.md`

---

## 1. The central design decision

The master prompt says: *"Do not implement agents as independent LLM prompts with hardcoded
execution sequences."* It also says: *"Neither simulate parallel execution."*

Both are satisfied by one design:

> **An agent is not a loop. An agent is a function with a declared contract, invoked by a
> deterministic scheduler.**

- Control flow (what happens next, when to stop, when to validate) → **deterministic code**.
- Content (which class to inspect, how to interpret a manifest, whether a pattern is exploitable) →
  **model output, schema-validated, from a closed vocabulary.**

An "agent" therefore = `(role prompt, tool allowlist, input schema, output schema, budget)`. It is
invoked, it returns typed data, it exits. It does not hold a conversation with other agents. The
"conversation" is the event log and the frontier.

**Why this matters practically:** an agent that is a function is unit-testable with a stub model.
An agent that is a loop can only be tested end-to-end at high cost. For a 6-person team this is the
difference between a test suite and a demo.

## 2. Agent contract

```python
# mobius/core/contracts.py  (Layer 1 — no I/O imports allowed)
from typing import Protocol, Generic, TypeVar
from pydantic import BaseModel

InT = TypeVar("InT", bound=BaseModel)
OutT = TypeVar("OutT", bound=BaseModel)

class AgentSpec(BaseModel):
    name: str                       # "SPECTRE"
    role: str                       # one-line purpose
    allowed_actions: frozenset[str] # closed set; enforced at dispatch
    budget: AgentBudget             # model tokens, tool calls, wall clock
    output_schema: str              # ref into the schema registry

class AgentBudget(BaseModel):
    max_model_tokens: int = 60_000
    max_tool_calls: int = 25
    max_wall_seconds: int = 300

class Agent(Protocol, Generic[InT, OutT]):
    spec: AgentSpec
    async def run(self, task: InT, ctx: AgentContext) -> OutT: ...
```

`AgentContext` deliberately carries **no direct DB handle and no LLM client**. It exposes:

| Member | Purpose |
|---|---|
| `evidence: EvidenceReader` | read-only access to stored artifacts |
| `tools: ToolInvoker` | request a tool run; returns `ToolResult \| ToolUnavailable \| ToolError` |
| `model: ModelGateway` | structured completion with schema + repair |
| `emit: EventEmitter` | append events (only through the service layer) |
| `budget: BudgetMeter` | live remaining budget; raises `BudgetExceeded` |

This makes every agent trivially mockable and makes it *impossible* for an agent to write a Finding
directly. Only `ValidationService` creates findings.

## 3. Structured communication schema

The master prompt's illustrative message schema is a reasonable start but conflates several things.
The proposed replacement separates **what was seen** (Observation) from **what is believed**
(Hypothesis) from **what was decided** (Decision). Conflating them is the most common way a
security tool ends up unable to distinguish fact from inference.

```jsonc
// Observation — a typed, evidence-backed statement about the artefact
{
  "id": "obs_01J8Z...",            // ULID, sortable
  "scan_id": "scn_01J8Z...",
  "agent": "RECON",
  "kind": "fact",                  // fact | inference | anomaly
  "fidelity": "binary-xml",        // binary-xml | decompiled | smali | decompiler-failed | runtime
  "subject": {
    "type": "component",
    "ref": "com.example/.ExportActivity"
  },
  "statement": "Exported activity with no android:permission and an implicit-export intent filter accepting ACTION_SEND with scheme 'myapp'.",
  "evidence_refs": ["ev_01J8Z..."],// MUST be non-empty for kind=fact  (AC-FR-RECON-7)
  "attributes": {                  // structured, queryable — not prose
    "exported": true,
    "export_reason": "intent_filter",
    "permission": null,
    "actions": ["android.intent.action.SEND"],
    "data_schemes": ["myapp"]
  },
  "maswe": ["MASWE-0029"],         // weakness this *may* relate to; not a verdict
  "confidence": 1.0,               // facts are 1.0; inferences are < 1.0
  "created_at": "2026-11-12T09:00:00Z"
}
```

```jsonc
// Hypothesis — a testable security claim awaiting evidence
{
  "id": "hyp_01J8Z...",
  "scan_id": "scn_01J8Z...",
  "claim": "An unprivileged third-party app can invoke ExportActivity with attacker-controlled extras, reaching a data write with no caller verification.",
  "derived_from": ["obs_01J8Z...", "obs_01J9A..."],
  "maswe": ["MASWE-0029"],
  "status": "open",                // open | testing | supported | refuted | abandoned | parked
  "required_evidence": [           // declared BEFORE testing — prevents moving goalposts
    "caller-identity-check-absent",
    "sink-reachable-from-intent-extras"
  ],
  "satisfied_evidence": [],
  "priority": 0.72,
  "depth": 1,
  "parent_hypothesis_id": null
}
```

```jsonc
// Decision — why the system did what it did. Auditable, NOT chain-of-thought.
{
  "id": "dec_01J8Z...",
  "scan_id": "scn_01J8Z...",
  "agent": "NEXUS",
  "action": "inspect_method",          // must exist in the action registry
  "action_args": { "class": "com.example.ExportActivity", "method": "onCreate" },
  "considered_evidence": ["obs_01J8Z...", "obs_01J9A..."],
  "alternatives_rejected": [
    { "action": "inspect_method", "target": "com.example.MainActivity",
      "reason": "not exported; lower expected information gain" }
  ],
  "expected_outcome": "Locate the data sink reached from getIntent().getExtras().",
  "uncertainty": "Cannot yet tell whether a signature permission gates the receiver path.",
  "frontier_snapshot": 4                // reusable for replay
}
```

**Explicit non-goal:** MOBIUS will not store model reasoning traces in `Decision`. The master prompt
forbids exposing chain-of-thought, and it is also bad engineering — it is verbose, non-deterministic,
and not an audit trail. The audit trail is the *action, its inputs, its evidence, and its expected
outcome*. Those are checkable; a narrative is not.

## 4. The frontier: how "adaptive planning" is actually implemented

A hypothesis-driven investigation is a **best-first search over an open action space**. The frontier
is a priority queue persisted in Postgres, not a list in memory — so it survives restart (FR-NEXUS-7).

```python
# Layer 1 — pure function, no I/O, fully unit-testable
def score(entry: FrontierEntry, ctx: ScoreContext) -> float:
    """
    Expected value of performing this action.

    EV = ( P(informative) * info_gain * impact_if_confirmed ) / ( cost * risk_penalty )

    Every term is bounded to [0,1] so the score is comparable across action types.
    """
    p = ctx.prior[entry.action]                       # empirical, from past scans; default 0.5
    gain = 1.0 - entry.expected_information_delta      # prefer actions that change belief
    impact = ctx.impact_weight(entry.relates_to_maswe)  # CVSS-derived, static table
    cost = ctx.normalised_cost(entry.action)            # wall-time percentile, static table
    risk = ctx.risk_penalty(entry.action, ctx.intensity) # dynamic actions cost more
    depth_decay = 0.85 ** entry.depth                   # discourage rabbit holes
    return (p * gain * impact * depth_decay) / (cost * (1.0 + risk))
```

Properties that make this defensible rather than hand-wavy:

1. **No model call to rank.** Ranking is arithmetic over stored attributes. Cheap, deterministic,
   explainable, and reproducible — critical when a reviewer asks "why did it look at *that* class?"
2. **`prior` is empirical and improves.** Start at 0.5; update from completed scans. This is the one
   place genuine learning happens, and it is *frequency counting*, not a neural network — honest and
   testable.
3. **`risk_penalty` encodes the safety policy**: at intensity 0, dynamic actions get an infinite
   penalty and can never be popped. Safety is in the scorer, not in a prompt.
4. **Depth decay** implements FR-NEXUS-5 without a special-case loop detector.

The LLM's role in planning is narrow and defensible: **generate candidate frontier entries**
("what hypotheses are worth considering here?") and **fill action parameters**. It never ranks and
never decides termination.

### 4.1 Why hybrid, and what the alternatives cost

| Approach | Verdict | Reasoning |
|---|---|---|
| Fixed scanner pipeline | Rejected | This is precisely what the project must not be |
| Pure ReAct loop | Rejected as control flow | No termination guarantee, no cost ceiling, no rollback; failure modes documented [S1] |
| Full LLM planner, replans every step | Rejected | Non-deterministic token cost, unreproducible investigations, hard to audit |
| **FSM + persisted frontier + arithmetic ranking + LLM content generation** | **Chosen** | Deterministic control, bounded cost, replayable, auditable; model adds judgement where judgement is needed |
| Learned policy (RL) | Rejected | No training signal; unjustifiable in a semester |

## 5. The seven agents, concretely

Each row is implementable as one module with a prompt and a tool allowlist.

| Agent | Input | Output | Allowed actions | Model tier |
|---|---|---|---|---|
| **NEXUS** | frontier snapshot + recent observations | `Decision` + optional new `Hypothesis` | `push_hypothesis`, `rank`, `assign`, `request_validation`, `terminate_branch` | reasoning |
| **RECON** | artifact key | `ManifestFacts`, `Component[]`, `CertFacts`, `NetworkConfig` | `parse_manifest`, `parse_axml`, `list_dex`, `parse_cert`, `parse_nsc` | none (deterministic) |
| **SPECTRE** | class/method target + question | `CodeObservation[]` | `find_class`, `decompile_method`, `find_api_refs`, `find_string`, `callers_of`, `smali_fallback` | workhorse |
| **PHANTOM** | component + test intent | `RuntimeObservation[]` | `launch_component`, `send_intent`, `logcat_window`, `frida_script` *(intensity ≥ 2)* | workhorse |
| **VECTOR** | endpoint set + auth observation | `ApiObservation[]` | `capture_traffic`, `replay_request`, `inspect_jwt`, `probe_tls` *(intensity ≥ 2)* | workhorse |
| **VERITAS** | finding draft + evidence | `Verdict` | `re_read_source`, `request_evidence`, `check_gate` | **reasoning, different model** |
| **ARCHIVIST** | any | `Evidence`, `ReportSection` | `store_evidence`, `compose_report`, `build_timeline` | none (deterministic) |

Two design notes that matter:

- **RECON and ARCHIVIST use no model at all.** Manifest parsing is deterministic; using an LLM for it
  would add non-determinism, cost, and hallucination risk with zero benefit. This is a deliberate
  challenge to the master prompt's framing: not every "agent" should be an LLM.
- **VERITAS must run on a different model instance than SPECTRE, at temperature 0.** Using the same
  model to check itself produces correlated errors — it will agree with its own reasoning style. Model
  diversity is the cheapest real independence available when a second human reviewer is not in the loop.

## 6. Confirmation gates — the heart of false-positive control

A finding cannot be `CONFIRMED` unless its class gate passes. Gates are predicates in Layer 1,
declarative and testable.

| Class | Gate (all must hold) | Rationale |
|---|---|---|
| `exported-component-no-permission` | component is exported **and** no `android:permission` **and** no runtime caller check found by targeted inspection **and** a reachable privileged sink exists | Exported alone is not a vulnerability — most launchers are exported |
| `hardcoded-secret` | string/asset located **and** entropy + format check **and** not a placeholder/test value **and** the value is used in a security context (auth header, key init) | Most "secrets" from scanners are ad IDs or sample keys |
| `insecure-storage` | secret/PII written to external storage or world-readable file **and** write site confirmed in code **and** data is not encrypted first | Requires the *data* to be sensitive, not just the storage API |
| `weak-crypto` | algorithm identified (DES/RC4/ECB/MD5 for auth) **and** used for a security purpose (not a checksum) **and** key provenance known | MD5 for a file cache key is not a finding |
| `webview-rce-surface` | `addJavascriptInterface` reachable **and** `setJavaScriptEnabled(true)` **and** loaded content is attacker-influenceable | Otherwise it is dead code |
| `cleartext-transport` | cleartext permitted **and** a non-localhost endpoint is actually contacted **and** payload contains credentials/tokens | `usesCleartextTraffic` alone is a config smell |
| `exported-provider-path-traversal` | provider exported **and** `openFile` reachable **and** path not canonicalised **and** Uri is caller-controlled | |
| `dynamic-code-loading` | DEX/jar/APK loaded at runtime **and** source of bytes is network or external storage **and** no integrity check | Directly relevant to stager/dropper designs (`ORACLE_THREAT_INTEL.md`) |
| `implicit-intent-sensitive-data` | sensitive extra sent via implicit intent **and** no package/explicit component set | |
| `deeplink-unvalidated-input` | deep link parameter flows to a sensitive sink **and** no validation on the path | |

Each gate has: required evidence *types*, a code predicate, and a unit test with a positive and a
**negative** example. The negative examples are the point — they are what stop the tool from
becoming a scanner.

**Calibration rule:** severity (impact if true) and confidence (belief it is true) are independent
columns. A finding may be `severity=high, confidence=0.3` — and it must be displayed that way, never
averaged into a single "risk score". Averaging is how scanners manufacture false certainty.

## 7. Tool adapter contract

```python
class ToolSpec(BaseModel):
    name: str                      # "jadx.decompile_method"
    binary: str                    # resolved via config; absence → ToolUnavailable
    version_probe: list[str]       # e.g. ["jadx", "--version"]
    supports: frozenset[str]
    timeout_s: int
    max_memory_mb: int
    intensity_required: int = 0    # 0 = passive/static
    network: bool = False          # runner must block egress unless True
    input_model: type[BaseModel]
    evidence_kinds: tuple[str, ...]

class ToolAdapter(Protocol):
    spec: ToolSpec
    def invoke(self, args: BaseModel, workdir: Path) -> ToolResult: ...
```

**Non-negotiable rules** (NFR-SEC-1, NFR-SEC-2):

1. `subprocess.run(argv_list, shell=False)` only. The string `shell=True` is banned by a CI grep gate.
2. Every adapter validates `args` against `input_model` before touching a process.
3. The LLM can only choose from `spec.supports` and can only fill `input_model` fields; it cannot
   inject a binary path, a flag, or a shell metacharacter — because there is no path where a string
   becomes argv.
4. Timeout and memory limits are enforced by the runner (`resource.setrlimit` + a kill watchdog),
   not by the adapter.
5. Non-zero exit is a normal outcome → `ToolError(exit_code, stderr_tail)`, never an exception that
   kills the investigation (NFR-REL-1).

### 7.1 Version pinning

Tool behaviour changes between versions and silently changes findings. `tools.lock.yaml` pins
versions and the runner reports actual detected versions into every `ToolExecution` row. A report
without tool versions is not reproducible, and non-reproducible findings are not evidence.

## 8. Failure handling

| Failure | Handling | Event |
|---|---|---|
| Tool binary missing | Adapter returns `ToolUnavailable`; frontier drops entries needing it; investigation continues | `tool_unavailable` |
| Tool timeout | Kill process group; record partial stdout as evidence with `truncated=true` | `tool_timeout` |
| Tool crash (e.g. JADX OOM) | Retry once with smaller scope (single class, not whole APK); if it fails again, mark fidelity `decompiler-failed` | `tool_failed` |
| JADX cannot decompile a method | Fall back to smali; record `fidelity="smali"` | `fidelity_degraded` |
| LLM returns invalid JSON | Schema-repair loop, max 2 attempts, then deterministic fallback action | `planner_rejected` |
| LLM proposes unregistered action | Reject, log, pop next frontier entry | `planner_rejected` |
| Budget exceeded | `BUDGET_EXHAUSTED`, emit partial report | `investigation_updated` |
| Same action chosen 3× with no new evidence | Terminate branch, mark hypothesis `abandoned` | `hypothesis_updated` |
| Runner process dies | Worker detects lease expiry, requeues once, then `agent_error` | `agent_error` |

Every row above is a test case in `tests/fault_injection/`. This table is the test plan.

## 9. What the model is actually asked

Prompts are versioned artefacts (`mobius/agents/prompts/*.md`, hashed into every decision) so that a
finding can be traced to the prompt version that produced it. Each prompt:

- states the closed set of allowed actions,
- forces the output schema (JSON Schema emitted from Pydantic, not hand-written),
- requires evidence refs for every claim,
- permits `"insufficient_evidence"` as a first-class answer,
- gives 2–3 worked examples including a *negative* one (a pattern that looks suspicious but is not).

That last item is the highest-leverage prompt engineering available for false-positive reduction, and
it is cheap to iterate on because the eval harness in `MODEL_BENCHMARKS.md` scores it directly.

## Sources

- [S1] Production failure modes of unconstrained ReAct loops: https://blog.llmgo.top/en/articles/agent-loop-state-machine/
- [S2] ReAct vs Plan-and-Execute trade-offs (adaptivity vs cost/auditability): https://atlan.com/know/ai-agent/react-vs-plan-and-execute-agent-architecture/
- [S3] ReWOO / LLMCompiler style planning — motivation for separating planning from execution.
- [S4] OWASP MASWE weakness taxonomy (78 weaknesses) for gate → weakness mapping: https://mas.owasp.org/news/
