# ARCHITECTURE DECISIONS

**Status:** Proposed unless marked Approved
**Convention:** once approved, a decision is not silently changed. If new evidence invalidates it, a new
ADR supersedes it and states why (`master prompt §21`).

| ADR | Decision | State |
|---|---|---|
| 001 | Modular monolith, three entrypoints | Proposed |
| 002 | Tool plane is external and configurable | Proposed |
| 003 | Deterministic control flow, model-driven content | **Proposed (core)** |
| 004 | Agents are typed functions, not loops | **Proposed (core)** |
| 005 | Observation / hypothesis / decision are separate entities | **Proposed (core)** |
| 006 | Postgres adjacency tables, not a graph database | Proposed |
| 007 | Postgres as queue and event transport; no Redis | Proposed |
| 008 | No message broker, no Kubernetes | Proposed |
| 009 | Content-addressed, immutable evidence | Proposed |
| 010 | Two model tiers; VERITAS on a different model | Proposed |
| 011 | No agent framework (LangGraph/CrewAI) | Proposed |
| 012 | Confirmation gates as code predicates | **Proposed (core)** |
| 013 | MobSF via HTTP only (GPL boundary) | Proposed |
| 014 | v1 attack graph is a bounded reachability view | Proposed |
| 015 | Vertical slice over phase-by-phase build | **Requires Director approval** |
| 016 | A container runtime is required for the runner sandbox | Proposed |
| 017 | Pause is a flag, not an FSM state | Proposed |

---

## ADR-001 — Modular monolith with three entrypoints

**Problem.** Determine deployment granularity.
**Options.** (a) single process; (b) three processes from one codebase (api / worker / runner);
(c) microservices per agent or per tool.
**Decision.** (b).
**Rationale.** The API must stay responsive during long decompiles. The runner must be killable and
credential-free (threat model B4). The orchestrator must not import analysis libraries. All three needs
are met without independent versioning, service discovery, or network policy between services.
**Consequences.** One image, three commands. Layer boundaries enforced by import-lint tests, not by
network hops.
**Reversal cost.** Low — process split is a deployment concern, and the code is already layered.

## ADR-002 — Tool plane is external and configurable

**Problem.** JADX/Apktool/aapt2 need a JDK; the development sandbox has none
(`ENVIRONMENT_AUDIT.md` §4).
**Decision.** Tools are resolved from `tools.lock.yaml` + `MOBIUS_TOOL_PATHS` at runtime; absence
yields `ToolUnavailable`, never a crash.
**Rationale.** Decouples build environment from analysis environment — the only way this project can be
developed in one place and executed in another.
**Consequences.** Every adapter needs an availability test. The UI must show capability before a scan
starts (`API_SPECIFICATION.md` §3.5).
**Mitigation of the downside.** `GET /system/tools` is surfaced in the UI so the user never waits 20
minutes to discover PHANTOM was unavailable.

## ADR-003 — Deterministic control flow, model-driven content

**Problem.** Where does autonomy live, and how is it bounded?
**Options.** (a) pure ReAct loop; (b) full LLM planner; (c) FSM + persisted frontier + arithmetic
ranking, model supplies hypotheses and parameters.
**Decision.** (c).
**Rationale.** Unconstrained loops have documented failure modes — retry storms, context snowball,
dirty-state contamination, no rollback [S1]. An FSM gives bounded cost, replayability and an audit
trail; the model still provides the judgement that makes investigation non-trivial. Cost ceilings and
termination are then *guaranteed*, not hoped for.
**Consequences.** Some "agentic" freedom is traded for inspectability. The defence of the project
becomes "control is deterministic, judgement is model-driven" — a statement that can be pointed at in
code.
**Supersedes.** The master prompt's implicit ReAct framing.

## ADR-004 — Agents are typed functions, not loops

**Decision.** An agent is `(role prompt, tool allowlist, input schema, output schema, budget)` invoked
by the scheduler.
**Rationale.** Testability with a stub model; no cross-agent conversational state to corrupt; a failed
agent is a failed function call, not a stuck process.
**Consequences.** "Agent conversation" is expressed through the event log, not message passing. Some
reviewers may find this less agentic; it is more debuggable.

## ADR-005 — Observation, hypothesis, decision are separate entities

**Decision.** Three tables, three schemas.
**Rationale.** The master prompt's example message conflates them. Conflation is how a tool loses the
ability to distinguish what it saw from what it inferred from what it decided — the exact distinction
the project's credibility rests on.
**Consequences.** More tables; a schema-level guarantee that a `fact` has evidence and confidence
exactly 1.0 (`DATABASE_SCHEMA.md` §3.4).

## ADR-006 — Postgres adjacency tables, not a graph database

**Problem.** Represent the attack graph.
**Options.** Neo4j; Postgres adjacency + recursive CTE; in-memory graph rebuilt per request.
**Decision.** Postgres.
**Rationale.** ≤ ~5 k nodes per scan (measured estimate: 10³ observations, 5×10² nodes). Recursive CTEs
with a depth bound and `CYCLE` detection answer every required query (neighbourhood, path, filtering).
A second datastore introduces a consistency problem between the relational record and the graph — a real
cost for a hypothetical scale benefit.
**Reversal trigger.** If path queries exceed ~500 ms at 10 k nodes, revisit.

## ADR-007 — Postgres as queue and event transport; no Redis

**Problem.** Job dispatch + real-time events + replay.
**Options.** Redis pub/sub (as proposed in the master prompt); Redis Streams; Kafka; Postgres
`LISTEN/NOTIFY` + table + `SKIP LOCKED`.
**Decision.** Postgres.
**Rationale.** One datastore, transactional consistency between state change and event, replay from a
durable table, and `SKIP LOCKED` is a correct queue at this concurrency. Throughput requirement is tens
of events/second; Postgres handles thousands.
**Critical implementation note.** `NOTIFY` payloads are limited and may coalesce — so the notification
is a **wake-up hint only**, and subscribers read rows from `events`. Treating the notification as the
data is the bug that makes a live UI silently stop updating.
**Addendum (SSE vs WebSocket).** SSE provides reconnect + `Last-Event-ID` replay for free and is
sufficient for a server→client feed. WebSocket is retained only for the "ask NEXUS" interaction. If
schedule pressure appears, **switch to SSE** — recorded as a live option, not a failure.

## ADR-008 — No message broker, no Kubernetes

**Decision.** None.
**Rationale.** Both are operationally expensive and solve problems this project does not have. Adding
them would create the appearance of production-readiness without the substance.

## ADR-009 — Content-addressed, immutable evidence

**Decision.** `evidence.sha256` unique per scan; blobs immutable; corrections are new evidence + a
superseding reference.
**Rationale.** An evidence chain that can be edited is not an evidence chain. Deduplication is a
side-benefit.

## ADR-010 — Two model tiers; VERITAS on a different model

**Problem.** Per-agent routing (as proposed) vs simplicity.
**Decision.** Two tiers (`reasoning`, `workhorse`) plus `none` for deterministic agents. VERITAS must
not share SPECTRE's model; enforced at startup.
**Rationale.** Evaluating 8 agents × N models is infeasible in a semester; two tiers capture most of
the benefit. Model diversity is the cheapest available independence for validation — same-model
self-review produces correlated errors.
**Consequences.** Routing is coarse. A `--allow-self-review` escape hatch exists for experimentation but
stamps `self_review=true` on the verdict so it can never be mistaken for independent validation.

## ADR-011 — No agent framework

**Decision.** Direct provider API calls + a small FSM.
**Rationale.** The state model, the audit trail and the confirmation gates are the project's
contribution. LangGraph/CrewAI would own the first and complicate the second, while adding a dependency
whose internals the team does not control. The alternative is ~200 lines of explicit code that can be
inspected during a defence.
**Counter-argument acknowledged.** A framework would be faster to a working demo. It would also make
"why did it do that?" answerable only by reading framework internals.

## ADR-012 — Confirmation gates as code predicates

**Decision.** A finding reaches `CONFIRMED` only by satisfying a class-specific predicate over evidence.
**Rationale.** This is the single control that prevents the product from becoming a scanner, and it is
also the control that makes prompt injection non-catastrophic: an injected instruction cannot satisfy a
predicate (`THREAT_MODEL.md` §4, C5).
**Consequences.** Recall will be lower than a scanner's. That is the intended trade and must be measured
and reported.

## ADR-013 — MobSF via HTTP only (GPL boundary)

**Problem.** MobSF is GPL-3.0; MOBIUS may be distributed as a graduation artefact.
**Decision.** Integrate over HTTP as a separate service, for **cross-checking only**.
**Rationale.** Arm's-length HTTP interaction avoids creating a derivative work; importing its modules
would not. Additionally, MobSF's engine is largely JADX + Apktool + regex heuristics — the same signals —
so its value is as a *comparison baseline* for the false-positive evaluation, not as a dependency.
Same reasoning applies to Objection (GPL-3.0).

## ADR-014 — v1 attack graph is a bounded reachability view

**Problem.** Graph scope creep; React Flow performance; honesty about hypothetical edges.
**Options.** (a) full graph engine; (b) bounded neighbourhood API over a real graph model;
(c) component reachability tree only.
**Decision.** (b) in the data model, (c) in the v1 UI.
**Rationale.** The data model must be a real graph because edges carry assertion status and evidence —
that is the research contribution. The *UI* renders a reachability view for v1 because it answers the
same user question with a fraction of the interaction complexity. This reverses Specialist A's original
position on the basis of Specialist G's critique (`SPECIALIST_REPORTS.md §8`, reversal #2).

## ADR-015 — Vertical slice over phase-by-phase build

**Problem.** The master prompt's Phase 2→9 ordering builds breadth first and finishes with a system that
has never completed one investigation end-to-end.
**Decision (proposed, needs Director approval).** Build one complete investigation path first
(`ARCHITECTURE.md` §8), then widen.
**Rationale.** Integration risk is highest at the seams. A slice forces every seam to be crossed while
there is still time to fix it. It also produces something demonstrable at any point.
**Risk of the decision.** Less visible surface area at the mid-point review.
**Approval required.** This is a scope change relative to the master prompt and must not be made
unilaterally.

## ADR-016 — A container runtime is required for the runner sandbox

**Problem.** `ARCHITECTURE.md §9` selects "Docker + `nsjail`/`firejail`" for the runner, and
`NFR-SEC-2` verifies isolation via "compose inspection". `ENVIRONMENT_AUDIT.md` records that **Docker is
absent** from the current environment. No ADR made the dependency explicit, so the isolation claim rested
on an unrecorded assumption (A-07).

**Decision.** A container runtime is a **hard prerequisite for anything that touches an untrusted APK**.
Without one, the runner may still be used for trusted fixtures, and the isolation claim must be reported
as degraded wherever it appears — in the UI, in the report's methodology section, and in
`IMPLEMENTATION_STATUS.md`. It must not be silently assumed.

**Rationale.** Specialist G's critique is correct: process separation (`setrlimit` + unprivileged UID)
bounds resource exhaustion and filesystem damage, but it does **not** contain a code-execution
vulnerability in a decompiler — and a decompiler is a large native/JVM parser fed adversarial input by
design. Claiming otherwise would repeat the exact overstatement this project criticises in others.

**Consequences.** (a) `THREAT_MODEL.md` AR-1 is upgraded from "accepted residual risk" to "a residual risk
that becomes unacceptable once a container host is available and therefore must be fixed at that point".
(b) The `tools.lock.yaml` and `GET /system/tools` capability report gains a `sandbox` field so the
degradation is visible before a scan starts, not after. (c) The demo plan must not claim isolation that
the demo host does not provide.

**Reversal trigger.** None foreseen. The only way to relax this is to replace the container with a
stronger boundary (gVisor, microVM), which is a superset, not an exception.

**Related.** ADR-002 (configurable tool plane), R-01, A-07, `THREAT_MODEL.md` B4/AR-1.

## ADR-017 — Pause is a flag, not an FSM state

**Problem.** Three documents disagreed. `EVENT_ARCHITECTURE.md §7` said a pause puts the FSM in `PAUSED`
"a sub-state of `SELECTING`"; `DATABASE_SCHEMA.md`'s `state_known` CHECK did not include `PAUSED` and
would have **rejected** the row; `ARCHITECTURE.md`'s FSM had no pause transition at all. Meanwhile
`FR-NEXUS-7` requires pause/resume with fully persisted state and `API_SPECIFICATION.md` exposes
`/pause` and `/resume`.

**Options.** (a) Add `PAUSED` as a 16th state. Requires a `resume_to` column to remember where to return,
and roughly doubles the transition table because every state can be paused. (b) Make pause a flag:
`paused_at`, `paused_by`, `pause_reason`, with state untouched. (c) Derive it from the absence of a worker
lease.

**Decision.** (b).

**Rationale.** A paused investigation is not in a *different phase* — it is in the same phase, not
advancing. Modelling it as a state conflates "where am I in the workflow" with "is the workflow
temporarily stopped", and the cost of that conflation is a `resume_to` column plus a transition matrix
that must be maintained for every future state. The flag is one column, orthogonal by construction,
trivially indexable, and it composes with `AWAITING_APPROVAL` (a scan can be paused while awaiting
approval) — which the state model could not express without a second dimension anyway.

**Consequences.** `state_known` stays at 15 values. `pause_is_coherent` CHECK binds `paused_at` and
`paused_by` together. `pause`/`resume` emit `investigation_paused`/`investigation_resumed` but **no
`investigation_updated` state transition**, so a paused scan's state chip does not change. The API returns
`{state, paused}` so the client can render both facts independently.

**Addendum — `SCOPE_BLOCKED` is retained as a state.** It is genuinely a workflow outcome ("this scan may
not proceed"), not a temporary stop, and it exists so that a *refused* scan is still an auditable row
(AC-FR-AUTH-2). That is the distinction between the two: outcome vs interruption.

---

## Sources

- [S1] Enumerated failure modes of unconstrained agent loops: https://blog.llmgo.top/en/articles/agent-loop-state-machine/
- [S2] Postgres `NOTIFY` semantics (payload limit, coalescing): PostgreSQL documentation, "NOTIFY"
- [S3] GPL-3.0 implications for HTTP integration vs module import: FSF GPL FAQ, "Mere Aggregation"
