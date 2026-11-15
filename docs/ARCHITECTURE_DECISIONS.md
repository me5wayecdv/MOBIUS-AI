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
| 018 | JSON columns instead of Postgres arrays | Proposed |
| 019 | Explicit flush order; no ORM relationships | Proposed |
| 020 | RECON decodes AXML in-process with androguard | Proposed |
| 021 | SSE by polling the event table, not LISTEN/NOTIFY | Proposed |

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

## ADR-018 — JSON columns instead of PostgreSQL arrays

**Problem.** `evidence_refs`, `maswe`, `masvs` and `gate_evidence` are naturally `text[]` in Postgres.
The test suite and CI run on SQLite, which has no array type.

**Options.** (a) `ARRAY(Text)` with a SQLite variant; (b) JSON columns everywhere; (c) join tables for
every list; (d) skip SQLite and require Postgres for tests.

**Decision.** (b) — JSON.

**Rationale.** (a) is the tempting option and the worst one: two storage representations of the same
concept, so a bug can appear only on one backend and only in production. (c) would be correct
relationally but adds four join tables to a schema that is already the largest artefact in the project,
and the lists are read whole, never queried by element. (d) makes the domain tests depend on an external
service, which contradicts the Layer-1 purity goal the project is built around.

**Cost.** The database can no longer enforce that an element of `evidence_refs` exists. That is a real
loss: it is the one integrity property JSON gives up here.

**Mitigation.** An application-level check plus the FR-EV-3 dangling-reference test, which scans for
references to evidence rows that do not exist. `gate_evidence` is validated by Pydantic to `dict[str, bool]`
before it reaches the column, so the shape is still guaranteed.

**Reversal.** Moderate — a migration to `text[]` with a validation pass. Acceptable because the column
names and payload shapes would not change.

## ADR-019 — Explicit flush order instead of ORM relationships

**Problem.** The first working build of `IntakeService` failed with
`sqlite3.IntegrityError: FOREIGN KEY constraint failed`. Root cause, reproduced: SQLAlchemy orders INSERTs
using `relationship()` declarations, **not** foreign keys. With no relationships configured it emitted
`INSERT applications`, then `INSERT investigations`, and never emitted the pending `users` row at all —
so a parent vanished and a child violated the constraint.

**Options.** (a) add `relationship()` declarations so the unit of work sorts by dependency; (b) order
explicit flushes in the service; (c) disable `PRAGMA foreign_keys`; (d) drop ORM writes, use Core inserts.

**Decision.** (b).

**Rationale.** (c) is not a fix, it removes the detector — the same code would corrupt a Postgres
database silently. (a) works, but relationships bring cascade semantics, lazy-loading surprises and
implicit DELETE behaviour into a layer whose job is to store rows and nothing else; the mapping would then
drive domain decisions. (d) is more code for no additional safety. (b) makes the dependency order visible
at the call site (user → application/authorisation → investigation → event), keeps the mapping layer dumb,
and is what the tests exercise.

**Consequences.** Every service that writes more than one table must flush parents before children, and a
new table means reviewing its writers. Recorded here because the failure is silent-ish (a missing INSERT,
not a loud error) and would otherwise be "fixed" by adding relationships without knowing why.

**Diagnostic note for the next person.** `sort_tables_and_constraints` returns the correct order — that is
not evidence about the unit of work. Reproduce by adding rows in one `commit()` and reading the emitted
SQL with `echo=True`.

## ADR-020 — RECON decodes AXML in-process with androguard

**Problem.** RECON must read the binary `AndroidManifest.xml` inside an APK. The approved
architecture (ADR-002) puts analysis tooling behind an external, configurable tool plane,
because JADX and Apktool need a JDK that this environment does not have.

**Options.** (a) route manifest parsing through the external tool plane like every other
adapter; (b) special-case androguard as an in-process Python dependency; (c) write our own
AXML decoder; (d) extract the manifest with a remote service.

**Decision.** (b).

**Rationale.** The tool-plane rule exists to keep a killable, credential-free process around
*mutating* tools — decompilers, instrumenters, whatever executes against untrusted input.
androguard is a parser: pure Python, no subprocess, no JDK, no network, and it runs inside
the same request that already holds the APK bytes. Introducing a subprocess boundary here
would add a failure mode without adding isolation, since the parser reads a file the API has
already accepted. (a) would also make RECON un-runnable in an environment where the whole
point is that RECON *is* the runnable part. (c) duplicates a mature parser on a binary format
with a long tail of vendor quirks. (d) sends an attacker-supplied document to a third party.

**Consequences.**
- `androguard>=4.1` is a hard dependency. It is the only analysis tool in the dependency set.
- The domain never imports it: `core.manifest` holds the surface model, and
  `adapters.android_manifest` is the only module that touches androguard, so SPECTRE's
  JADX path can stay external without disturbing this one.
- **Documented quirk:** androguard's `AXMLPrinter` emits `xmlns:android="..."` but writes the
  attributes *without* the `android:` prefix. A strict `{uri}name` lookup therefore reads
  every Android attribute as absent, which makes a fully exported app look inert. The adapter
  falls back to the bare attribute name and a test pins the behaviour.
- The binary path is tested against a hand-encoded AXML fixture that androguard must also
  decode, because no sample APK exists in this environment.

**Reversal cost.** Low: the parser sits behind `parse_apk()`, returning a Layer-1
`ManifestSurface`. Swapping in JADX's XML output changes one adapter function.

## ADR-021 — SSE by polling the event table, not LISTEN/NOTIFY

**Problem.** The War Room needs a live event feed with resume-after-reconnect.

**Options.** (a) Postgres `LISTEN`/`NOTIFY` plus WebSocket; (b) SSE fed by polling
`events` with `seq > last`; (c) in-process pub/sub through a queue.

**Decision.** (b).

**Rationale.** (c) is wrong in a multi-process deployment and was rejected for the same
reason ADR-007 rejected Redis: the database already holds the ordering guarantee, and a
second bus can disagree with it. (a) is the better end state but is Postgres-only, which
would leave the stream untested in CI and unusable on the SQLite path a reviewer runs; it
also adds a listening connection per client. Polling keeps replay, ordering and the
`Last-Event-ID` contract identical on both backends, and it exercises the resume path
continuously rather than only after a real disconnect.

**Cost.** Up to one poll interval of latency (200 ms today) and one small query per interval
per connected client. Both are acceptable at the target scale (a handful of analysts).

**Consequences.** `GET /scans/{id}/stream` closes with a `stream_end` event once the
investigation is terminal and every event has been delivered, so clients stop reconnecting
without guessing. The `EventEmitter` port means a push transport can replace this without
touching callers. Revisit if concurrent viewers exceed ~50 or latency becomes a complaint.

---

## ADR-022 — SPECTRE decides reachability by graph search, with no model in the path

**Problem.** SPECTRE's job is to convert RECON's `insufficient_evidence` candidates into
gate evidence: is a sensitive sink reachable from an exported entry point without a caller
check? The design in the master prompt routes this through the model (decompile, ask, parse
the answer).

**Options.** (a) model reads the decompiled method and answers "reachable or not"; (b) a
deterministic bounded BFS over the call graph built from the dex; (c) hybrid — BFS to gather
candidates, model to adjudicate the ones BFS leaves open.

**Decision.** (b) for v1. (c) is the intended end state for the parts (b) cannot answer, but
(b) ships alone first.

**Rationale.**
1. *Determinism is a stated requirement.* The same APK must yield the same path and the same
   verdict or the audit trail is theatre. A model makes the verdict depend on sampler state,
   prompt order and provider version; a graph search depends on the dex bytes only.
2. *The question is not one a model answers better.* "Is there a call path from A to B" is a
   graph property, not a judgement call. Asking a model to compute it introduces variance
   with no gain in capability.
3. *It routes around blocker Q3.* Sending decompiled proprietary code to a third party is
   unresolved (R-09, ethics Q3). Reachability needs none of that, so the first capability
   that produces real evidence is also the one that needs no data-sharing decision.
4. *It produces the clauses the gate already consumes*, rather than a prose judgement the
   gate would have to trust.

**The rule that makes this honest — truncation is never refutation.** A bounded search that
finds nothing has learned nothing about what it did not look at. So `sink_reachable` is
`True` only on a found path, and `False` **only** when the traversal completed *and*
`CodeIndex.truncated` is false. Every other outcome — node budget exhausted, no entry point
matched, class absent, dex unparseable — is `None`, which the gate treats as missing
evidence (`Clause.absence_is_evidence`, ADR-018's gate machinery), never as a failed clause.
A partial search therefore reports `insufficient_evidence`; only an exhaustive one may
produce `not-reached` → `REJECTED`.

**What the search deliberately cannot see.** No data flow: reachability to a *sink
invocation* is not proof that attacker-controlled data reaches it. No CFG: a guard anywhere
in the same method counts, even if it executes after the sink (conservative — it biases
toward not confirming, recorded as R-21). No reflection, no obfuscated dynamic dispatch, no
framework internals (the graph holds application classes only, so the search cannot walk
the framework and manufacture a path). These are false-negative sources, and they are why
the sink catalogue was tightened mid-development: `SharedPreferences.getString` and
`Context.startActivity` were removed after a real APK produced a "confirmed" finding whose
only content was an exported receiver reading its own preference. Reachability without data
flow cannot distinguish that from exfiltration, so the catalogue only admits operations
whose execution is itself security-relevant.

**Cost.** The verdict is weaker than a real data-flow analysis and will miss findings a
taint tracker would catch. It is reported as `insufficient_evidence` with the reached
methods, so an analyst can finish the job by hand, and the model-backed pass over exactly
those methods remains the plan.

**Consequences.** SPECTRE's confidence values are capped at 0.95 and the gate can reject but
only the *complete* absence of a path — never "looks safe". `method_names` are matched
without descriptors because real `onReceive(Context,Intent)V` does not match an empty
descriptor, which the first real APK exposed.

---

## ADR-023 — NEXUS is a deterministic dispatcher, not an adaptive planner

**Problem.** Something has to move an investigation from RECON's queue of candidates to a
closed, reported scan. The master prompt and `AGENT_DESIGN.md` describe an agent that picks
work, observes the result, and *re-plans* when the result is uninformative.

**Options.** (a) a model-driven planner that scores and re-scores the frontier as evidence
arrives; (b) a deterministic dispatcher over the arithmetic scorer in `core/frontier.py`; (c)
no loop - each tool invoked by hand through its own endpoint.

**Decision.** (b), named precisely as a dispatcher.

**Rationale.**
1. *Re-planning is the only part that needs a model, and no model is called in this build.*
   Building (a) now would mean either a stub that pretends to plan, or a live dependency on a
   provider key that does not exist here (R-14) and an unresolved ethics decision about
   sending decompiled proprietary code to a third party (R-09, Q3).
2. *The parts that matter are deterministic.* Ranking is arithmetic, the dispatch table is a
   dict, and the step budget is a counter. That makes the whole loop replayable: the same APK
   with the same budget produces the same dispatch order and the same verdicts - verified by
   running the same scan twice and comparing, not by assertion.
3. *This resolves escalated disagreement C-5 by conceding it.* The frontier is best-first
   search with a hand-written objective, not adaptive planning. The status file now says so,
   and so does the response body.

**The budget is a stop, not a hint.** `max_steps` bounds dispatches. When it is reached the
FSM moves to `BUDGET_EXHAUSTED`, the remaining entries stay `queued`, and the response and
`nexus_complete` event both name them. A loop that cannot say what it skipped is not
auditable, and a budget that is quietly ignored during a demo is worse than none.

**What it refuses to fake.** A frontier entry whose agent does not exist in this build
(PHANTOM, VECTOR, ORACLE, ARCHIVIST) is marked `dropped` with the reason. Entries forbidden
by the current intensity are dropped with *that* reason, which is the decisive one: an
analyst can widen an authorisation, but cannot conjure PHANTOM. Nothing is silently skipped
and nothing is counted as done.

**Cost.** The loop cannot discover work that no tool queued for it. If RECON enqueues one
candidate, one candidate is dispatched, and no amount of stepping will find a second. This is
the honest ceiling of the current build: coverage grows with the tools that enqueue work, not
with the loop.

**Consequences.** `POST /scans/{id}/nexus` owns the path from `SURFACE_READY` to `CLOSED`,
including the `code_analysis_complete` event the stream contract expects, whoever drove the
analysis. The single-shot `POST /spectre` remains for targeted code analysis. The model-driven
planner is phase 5 work and is **not implemented** - `IMPLEMENTATION_STATUS.md` says so.

---

## ADR-024 — Presentation is generated from rows, and an unmeasured benchmark reports nothing

**Problem.** Three things now face a reader rather than a program: the investigation report, the
War Room UI, and the benchmark's precision figure. Each is a place where a plausible-looking
number or sentence could be composed that no row supports.

**Options.** (a) author the report as a template with analysis written into it at run time;
(b) generate every section from stored rows and refuse sections the rows cannot fill;
(c) leave reporting and measurement to whoever writes the dissertation.

**Decision.** (b) for all three artefacts.

**Rationale.**
1. *The report is evidence, so it is stored as evidence.* It is generated from findings,
   verdicts, observations, frontier entries and the event log, then written through
   `EvidenceService` and content-addressed. A reader can tell which document the scan produced.
   The "not determined" section is not prose an author writes; it is the list of findings in
   manual review, observations whose reachability was never established, and frontier entries
   that never ran - each with its stored reason.
2. *The UI reads the API and nothing else.* One static document, no framework, no fixture. Its
   event panel replays `/events` rather than listening for a hardcoded list of event names,
   because a listener list is a UI deciding which parts of the truth it will show.
3. *A benchmark with no corpus reports `measured: false`.* Reporting `precision: 1.0` over an
   empty sample set is the exact failure mode the claims audit exists to prevent, and it is the
   easiest one to ship by accident. Rates are `None` when their denominator is zero, and a
   sample that failed to analyse is counted as `error`, never as a correct rejection.
4. *Labels need a basis.* A sample without a recorded note about who labelled it and why is
   refused, because an unlabelled "benign" is a guess, and a guess multiplied by a corpus size
   becomes a precision figure.

**Cost.** The report reads more like a ledger than like a narrative, and it cannot say things a
human would want it to say ("this looks like a credential leak"). That is the trade: the
narrative layer belongs to the analyst, and the document gives them the facts to write it.

**Consequences.** `POST /scans/{id}/report` writes the document (NEXUS writes one at closure),
`GET /scans/{id}/report` returns the stored Markdown, `GET /scans` lists investigations so a UI
never hardcodes an id, and `python -m mobius.tools.benchmark corpus.json` exits non-zero when a
benign control is flagged. Every rate it prints is accompanied by the counts it came from.

---

## ADR-025 — Migrations from the first deploy, and the trigger ships with them

**Problem.** The schema was created with `Base.metadata.create_all()`. That is fine for tests
and fatal for a deployed database: there is no history, no ordering, and no way to know whether
a database matches the models.

**Options.** (a) keep `create_all` and document it as dev-only; (b) Alembic with autogenerated
revisions, keep `create_all` for tests, and make CI prove the two agree; (c) hand-written SQL
migrations.

**Decision.** (b).

**Rationale.**
1. *Tests build their database with `create_all`, so they would never notice drift.* That is the
   real risk, and it is closed by a test that builds a database **only** through
   `alembic upgrade head` and then runs `alembic check`, which fails when a model change has no
   migration. Without that check, "we have migrations" means "we have files".
2. *The connection string is the application's.* `MOBIUS_DB_URL` is read the same way the API
   reads it; `env.py` refuses to run without it. A migration tool with its own URL is how a
   deploy migrates one database and serves another.
3. *The authorisation trigger is applied by the migration on PostgreSQL and skipped elsewhere,
   out loud.* The trigger has never been executed — there is no PostgreSQL server here (Q2) —
   and the migration says so rather than implying the guarantee holds everywhere. SQLite gets
   the service-layer check only, which is why production runs Postgres.
4. *Rollback is tested.* A migration history that cannot be undone is a one-way door on a
   schema the project will certainly revise.

**Cost.** `alembic` becomes a runtime dependency, and `render_as_batch` makes SQLite migrations
recreate tables rather than alter them. Acceptable: the dev database is disposable, and batch
mode is what keeps the history usable on both backends.

**Consequences.** `alembic upgrade head` builds the schema; `tests/test_migrations.py` asserts
the full table set, no drift, a clean downgrade to base, and that a replay (upgrade → base →
upgrade) works. `create_all` remains for the fast test path, with the drift check standing
guard.

---

## Sources

- [S1] Enumerated failure modes of unconstrained agent loops: https://blog.llmgo.top/en/articles/agent-loop-state-machine/
- [S2] Postgres `NOTIFY` semantics (payload limit, coalescing): PostgreSQL documentation, "NOTIFY"
- [S3] GPL-3.0 implications for HTTP integration vs module import: FSF GPL FAQ, "Mere Aggregation"
