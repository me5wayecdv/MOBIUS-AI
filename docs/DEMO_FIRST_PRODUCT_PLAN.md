# MOBIUS — Demo-First Product & Engineering Plan

**Status:** Project Director direction recorded; implementation plan for the graduation-project demonstration.
**Baseline:** main at `669ecd54730fd491a1b184a2d295fa9415821c91` (verify before implementation).
**Product outcome:** an evidence-driven Android security investigation agent that analyzes an authorized APK, inspects the supported codebase, forms and correlates security hypotheses, executes safe reproducible proofs of concept in a controlled lab, validates results, and produces a reviewable report. The War Room exposes the real investigation as it happens.

## 1. Product definition

MOBIUS is not a scanner with an LLM summary and not a dashboard that simulates agents. Its core deliverable is one complete investigation loop:

1. Intake an APK and bind the investigation to explicit authorization and the APK SHA-256.
2. Inventory and index the application: manifest, all supported DEX files, resources/strings, certificates, native libraries, and decompiled source where available.
3. Build navigable code intelligence: classes, methods, call edges, entry points, sensitive operations, source references, and (where supported) control/data-flow.
4. Generate evidence-backed observations and testable hypotheses.
5. Let NEXUS choose the next bounded investigation action from the actual observations, evidence, available tools, and remaining budget.
6. Correlate findings into candidate attack paths. A relationship is a hypothesis until its preconditions and exploitability are validated.
7. Execute a safe, scoped PoC/test plan against a lab APK/emulator or local test harness. Capture reproducible inputs, outputs, logs, and environment details.
8. Have VERITAS independently challenge the claim and evidence. Deterministic gates remain the authority for status transitions.
9. Generate a report containing findings, evidence, code locations, attack paths, PoC steps/results, remediation, coverage, and explicit unknowns.
10. Stream the real events to the War Room. Every visual activity must be backed by a persisted backend event or an explicitly labelled capability state.

## 2. Graduation-demo scope

### Must work in the demonstration
- APK upload, SHA-256 identity, authorization binding, and investigation creation.
- RECON inventory and manifest/component analysis.
- Multi-DEX inventory and indexing (all DEX entries discovered; unsupported or failed entries explicitly reported).
- Source/code navigation for the supported analysis path; JADX integration when the host has a JDK.
- At least a useful set of Android security checks with evidence and positive/negative fixtures.
- Call graph and initial data-flow tracking for selected high-value source/sink families; never label reachability alone as proof of tainted input.
- NEXUS hypothesis/action planning using a provider abstraction and typed, allowlisted tools. Deterministic fallback must be labelled as fallback, not AI.
- Finding correlation and an attack-path graph with explicit edge semantics (observed, inferred, validated).
- A controlled PoC runner for non-destructive tests on the project's own intentionally vulnerable demo APK / emulator or harness.
- Independent VERITAS review or a clearly labelled deterministic validation-only fallback if no second model is configured.
- ARCHIVIST report generation from persisted evidence.
- War Room showing actual agents, current task, source file/method, tool execution, observations, hypotheses, decisions, validation, PoC result, and report status.
- Replay of the same real event stream after refresh/reconnect.

### Implement only if it materially improves the one-hour defence
- PHANTOM runtime instrumentation against a prepared emulator.
- VECTOR API/network inspection against a controlled local test backend.
- A PDF export if Markdown/HTML report print is insufficient.
- Additional analysis categories beyond the demo APK's deliberately chosen vulnerability scenarios.

### Explicitly deferred (not graduation-demo requirements)
- Public multi-tenant SaaS, billing, enterprise SSO, high availability, autoscaling, Kubernetes, distributed microservices, managed model routing, production operations and extensive account administration.
- Full support for every Android obfuscator, every native-code pattern, arbitrary reflection resolution, complete framework modeling, or mathematically complete taint analysis.
- ORACLE/C2 research UI, multi-model voting, model fine-tuning, unrestricted exploit generation, destructive testing, stealth, persistence, credential theft, or covert exfiltration.

## 3. Honest coverage contract

"Analyze all code" means MOBIUS must enumerate every code container it recognizes and report coverage, not promise perfect semantic understanding.

The analysis manifest must include:
- APK SHA-256 and package/version identity.
- Every `classes*.dex` entry discovered, indexed, skipped, or failed, with reason.
- Java/Kotlin decompilation coverage where JADX is available, including failed classes and fidelity.
- Native libraries and assets discovered, and whether each is analyzed or inventory-only.
- Class/method counts, call-graph node/edge counts, truncation flags, and analysis budgets.
- Unsupported constructs/limitations: reflection, dynamic loading, obfuscation, native boundaries, framework gaps, unresolved dispatch, and parse failures. The D-016 manifest is exposed at `GET /api/v1/scans/{scan_id}/coverage-manifest` and embedded as JSON in ARCHIVIST; it distinguishes `inventory_only`, `unsupported`, `not_run`, `partial` and `complete` rather than implying semantic coverage from file discovery.

A partial or truncated analysis is never presented as complete. "No finding" is not "safe".

## 4. Agent responsibilities

| Agent | Graduation-demo responsibility | Truthful status rule |
|---|---|---|
| NEXUS | Build hypotheses, choose next action, dispatch allowlisted tools, re-plan from results | Show model/provider and planner mode; deterministic dispatcher is not autonomous reasoning |
| RECON | Package, manifest, components, permissions, DEX/native/resource inventory | Facts cite artifact evidence |
| SPECTRE | Code indexing, code search, call/data-flow queries, security hypotheses | Distinguish syntactic match, reachability, taint, and validated exploitability |
| PHANTOM | Optional emulator/runtime observation and safe PoC execution | Only active when emulator/tool is detected and test plan is approved |
| VECTOR | Optional scoped API/network tests against an authorized lab target | No arbitrary external target or unrestricted egress |
| VERITAS | Independent adversarial review of candidate findings and PoC evidence | Record reviewer identity/model/version; deterministic gates remain final |
| ARCHIVIST | Evidence index, coverage, findings, attack paths, PoC result and report | Generate only from persisted records |

## 5. War Room product requirements

The War Room is an investigation cockpit, not a generic admin dashboard.

### Main layout
- **Mission header:** APK name/package, SHA-256 short form, investigation state, elapsed time, stop/cancel controls.
- **Agent network:** one card per real agent with idle/queued/running/waiting/completed/failed state, current task, and last event time.
- **Investigation timeline:** append-only live feed with agent, action, target, result, evidence references and timestamp.
- **Code investigation studio:** file/class/method navigator, source or smali view, highlighted source ranges, call path and evidence panel.
- **Attack graph:** nodes for components, methods, APIs, data sources/sinks and findings; edge labels distinguish observed/inferred/validated.
- **Hypothesis & finding inspector:** claim, origin evidence, required proof, satisfied proof, severity, confidence, verdict and reviewer.
- **PoC lab:** test plan, approval state, execution status, inputs, outputs, logs, reproducibility and cleanup status.
- **Coverage panel:** indexed/total DEX, decompiled/failed classes, analyzed/unsupported surfaces, truncated paths and tool availability.
- **Report panel:** generation state and report access.

### Visual and interaction direction
Premium dark research command center, restrained color, strong typography, dense but readable data, subtle motion only for real state changes. Avoid generic SaaS cards, decorative charts, fake terminal typing, fake scan percentages, simulated parallel agent activity, or invented findings.

### Event contract
At minimum: `investigation_started`, `agent_queued`, `agent_started`, `agent_waiting`, `agent_completed`, `agent_failed`, `tool_started`, `tool_completed`, `observation_created`, `hypothesis_created`, `decision_recorded`, `code_location_inspected`, `attack_path_updated`, `approval_requested`, `approval_resolved`, `poc_started`, `poc_completed`, `finding_created`, `finding_validated`, `finding_rejected`, `report_generated`, `coverage_updated`, `investigation_completed`.

Events must describe completed or currently executing backend work. Do not emit future-tense or cosmetic events as if work occurred.

## 6. Engineering sequence — vertical slices

### Slice A — Real code intelligence (first)
- Discover all DEX entries; index each independently and aggregate with provenance.
- Add JADX adapter and decompilation cache keyed by APK digest + tool version.
- Build class/method/source-reference index and sensitive API catalogue.
- Add method-level call graph and bounded CFG/data-flow for a small, testable set of source/sink families.
- Persist coverage and unsupported reasons.
- Add fixtures for multidex, overloaded methods, callbacks, guard ordering, reflection boundaries, malformed DEX, and known positive/negative flows.

**Acceptance:** a prepared APK has every DEX enumerated; supported DEX files indexed; source locations resolve; coverage explains every omission; positive and negative data-flow fixtures pass.

### Slice B — Model-backed reasoning and NEXUS
- Add ModelGateway provider interface with structured JSON/schema validation, timeouts, token/call budgets and deterministic mock provider for tests.
- SPECTRE produces bounded evidence packages, not whole-repository prompt dumps.
- NEXUS proposes only typed actions from a closed registry; validate target IDs, authorization, budget, tool availability and prerequisites before dispatch.
- Record model/provider/version, prompt version, inputs, outputs, decisions, rejected alternatives and uncertainty.
- Re-plan only from newly persisted observations/results. Never let model prose directly create a confirmed finding.

**Acceptance:** on a fixed fixture, NEXUS creates a hypothesis, selects a code inspection action, consumes its result, changes its next action based on that result, and stops at budget. Invalid/out-of-scope model actions are rejected and audited.

### Slice C — Correlation and attack paths
- Persist graph nodes/edges and provenance.
- Correlate shared components, data sources, sinks, permissions, caller checks and API endpoints.
- Label edges observed/inferred/validated; track prerequisites and confidence independently.
- Detect candidate chains; do not infer exploitability from adjacency alone.

**Acceptance:** a known multi-step fixture produces the expected candidate path; removing a required edge breaks the chain; graph can be reconstructed from evidence.

### Slice D — Safe PoC lab and validation
- Define PoC/TestPlan schema: target APK digest, authorization scope, hypothesis IDs, prerequisites, actions, expected result, safety class, budgets, cleanup, evidence outputs.
- Only permit allowlisted non-destructive tests on the prepared intentionally vulnerable APK, emulator, or local harness.
- Require approval for any test that changes state, accesses sensitive data, or interacts with a live service.
- Capture exact command/tool version, inputs, timestamps, stdout/stderr, logcat/network artifacts, expected/actual result and exit status.
- VERITAS reviews evidence independently; deterministic gate predicates decide verdict.

**Acceptance:** at least one intentionally vulnerable lab scenario has a reproducible PoC with captured evidence; a negative control does not confirm; all tests stay inside the configured lab boundary.

### Slice E — War Room and report
- Replace the current basic page with the complete investigation cockpit described above, retaining existing API contracts where possible.
- Add APIs for code index, source excerpts, hypotheses, decisions, graph, coverage and PoC records.
- Build event-driven updates and replay from durable event storage.
- Add browser-level test for a real fixture investigation.
- Report findings, attack path, evidence, PoC result, remediation, coverage and unknowns.

**Acceptance:** run one complete fixture investigation; every visible agent/task/file/graph/PoC state is traceable to API data/events; refresh preserves the timeline; report agrees with persisted findings.

## 7. One-hour defence plan

| Segment | Time | What the committee sees |
|---|---:|---|
| Problem and architecture | 5 min | Why scanner output is insufficient; MOBIUS investigation loop |
| APK intake and coverage | 5 min | Upload, identity, authorization, code inventory |
| Autonomous code investigation | 15 min | Agents inspect code; NEXUS changes plan based on evidence |
| Correlation and attack path | 8 min | Individual weaknesses become a candidate chain |
| PoC and validation | 10 min | Safe test execution, evidence, independent challenge |
| War Room and report | 7 min | Real-time events, code references, final report |
| Evaluation, limitations, Q&A | 10 min | Positive/negative controls, coverage, known gaps |

Prepare a recorded run of the same real investigation as a fallback. Label it "recorded run"; never blend recorded data with a live scan.

## 8. Release and safety boundaries

This is a graduation-project prototype, not a public production service. Production features are deferred. Safety controls remain mandatory:
- Explicit authorization bound to exact APK SHA-256.
- Use the project's own lab APKs and controlled targets.
- No arbitrary shell execution from model output.
- Closed tool/action allowlist and validated typed arguments.
- Bounded file size, archive expansion, CPU, memory, time and output.
- No unrestricted network access; lab-only network targets.
- Approval for state-changing or sensitive PoCs.
- Cancellation and persisted audit trail.
- Treat APK contents, source comments, strings and model-visible artefacts as untrusted prompt-injection input.
- Findings require evidence; LLM output alone is never proof.

## 9. Definition of done for the graduation project

The project is ready for defence when the team can demonstrate, on a pinned and reproducible lab APK:
1. APK and code coverage inventory with honest limitations.
2. A model-backed investigation that adapts at least once based on new evidence.
3. A real code path and evidence-backed security hypothesis.
4. A correlated candidate attack path.
5. A safe, reproducible PoC with positive and negative control.
6. An independently reviewed result or explicitly labelled fallback.
7. A report that another reviewer can reproduce and audit.
8. A War Room whose activity is entirely grounded in real backend events.
9. A benchmark and limitations statement that does not overclaim recall or completeness.


## 10. Visual and browser acceptance gates

- D-033 and every War Room panel D-050–D-055 require real screenshots from a seeded investigation at 1280px desktop and 390px mobile. The screenshots are uploaded as a CI artifact; a human project-owner review is mandatory. A green build is not visual acceptance.
- D-056 is a Playwright browser-level run on one deterministic fixture: upload → investigation → evidence → graph → PoC → report. The test captures a screenshot after each stage and verifies the complete persisted event sequence is identical after reload.
- The CI fixture's PoC harness is explicitly synthetic. It proves UI/API/persistence integration, not APK runtime exploitability or real-device execution.
