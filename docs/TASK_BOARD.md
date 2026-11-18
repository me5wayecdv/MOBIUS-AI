# MOBIUS TASK BOARD — GRADUATION DEMO

**Product direction:** evidence-driven autonomous Android security investigation with a live War Room.
**Execution strategy:** demo-first; production-only infrastructure is deferred.
**Detailed product contract:** [DEMO_FIRST_PRODUCT_PLAN.md](DEMO_FIRST_PRODUCT_PLAN.md)
**Legend:** `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked · `[-]` deferred

## Current verified baseline

- Backend vertical slice exists: APK intake, SHA-256 authorization binding, binary manifest parsing, multi-DEX indexing with per-entry coverage/provenance, bounded application call-graph reachability, deterministic gates, NEXUS dispatcher, SSE replay, Markdown report. Isolated manifest and DEX worker job paths are implemented. The DEX OCI image is published and passed its real-DEX smoke test (PR #32); deployment on a dedicated worker host remains pending.
- Existing War Room is a basic HTML page reading API data. It is not the intended final investigation cockpit.
- A local Ollama/structured-output provider boundary and deterministic mock implement the core ModelGateway port (PR #33). NEXUS hypothesis generation (PR #35) and D-026 VERITAS review (PR #39) use the investigation-bound gateway only with explicit per-investigation consent; deterministic fallback remains the default.
- No full decompilation workflow, CFG/taint analysis, model-driven adaptive NEXUS, PoC runner, persisted attack graph, PHANTOM, or VECTOR. D-026 VERITAS independent review is being implemented on PR #39; it is advisory and not yet wired into the scan pipeline. The DEX OCI worker image smoke test passed; dedicated worker deployment remains pending.
- Latest documented audit and status files must be reconciled to current main before using them as live status.

## Priority 0 — Establish reproducible demo target

| # | Task | Owner | State | Acceptance |
|---|---|---|---|---|
| D-001 | Select one intentionally vulnerable Android APK owned by the team | Director + Android team | [ ] | APK, source, package, version and SHA-256 pinned |
| D-002 | Define 2–3 demonstration vulnerability scenarios | Director + M2 + M5 | [ ] | Each has source location, expected evidence, positive and negative control |
| D-003 | Confirm host capabilities: JDK/JADX, Android SDK, emulator/KVM, Docker | Director | [ ] | Tool availability recorded; no assumed capabilities |
| D-004 | Freeze demo-only scope and fallback recording | All | [ ] | One reproducible live run plus labelled recorded fallback |

## Priority 1 — Full code intelligence (first engineering slice)

| # | Task | Owner | State | Acceptance |
|---|---|---|---|---|
| D-010 | Verify APK multi-DEX enumeration and add per-entry coverage/provenance | M2 | [~] | Implemented parser coverage; isolated `dex_index` queue/image/worker path added on PR branch. Validate against a real multidex APK and deployed worker before marking done |
| D-011 | Harden multi-DEX aggregation and provenance | M2 | [~] | Parser tests cover provenance, duplicate classes, malformed secondary DEX, and budget truncation; worker payload round-trip and APK digest binding added. CI and published-image smoke tests passed (PR #32); dedicated worker deployment smoke test remains |
| D-012 | Add JADX adapter and cache by APK digest/tool version | M2 | [ ] | Source/decompiled references resolve; failures explicit |
| D-013 | Build class/method/source lookup APIs | M1 + M2 | [ ] | War Room can navigate to actual code locations |
| D-014 | Add Android sensitive source/sink catalogue | M2 + M5 | [ ] | Catalogue has MASWE/MASVS mapping and positive/negative tests |
| D-015 | Add bounded CFG/data-flow for selected source/sink families | M1 + M2 | [ ] | Tainted/untrusted input tracked to selected sensitive sinks; guard order considered |
| D-016 | Add code coverage/limitations manifest | M1 + M2 | [ ] | Report discloses unsupported reflection/native/obfuscation/truncation |

## Priority 2 — Autonomous reasoning and investigation

| # | Task | Owner | State | Acceptance |
|---|---|---|---|---|
| D-020 | Model provider abstraction + structured output validation | M1 | [~] | Local Ollama and deterministic mock share the core ModelGateway port; consent, JSON Schema validation and token accounting are tested. Live Ollama execution and NEXUS integration remain |
| D-021 | Evidence package builder for targeted code context | M1 + M2 | [~] | PR #34 merged with bounded component-scoped observations, method/caller references, sink/guard references, findings and evidence provenance. Actual decompiled source snippets remain blocked on D-012/JADX; do not mark complete until included and tested |
| D-022 | NEXUS hypothesis generation | M1 | [~] | PR #35 merged; Python 3.11/3.12 CI green. Structured model-backed hypotheses cite only packaged observation IDs and declare required evidence; deterministic fallback remains default and explicitly labelled. No tool dispatch or PoC execution from model output. Real Ollama run/model quality benchmark remains unverified |
| D-023 | Typed action registry and policy validation | M1 | [~] | PR #36 merged; Python 3.11/3.12 CI green. Closed SPECTRE action allowlist, strict Pydantic argument schemas, agent/intensity checks and API schema discovery. |
| D-024 | Adaptive re-planning loop | M1 | [x] | PR #37 merged; reachable sink results create a typed `callers_of` follow-up for the sink-bearing method, persist a decision/event, and dispatch through the closed registry. Deterministic policy, not model-generated. Python 3.11/3.12 CI green. |
| D-025 | Persist model/provider/version, prompt version and decisions | M1 | [~] | NEXUS model hypothesis decisions persist provider, requested/actual model, role, prompt version, prompt/input/schema/response SHA-256, schema name, validated structured output, token usage, latency and generation parameters. Deterministic fallback remains explicitly labelled and records no provider/model. Broader decision producers and replay UI/API remain. |
| D-026 | Independent VERITAS review | M1 + M5 | [~] | PR #39 adds a separate advisory reviewer using a different requested and provider-resolved model, explicit per-investigation consent, the cumulative token gateway, evidence-reference confinement, and persisted DecisionRow/event provenance. Deterministic validation gates remain the sole verdict authority. Pipeline/UI integration and real Ollama quality validation remain. |

## Priority 3 — Correlation and attack graph

| # | Task | Owner | State | Acceptance |
|---|---|---|---|---|
| D-030 | Persist graph nodes and edges | M1 | [x] | PR #40 merged. Four normalized graph/evidence tables, composite same-investigation FKs, dedicated `ged_` edge IDs, and additive idempotent projection from persisted observations/findings/evidence. Python 3.11/3.12 + PostgreSQL 16 CI green (439 tests each). |
| D-031 | Correlate component, caller, data source, sink and permission evidence | M1 + M2 | [x] | PR #41 merged. Direct component/method/permission/source/sink/guard relations carry evidence refs and assertion levels; no source nodes are invented without persisted source observations. Python 3.11/3.12 + PostgreSQL 16 CI green (441 tests each). | Relations carry provenance and edge type |
| D-032 | Build candidate attack-chain reasoning | M1 + M5 | [x] | PR #42 merged. Bounded candidates persist as hypothesis graph nodes with ordered steps, prerequisites and missing proof. Taint propagation and runtime reproduction remain explicitly unproven. Python 3.11/3.12 + PostgreSQL 16 CI green (444 tests each). | Candidate path has explicit prerequisites and missing proof |
| D-033 | Attack graph API and React Flow view | M6 | [~] | PR in progress: owner-scoped graph read/rebuild APIs, React Flow UI, assertion/provenance inspector and candidate proof gaps. | Observed/inferred/validated edges visually distinct |

## Priority 4 — Safe PoC lab

| # | Task | Owner | State | Acceptance |
|---|---|---|---|---|
| D-040 | Define typed PoC/TestPlan schema | M1 + M3 | [ ] | Target digest, scope, hypothesis, steps, expected outcome, budgets and cleanup |
| D-041 | Implement allowlisted non-destructive test adapters | M3 | [ ] | Only prepared lab APK/emulator/local harness targets |
| D-042 | Capture reproducible PoC evidence | M1 + M3 | [ ] | Tool version, inputs, outputs, logs, timestamps and exit status persisted |
| D-043 | Add approval, timeout, cancel and cleanup paths | M1 + M3 | [ ] | Out-of-scope or state-changing tests blocked without approval |
| D-044 | Positive and negative PoC integration tests | M3 + M5 | [ ] | Positive reproduces; negative control does not confirm |

## Priority 5 — War Room (real backend activity only)

| # | Task | Owner | State | Acceptance |
|---|---|---|---|---|
| D-050 | Mission header and investigation coverage panel | M6 | [ ] | APK identity, scan state, tool/coverage limitations shown |
| D-051 | Agent network with real lifecycle states | M6 + M1 | [ ] | Every state comes from persisted backend events |
| D-052 | Investigation timeline with replay/reconnect | M6 + M1 | [ ] | Refresh does not lose events; no simulated activity |
| D-053 | Code Investigation Studio | M6 | [ ] | Real source/DEX references, selected method and evidence |
| D-054 | Attack graph and hypothesis inspector | M6 | [ ] | Edge semantics and proof state visible |
| D-055 | PoC Lab panel and report viewer | M6 + M1 | [ ] | Real execution records and report |
| D-056 | Browser-level E2E for the complete demo | M6 + All | [ ] | Upload → investigation → evidence → PoC → report works |

## Priority 6 — Optional capabilities

| # | Task | Owner | State | Condition |
|---|---|---|---|---|
| D-060 | PHANTOM emulator/runtime adapter | M3 | [-] | Implement only if host has working emulator/KVM and it improves demo |
| D-061 | VECTOR API/network adapter | M4 | [-] | Implement only against the controlled lab backend |
| D-062 | PDF export | M6 | [-] | Only if report print/Markdown is insufficient |
| D-063 | Broader vulnerability catalogue | M2 + M5 | [-] | After the end-to-end slice is reliable |

## Deferred — not graduation-demo blockers

- Multi-tenant SaaS, billing, enterprise SSO, Kubernetes, autoscaling, HA, distributed microservices.
- Production identity provider and enterprise administration.
- Redis, graph database, fine-tuning, multi-model voting, ORACLE/C2 research UI.
- Arbitrary exploit generation, destructive tests, stealth, persistence, credential theft, covert exfiltration.
- Full support for every obfuscator, reflection pattern, native-code path and Android framework behavior.

## Demo definition of done

The team can run one pinned lab APK through a reproducible end-to-end investigation where:
1. All DEX entries are enumerated and coverage gaps are disclosed.
2. The AI inspects real code and adapts at least one investigation decision based on new evidence.
3. At least one meaningful security hypothesis cites code and evidence.
4. Related weaknesses form a candidate attack path with explicit proof requirements.
5. A safe PoC reproduces one issue and a negative control does not.
6. VERITAS challenges the result, or the UI clearly labels the deterministic fallback.
7. The War Room shows only real persisted activity and supports replay.
8. The final report contains code references, evidence, PoC result, remediation and unknowns.
