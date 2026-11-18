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
- PR #50 merged to main as `0cf634338bb14c47bd98928aa10824431d42121b`; owner visual acceptance is complete for D-033 and D-050–D-056. D-012 is now the active engineering task.

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
| D-012 | Add JADX adapter and cache by APK digest/tool version | M2 | [x] | PR #51 merged. Adapter uses fail-closed ToolRunner; cache identity is APK SHA-256 + JADX 1.5.6; source references are integrity-checked and bounded. CI run 44258662961 passed Python 3.11/3.12 + PostgreSQL 16 Browser E2E; real checked-in DEX fixture decompilation ran without skip. Runtime OCI backend registration remains a deployment/integration blocker, not part of this adapter task. |
| D-013 | Build class/method/source lookup APIs | M1 + M2 | [~] | Engineering complete on PR branch `feat/d-013-jadx-local-image-smoke`: owner-scoped lookup APIs; authorized `jadx_decompile` worker queue/registration; digest/version cache shared read-only with API; CI local image build+load (`push:false`) and real `AnalysisTest.dex` smoke verifying cache manifest and cache hit. GHCR publication is the only remaining engineering gate and is blocked pending explicit project-owner decision/approval. `MOBIUS_JADX_IMAGE` remains unset; queue returns 503 until an approved immutable digest is configured. No image publication workflow has been run. |
| D-014 | Add Android sensitive source/sink catalogue | M2 + M5 | [ ] | Catalogue has MASWE/MASVS mapping and positive/negative tests |
| D-015 | Add bounded CFG/data-flow for selected source/sink families | M1 + M2 | [ ] | Tainted/untrusted input tracked to selected sensitive sinks; guard order considered |
| D-016 | Add code coverage/limitations manifest | M1 + M2 | [ ] | Report discloses unsupported reflection/native/obfuscation/truncation |

## Priority 2 — Autonomous reasoning and investigation

| # | Task | Owner | State | Acceptance |
|---|---|---|---|---|
| D-020 | Model provider abstraction + structured output validation | M1 | [~] | Local Ollama and deterministic mock share the core ModelGateway port; consent, JSON Schema validation and token accounting are tested. Live Ollama execution and NEXUS integration remain |
| D-021 | Evidence package builder for targeted code context | M1 + M2 | [~] | PR #34 provides bounded component-scoped observations, method/caller references, sink/guard references and evidence provenance. Still needs persisted JADX source evidence and bounded source excerpts linked into the package; D-012 cache and D-013 lookup alone do not complete this criterion. |
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
| D-033 | Attack graph API and React Flow view | M6 | [x] | PR #43 implementation plus PR #50 screenshot coverage. Project owner reviewed the 1280px desktop and 390px mobile screenshots; graph nodes and embed view accepted. |

## Priority 4 — Safe PoC lab

| # | Task | Owner | State | Acceptance |
|---|---|---|---|---|
| D-040 | Define typed PoC/TestPlan schema | M1 + M3 | [x] | PR #44 merged. Typed target/authorization/hypothesis binding, closed action registry, budgets, safety class, approval and cleanup constraints. Python 3.11/3.12 + PostgreSQL 16 CI green (452 tests each). | Target digest, scope, hypothesis, steps, expected outcome, budgets and cleanup |
| D-041 | Implement allowlisted non-destructive test adapters | M3 | [x] | PR #45 merged. Persisted-manifest assertions and two deterministic local-only WebView harnesses; no shell, subprocess, network, emulator, or state-changing action. Python 3.11/3.12 + PostgreSQL 16 CI green (457 tests each). | Only prepared lab APK/emulator/local harness targets |
| D-042 | Capture reproducible PoC evidence | M1 + M3 | [x] | PR #46 merged. Plan/result/log evidence, hashes, tool versions, timestamps, duration, exit status and same-investigation links persisted. Python 3.11/3.12 + PostgreSQL 16 CI green (459 passed each). | Tool version, inputs, outputs, logs, timestamps and exit status persisted |
| D-043 | Add approval, timeout, cancel and cleanup paths | M1 + M3 | [x] | PR #47 and security hardening PR #49 merged. Persisted approval lifecycle, exact immutable plan SHA-256 binding, expiry, cooperative cancellation between bounded steps, per-step/total budgets and finally cleanup; state-changing adapters remain disabled. Python 3.11/3.12 + PostgreSQL 16 CI green (463 passed each). | Out-of-scope or state-changing tests blocked without approval |
| D-044 | Positive and negative PoC integration tests | M3 + M5 | [x] | PR #48 merged. Positive and negative harness controls persist reproducible run/result/log evidence; neither simulation is promoted to a finding/verdict. Python 3.11/3.12 + PostgreSQL 16 CI green (464 passed each). | Positive reproduces; negative control does not confirm |

## Priority 5 — War Room (real backend activity only)

| # | Task | Owner | State | Acceptance |
|---|---|---|---|---|
| D-050 | Mission header and investigation coverage panel | M6 | [x] | PR #50 merged; owner accepted desktop 1280px and mobile 390px screenshots. |
| D-051 | Agent network with real lifecycle states | M6 + M1 | [x] | PR #50 merged; persisted lifecycle-only states and intentional empty state visually accepted at 1280px/390px. |
| D-052 | Investigation timeline with replay/reconnect | M6 + M1 | [x] | PR #50 merged; browser E2E verifies persisted event sequence survives refresh; desktop/mobile screenshots accepted. |
| D-053 | Code Investigation Studio | M6 | [x] | PR #50 merged; honest missing-source/DEX-indexing state visually accepted. Real decompiled source navigation remains D-012/D-013 scope. |
| D-054 | Attack graph and hypothesis inspector | M6 | [x] | PR #50 merged; graph semantics, readable nodes and proof state accepted on desktop/mobile screenshots. |
| D-055 | PoC Lab panel and report viewer | M6 + M1 | [x] | PR #50 merged; persisted PoC records and semantic HTML report visually accepted on desktop/mobile screenshots. |
| D-056 | Browser-level E2E for the complete demo | M6 + All | [x] | PR #50 merged; CI run 44239527536 passed the PostgreSQL 16 browser flow and uploaded the 22-screenshot artifact. |

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
