# MOBIUS TASK BOARD — GRADUATION DEMO

**Product direction:** evidence-driven autonomous Android security investigation with a live War Room.
**Execution strategy:** demo-first; production-only infrastructure is deferred.
**Detailed product contract:** [DEMO_FIRST_PRODUCT_PLAN.md](DEMO_FIRST_PRODUCT_PLAN.md)
**Legend:** `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked · `[-]` deferred

## Current verified baseline (main `bb494a3`, 2026-11-19)

- Merged 2026-11-19: PR #59 (commit DB writes before response), PR #60 (integrates D-014 catalogue, D-015 bounded CFG/data-flow, D-016 coverage manifest, D-021 persisted source evidence), PR #61 (soundness: no-evidence cases stay at manual review, never refuted), PR #62 (local self-host delivery: image, compose, healthcheck, runbook, startup smoke). CI green on every merged head, and post-merge main CI on `bb494a3` completed success (Python 3.11/3.12, PostgreSQL 16-backed tests, War Room browser E2E; 536-test suite).
- True-main verification 2026-11-19 on `c6f0b82`: pinned Allsafe APK ran upload -> report; 92,817 methods indexed across 7 DEX entries; 5 components investigated; every component closed at `insufficient_evidence` / `manual_review_required` under the merged soundness policy. Clean-tree benchmark: recall 1/4 (95% CI 4.6-69.9%), precision 1.0, specificity 1.0; policy effect measured: insecurebankv2 review hits 0 -> 5, a2dp 1 -> 2.
- Published worker images (digest-pinned, digest smoke passed): `ghcr.io/me5wayecdv/mobius-dex@sha256:3ea8feba92f374825a60e75a94c557584a29a280f2c32b8bb2ec5535929f3f02`, `ghcr.io/me5wayecdv/mobius-recon@sha256:3874d22044f2452360e7bd94773ab9f8e4979f1fdc0adffd8f40f6fcfde9e789`. Under the owner-approved plan of 2026-11-18 (soundness policy plus DEX/RECON republication at no cost), the new JADX image explicitly stays unpublished; `MOBIUS_JADX_IMAGE` stays unset and the JADX queue returns 503 until an approved immutable digest is configured.
- Local delivery: the no-Docker path in `docs/LOCAL_RUN.md` is verified verbatim (PostgreSQL 16 over TCP, dedicated role, migrations, background server, healthcheck, upload/scan/UI). The Docker image and Compose stack are candidates, never executed (no Docker host where prepared). A minimal startup smoke is ready at `scripts/local-delivery-smoke.yml`; activation (moving it into `.github/workflows/`) is pending and being handled via the authorized account route (the automation token lacks `workflow` scope).
- Model integration measured live 2026-11-19 (Ollama 0.40.16): `qwen2.5:0.5b`, `qwen2.5:1.5b` and `qwen2.5-coder:1.5b` all produced schema-valid JSON, and all were rejected by the integrity guards (fabricated/wrong-kind citations); the deterministic fallback engaged. Whether a larger local model passes the guards is unknown - not yet tried.

## Priority 0 — Establish reproducible demo target

| # | Task | Owner | State | Acceptance |
|---|---|---|---|---|
| D-001 | Select one intentionally vulnerable Android APK owned by the team | Director + Android team | [~] | 7 public samples are pinned by SHA-256 with source URLs in `corpus/corpus.json` and Allsafe is the working demo target (journey of 2026-11-19). Remaining: record the team's formal target acceptance; pinning alone does not prove it. |
| D-002 | Define 2–3 demonstration vulnerability scenarios | Director + M2 + M5 | [x] | `docs/DEMO_SCENARIOS.md` defines three scenarios, each with pinned target, source location, expected evidence, and positive and negative controls measured on main (exported-component review; source-backed persisted evidence with 404 fail-closed controls; soundness boundary on insufficient evidence). |
| D-003 | Confirm host capabilities: JDK/JADX, Android SDK, emulator/KVM, Docker | Director | [ ] | Owner/demo-host step: record tool availability on the actual demo machine. Cannot be done from the build sandbox; no capabilities assumed. |
| D-004 | Freeze demo-only scope and fallback recording | All | [x] | Reproducible live run on main `c6f0b82` (2026-11-19, Allsafe scan `scn_01M7RW55B200GZ5KGC8HKSR5Z7`) plus a labelled recorded War Room replay prepared as the fallback (prepared internally; not yet shown to the owner). |

## Priority 1 — Full code intelligence (first engineering slice)

| # | Task | Owner | State | Acceptance |
|---|---|---|---|---|
| D-010 | Verify APK multi-DEX enumeration and add per-entry coverage/provenance | M2 | [~] | Merged. Validated against a real 7-entry multi-DEX APK via the inline path on true main (2026-11-19). Deployed-worker validation remains, folded into D-011 |
| D-011 | Harden multi-DEX aggregation and provenance | M2 | [~] | Parser tests cover provenance, duplicates, malformed secondary DEX and budget truncation; worker payload round-trip and APK digest binding merged (PR #32). Real multi-DEX APK validated inline on true main (7 entries, 92,817 methods, 2026-11-19). Dedicated worker deployment smoke remains (OCI route unverified on this host) |
| D-012 | Add JADX adapter and cache by APK digest/tool version | M2 | [x] | PR #51 merged. Adapter uses fail-closed ToolRunner; cache identity is APK SHA-256 + JADX 1.5.6; source references are integrity-checked and bounded. CI run 44258662961 passed Python 3.11/3.12 + PostgreSQL 16 Browser E2E; real checked-in DEX fixture decompilation ran without skip. Runtime OCI backend registration remains a deployment/integration blocker, not part of this adapter task. |
| D-013 | Build class/method/source lookup APIs | M1 + M2 | [x] | Engineering complete on PR branch `feat/d-013-jadx-local-image-smoke`: owner-scoped lookup APIs; authorized `jadx_decompile` worker queue/registration; digest/version cache shared read-only with API; CI local image build+load (`push:false`) and real `AnalysisTest.dex` smoke passed in Image CI Run #16 (`44272473218`) on HEAD `f8516909`: JADX 1.5.6 produced one Java source file, the manifest matched the DEX SHA-256/version, and the second call was a verified cache hit. No GHCR push occurred. GHCR publication has not been run and the JADX image remains unpublished (the owner-approved plan of 2026-11-18 covered DEX/RECON republication and stated the new JADX image stays unpublished). `MOBIUS_JADX_IMAGE` remains unset and the queue returns 503 by design until an approved immutable digest is configured. Lookup APIs and local-image real-DEX smoke merged (PR #54, #51). |
| D-014 | Add Android sensitive source/sink catalogue | M2 + M5 | [x] | Merged in PR #60. Versioned YAML source/sink/guard catalogue, exact DEX API matching, MASWE v1.0.0 + MASVS v2 mappings, provenance/confidence/impact metadata, positive/negative tests. CI green on main. |
| D-015 | Add bounded CFG/data-flow for selected source/sink families | M1 + M2 | [x] | Merged in PR #60. Bounded intra-procedural CFG/register taint for selected Intent/URI source candidates to direct WebView, SQL, process-exec and file sinks; records offsets and guard order/dominance. `may-flow` evidence only; try/catch and range-form invokes marked incomplete; field/array memory, interprocedural propagation, reflection, dynamic dispatch and guard branch outcome unsupported and disclosed, never treated as no-flow proof. |
| D-016 | Add code coverage/limitations manifest | M1 + M2 | [x] | Merged in PR #60 after review. Digest-verified APK inventory and structured per-stage manifest embedded in ARCHIVIST reports with an owner-scoped GET endpoint. Native/assets inventory-only; reflection/dynamic loading/obfuscation/CFG/data-flow limits explicit. CI green on main. |

## Priority 2 — Autonomous reasoning and investigation

| # | Task | Owner | State | Acceptance |
|---|---|---|---|---|
| D-020 | Model provider abstraction + structured output validation | M1 | [x] | Merged (PR #33/#35). Local Ollama and deterministic mock share the ModelGateway port; consent, JSON Schema validation and token accounting tested; NEXUS integration live. Live Ollama execution measured 2026-11-19: three small local models all failed the integrity guards; fail-closed fallback verified. Larger-model quality unknown. |
| D-021 | Evidence package builder for targeted code context | M1 + M2 | [x] | Merged in PR #60 after review. Owner-scoped cache-only source capture route; immutable content-addressed SOURCE/SMALI evidence bound to APK SHA-256 + JADX version + path/line/fidelity; hash-verified snippets in the bounded evidence package; NEXUS records their evidence IDs in decision provenance. Exercised end to end 2026-11-19 without OCI: real jadx 1.5.6 decompiled the pinned uncrack1 corpus APK into the verified on-disk cache via the adapter (local process backend, same adapter code and cache contract the worker uses); authorized HTTP then resolved classes/methods/source, POST /code/source/evidence persisted immutable evidence bound to APK SHA-256 + tool version + path/lines (scan scn_01M7RXEK5WQE1J2HHM6JT9FARH, evidence ev_01M7RXF6CNJ1RVTZR5KA1JEBEJ), and the evidence package serves the snippet with provenance. OCI worker deployment remains the only untested transport. |
| D-022 | NEXUS hypothesis generation | M1 | [~] | PR #35 merged; CI green. Structured model-backed hypotheses cite only packaged observation IDs and declare required evidence; deterministic fallback remains default and explicitly labelled. No tool dispatch or PoC execution from model output. Real Ollama run measured 2026-11-19: all tried models (qwen2.5 0.5b/1.5b/coder:1.5b) failed integrity guards and the fallback engaged - a verified fail-closed integration, but no accepted model-backed hypothesis has ever been produced; model quality remains an open gap |
| D-023 | Typed action registry and policy validation | M1 | [x] | PR #36 merged; CI green. Closed SPECTRE action allowlist, strict Pydantic argument schemas, agent/intensity checks and API schema discovery. |
| D-024 | Adaptive re-planning loop | M1 | [x] | PR #37 merged; reachable sink results create a typed `callers_of` follow-up for the sink-bearing method, persist a decision/event, and dispatch through the closed registry. Deterministic policy, not model-generated. Python 3.11/3.12 CI green. |
| D-025 | Persist model/provider/version, prompt version and decisions | M1 | [~] | Merged. NEXUS model hypothesis decisions persist provider, requested/actual model, role, prompt version, prompt/input/schema/response SHA-256, schema name, validated output, token usage, latency and generation parameters; deterministic fallback records no provider/model. Broader decision producers and replay UI/API remain. |
| D-026 | Independent VERITAS review | M1 + M5 | [~] | PR #39 merged: advisory reviewer with a different requested/provider-resolved model, per-investigation consent, cumulative token gateway, evidence-reference confinement, persisted DecisionRow/event provenance. Deterministic gates remain the sole verdict authority. Not wired into scan orchestration/UI; real-model quality unknown. |

## Priority 3 — Correlation and attack graph

| # | Task | Owner | State | Acceptance |
|---|---|---|---|---|
| D-030 | Persist graph nodes and edges | M1 | [x] | PR #40 merged. Four normalized graph/evidence tables, composite same-investigation FKs, dedicated `ged_` edge IDs, and additive idempotent projection from persisted observations/findings/evidence. Python 3.11/3.12 + PostgreSQL 16 CI green (439 tests each). |
| D-031 | Correlate component, caller, data source, sink and permission evidence | M1 + M2 | [x] | PR #41 merged. Direct component/method/permission/source/sink/guard relations carry evidence refs and assertion levels; no source nodes are invented without persisted source observations. Python 3.11/3.12 + PostgreSQL 16 CI green (441 tests each). | Relations carry provenance and edge type |
| D-032 | Build candidate attack-chain reasoning | M1 + M5 | [x] | PR #42 merged. Bounded candidates persist as hypothesis graph nodes with ordered steps, prerequisites and missing proof. Taint propagation and runtime reproduction remain explicitly unproven. Python 3.11/3.12 + PostgreSQL 16 CI green (444 tests each). | Candidate path has explicit prerequisites and missing proof |
| D-033 | Attack graph API and React Flow view | M6 | [x] | PR #43 implementation plus PR #50 screenshot coverage. 1280px desktop and 390px mobile screenshots were reviewed internally and previewed to the owner; explicit owner acceptance is not recorded. |

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
| D-050 | Mission header and investigation coverage panel | M6 | [x] | PR #50 merged; desktop 1280px and mobile 390px screenshots reviewed internally and previewed to the owner; explicit owner acceptance not recorded. |
| D-051 | Agent network with real lifecycle states | M6 + M1 | [x] | PR #50 merged; persisted lifecycle-only states and intentional empty state reviewed internally at 1280px/390px and previewed to the owner; explicit owner acceptance not recorded. |
| D-052 | Investigation timeline with replay/reconnect | M6 + M1 | [x] | PR #50 merged; browser E2E verifies persisted event sequence survives refresh; desktop/mobile screenshots reviewed internally and previewed to the owner; explicit owner acceptance not recorded. |
| D-053 | Code Investigation Studio | M6 | [x] | PR #50 merged; honest missing-source/DEX-indexing state reviewed internally and previewed to the owner (explicit acceptance not recorded). Real decompiled source navigation remains D-012/D-013 scope. |
| D-054 | Attack graph and hypothesis inspector | M6 | [x] | PR #50 merged; graph semantics, readable nodes and proof state reviewed internally on desktop/mobile screenshots and previewed to the owner; explicit acceptance not recorded. |
| D-055 | PoC Lab panel and report viewer | M6 + M1 | [x] | PR #50 merged; persisted PoC records and semantic HTML report reviewed internally on desktop/mobile screenshots and previewed to the owner; explicit acceptance not recorded. |
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
