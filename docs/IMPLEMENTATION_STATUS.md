# IMPLEMENTATION STATUS

> A **vertical slice of the backend is implemented and tested**. GitHub Actions CI on main runs the full pytest suite on Python 3.11 and 3.12 with PostgreSQL 16 integration tests, plus a SQLite Alembic migration smoke test (PR #11).
> RECON decodes real binary manifests, SPECTRE reads real dex and proves or fails to prove sink
> reachability from an exported entry point, and NEXUS drives that work from the frontier to a
> closed investigation. **No model is called anywhere** — SPECTRE decides by deterministic graph
> search (ADR-022) and NEXUS is a dispatcher, not a planner (ADR-023). No frontend exists. No
> confirmed true positive on real code has been produced yet. This file exists to prevent
> exactly the failure mode the project forbids: describing a proposal as if it were a working system
> (master prompt §23). Every row states its evidence; a row without a test is not `DONE`.

**Last updated:** 2026-11-16 · **Status baseline:** branch `feat/demo-first-autonomous-investigation` based on main `669ecd5`; verify the current commit before relying on this snapshot.

---

## Status legend

| Symbol | Meaning |
|---|---|
| `NOT STARTED` | No code |
| `DESIGNED` | Specification exists, no code |
| `STUB` | Code exists, returns placeholder; **must be labelled in the UI** |
| `PARTIAL` | Works for some inputs; limitations recorded |
| `DONE` | Implementation + tests + doc; acceptance criterion verified |

## Component status

| Component | Status | Spec | Evidence / limitation |
|---|---|---|---|
| Domain core (models, FSM, gates) | `DONE` | `AGENT_DESIGN.md`, `ARCHITECTURE.md §4` | `test_fsm.py` (15 states, no `PAUSED`), `test_gates.py` (10 gates, positive + negative controls), `test_schemas.py` (invariants) |
| Frontier + scorer | `PARTIAL` | `AGENT_DESIGN.md §4` | `test_frontier.py`: arithmetic, determinism, unauthorised action scores `-inf`, ties break on content not on generated ids. **Driven by NEXUS**, which is a dispatcher over this queue and not a planner (ADR-023) |
| NEXUS (dispatch loop) | `PARTIAL` | `AGENT_DESIGN.md §4`, phase 5 | `test_nexus.py` (19 tests) + 2 HTTP tests: pops the best entry, dispatches to the agent that can run it, records dropped work with reasons, stops on a step budget, closes the investigation. **No re-planning, no model** — a frontier entry no tool queued is never invented |
| Schema + migrations | `DONE` (migration history) | `DATABASE_SCHEMA.md`, ADR-025 | `alembic upgrade head` builds 14 tables + `alembic_version`; upgrade/downgrade/replay tested; `alembic check` fails on model drift. PostgreSQL 16 authorization-trigger integration tests run in CI (PR #11). |
| Event store + SSE polling | `PARTIAL` | `EVENT_ARCHITECTURE.md`, ADR-021 | `test_events.py`: per-investigation `seq`, row-locked allocation, unique constraint. SSE polls the durable event table and supports replay; no LISTEN/NOTIFY bridge. |
| API (applications/authorisations/scans) | `PARTIAL` | `API_SPECIFICATION.md` | 19 paths / 22 operations, driven end to end by `test_api.py`. **Auth is a stub** |
| WebSocket/SSE stream + replay | `DONE` | `API_SPECIFICATION.md §4` | `GET /scans/{id}/stream`: SSE with `Last-Event-ID` resume and a definite `stream_end`. `test_stream.py`. Polls the event table, not LISTEN/NOTIFY (ADR-021) |
| Tool runner sandbox | `NOT STARTED` | `AGENT_DESIGN.md §7` | |
| RECON adapter (androguard) | `PARTIAL` | `ANDROID_SECURITY_METHODOLOGY.md §2` | Manifest analysis is **real**: binary AXML decoded via androguard 4.1.4, 5 component kinds, permissions, export inference, evidence + observations + frontier. `test_android_manifest.py`, `test_recon.py`. **Manifest only** — no dex, strings, certs or native libs |
| Dex index (androguard) | `PARTIAL` | §5 | `index_apk` enumerates sorted `classes*.dex`; `index_dex` merges multiple DEX blobs. Current PR adds per-entry coverage (`indexed`/`failed`/`skipped`/`truncated`), class/method source provenance, duplicate-entry rejection, and bounded total DEX expansion. SPECTRE now treats incomplete DEX coverage as inconclusive for absence claims. New tests cover provenance, APK multi-entry coverage, partial failure, budget truncation, and method-reference parsing. GitHub Actions passed on Python 3.11 and 3.12 for commit `4501d3f`; the additional parser regression test is being verified in the current CI run. Reflection, CFG and data flow remain unimplemented. |
| Call graph + reachability | `PARTIAL` | §5 | Bounded deterministic BFS, application classes only, node budget with `truncated`. `test_reachability.py` (24 tests): truncation is never absence, a guard off the path is not counted, same-method guard is conservative regardless of order (R-21). **No data flow, no CFG** |
| SPECTRE | `PARTIAL` | §5 | Turns RECON candidates into gate evidence and emits `code_analysis_complete`; `test_spectre.py` + 2 HTTP tests. **Validated on one real APK** (`com.politedroid_4.apk`): 10 classes / 34 methods / 41 calls → `not-reached` over a complete traversal → `REJECTED`. No true positive on real code yet |
| JADX / smali decompilation | `NOT STARTED` | §5 | Blocked on JDK host (R-01). SPECTRE does not need it for reachability, only for the model-backed pass |
| PHANTOM / emulator | `NOT STARTED` | §7 | **Blocked: no KVM** (R-02) |
| VECTOR / mitmproxy | `NOT STARTED` | §4 | Blocked: no egress from sandbox |
| VERITAS + gates | `PARTIAL` | `AGENT_DESIGN.md §6` | Gate evaluation, verdict persistence and `ValidatorMustDiffer` implemented and tested. **The VERITAS model agent does not exist**; attributes come from RECON or over HTTP. `test_recon.py::test_recon_candidates_can_never_confirm` pins the honest outcome |
| Authorisation enforcement (trigger) | `PARTIAL` | `DATABASE_SCHEMA.md §3.2` | SQL in `adapters/sql/scope_guard.sql`, installed by migration on PostgreSQL; PostgreSQL 16 trigger integration tests now execute in CI (PR #11). Deployment enforcement and production auth remain unverified. |
| Attack graph (data model) | `DESIGNED` | `DATABASE_SCHEMA.md §3.8` | Tables `graph_nodes`/`graph_edges` **not created**; only `GraphNode`/`GraphEdge` domain models exist |
| Attack graph (UI) | `NOT STARTED` | ADR-014 | The War Room lists findings and surface; the reachability *graph* view is not built |
| ARCHIVIST (report) | `PARTIAL` | `REQUIREMENTS.md §1.9` | `services/archivist.py`: eight sections generated from stored rows, written as evidence, `POST/GET /scans/{id}/report`. **Markdown only** |
| Benchmark harness | `DONE` (harness) | `BENCHMARK_RESULTS.md` | `services/benchmark.py` + `python -m mobius.tools.benchmark`: precision/recall/specificity with **Wilson 95% intervals and denominators**, `measured: false` on an empty corpus, errors never counted as rejections. **First measurement: 7 pinned samples, precision 100% (1/1, CI 20.6–100%), recall 25% (1/4), specificity 100% (3/3)** |
| ORACLE | `NOT STARTED` | `ORACLE_THREAT_INTEL.md` | **Deliberately out of v1 scope** |
| Reports | `NOT STARTED` | `REQUIREMENTS.md §1.9` | Markdown for v1 |
| Frontend shell | `NOT STARTED` | `SPECIALIST_REPORTS.md F` | |
| Benchmark corpus (code analysis)\* | `PARTIAL` | `BENCHMARK_RESULTS.md` | 7 public APKs, every SHA-256 pinned in `corpus/corpus.json`, fetched by `scripts/fetch_corpus.py`. **Labelled by the implementer** — T-036 (independent labelling) is not satisfied, and the corpus is too small to establish a rate |
| Model benchmark results | `NOT STARTED` | `MODEL_BENCHMARKS.md §6–7` | **No model results exist. Do not cite any.** | Code-analysis results are in `BENCHMARK_RESULTS.md` and measure a tool, not a model |

## Phase status

| Phase | Name | Status |
|---|---|---|
| 0 | Environment & repository audit | **DONE** |
| 1 | Research & architecture | **DONE (awaiting Director approval)** |
| 2 | Core platform foundation | **PARTIAL** — vertical slice green, event stream and migrations done (ADR-025); **auth is still a stub** |
| 3 | RECON | NOT STARTED |
| 4 | SPECTRE | **PARTIAL** — deterministic reachability works on real dex (ADR-022); JADX, data flow and the model pass outstanding |
| 5 | NEXUS + agent runtime | **PARTIAL** — dispatch loop works end to end (ADR-023); the model-driven planner is NOT implemented |
| 6 | PHANTOM | NOT STARTED — **likely blocked permanently** |
| 7 | VECTOR | NOT STARTED |
| 8 | VERITAS + ARCHIVIST | **PARTIAL** — ARCHIVIST writes a real report from stored rows; the VERITAS *model* validator does not exist (gates validate, not a second model) |
| 9 | War Room | **PARTIAL** — one page at `/ui` reading `/api/v1` only (scans, surface, findings, replayed events, report link). **No browser test**: rendering is asserted at the HTML level, not by clicking |
| 10 | ORACLE | **DEFERRED — not in v1 scope** |
| 11 | Reporting | **PARTIAL** — Markdown only and stored as evidence; **no PDF, no template engine, no downloadable bundle** |
| 12 | Testing & evaluation | **PARTIAL** — 319 tests; first corpus measurement exists (7 samples, `BENCHMARK_RESULTS.md`). **Corpus too small, labels not independent, recall gap is a coverage gap** |

## Verified in this build

Commands run and their observed output, so a reader can distinguish measurement from claim:

| Check | Result |
|---|---|
| `pytest` | **319 passed, 6 skipped** in ~19 s |
| `pytest tests/test_layering.py` | Layer 1 imports no `sqlalchemy`/`fastapi`/outer layer |
| `uvicorn mobius.api.app:app` | Boots on `0.0.0.0:8000`; `/api/v1/health` → 200 |
| End-to-end over HTTP | upload (binary AXML, 1 141 B) → authorise → scan → **RECON → `SURFACE_READY`**: 5 components, 4 exported, 3 unguarded, 2 queued, launcher excluded → 9 audit events |
| RECON-only validation | `insufficient_evidence` / `manual_review_required`, confidence 0.25 — **never confirmed** |
| SSE stream | replays from `after=0` and closes with `stream_end` on a terminal scan |
| Unauthorised scan | 409 `AUTH_REQUIRED` |
| Self-validation | 409 `VALIDATOR_MUST_DIFFER` |
| Negative control (exported launcher, no sink) | `rejected`, reason `not-reachable` |
| SPECTRE on a real APK, over HTTP | `com.politedroid_4.apk` (18 489 B, real androguard): 10 classes, 34 methods, 34 graph nodes, 41 internal calls, `truncated=False`; 1 candidate → `not-reached` over 6 methods → `REJECTED` / `not-reachable`, confidence 0.38, `caller_check_absent: null`, `path_length: null`; repeat call → 409 `SCAN_STATE_CONFLICT`; 15 events ending `code_analysis_complete` |
| Truncation ≠ refutation | `test_truncation_never_reports_absence`: an exhausted node budget yields `sink_reachable=None` → `insufficient_evidence`, never `not-reachable` |
| Sink catalogue tightened | A real APK produced a **false positive** (`SharedPreferences.getString`); the sink was removed and a regression test pins its absence |
| Unparseable dex | 422 `CODE_INDEX_FAILED` over HTTP, typed |
| NEXUS on a real APK, over HTTP | `com.politedroid_4.apk` → RECON → `POST /nexus` → **`CLOSED`**, `stop_reason: completed`, 1 of 20 steps used, 1 candidate dispatched, 0 confirmed / 1 rejected, `code_analysis_complete` then `nexus_complete`, 409 on a second call |
| NEXUS determinism | The same APK scanned twice produced an identical decision payload, step list and result set — compared across two investigations, not within one run |
| NEXUS budget | `max_steps=1` over two candidates → 1 dispatched, 1 left `queued`, `stop_reason: budget_exhausted`, state `CLOSED`, and the skipped entry named in `notes` |
| Report on a real APK | 4 593 bytes of Markdown, 8 sections, evidence index with SHA-256 prefixes; states "no data-flow analysis" and "absence of a finding is not evidence of absence" |
| Report is reproducible | Same rows + same timestamp → byte-identical document (`test_the_same_rows_produce_byte_identical_reports`) |
| Migrations build the schema | `alembic upgrade head` on an empty SQLite file → 14 tables + `alembic_version`; `alembic check` → "No new upgrade operations detected"; `downgrade base` leaves only `alembic_version`; upgrade → base → upgrade replays |
| War Room served | `GET /ui` → 200 text/html, `GET /` → 307 to `/ui`; every panel reads `/api/v1` (no fixture, no placeholder) |
| Benchmark with no corpus | `measured: false`, no metrics, and a note saying no number may be cited; **this is the current state** |
| Benchmark on a control | Real pipeline (upload → RECON → NEXUS) over a synthetic control: 0 confirmed → benign specificity 100 %, precision `undefined` |
| **Corpus measurement** | 7 pinned APKs through the real pipeline: **precision 100 % (1/1, 95 % CI 20.6–100 %), recall 25 % (1/4, CI 4.6–69.9 %), benign specificity 100 % (3/3, CI 43.9–100 %)**, 0 errors. One true positive: exported `ViewStatement.onCreate` → `WebView` loader, no permission, no caller check |
| Corpus misses explained | All three MASTG crackmes have **one component, the launcher**, which RECON excludes → 0 candidates. The 25 % recall measures coverage of a weakness class this build has no gate for, not detector failure |
| `MOBIUS_ENV=production` | process **refuses to start** (stub auth) |

**Not verified anywhere yet:** the PostgreSQL trigger, LISTEN/NOTIFY, androidsdk tooling, any
emulator, any model call, and every number in `MODEL_BENCHMARKS.md`.

## SPECTRE — what its verdicts do and do not mean

Reachability is a **graph property**, and it is the only thing SPECTRE claims to establish:

| Verdict path | What it means | What it does *not* mean |
|---|---|---|
| `reached`, no guard → `confirmed` | An exported entry point reaches a security-relevant operation with no caller check on the path | That attacker-controlled data reaches it — there is no data flow analysis |
| `reached`, guard on the path → `REJECTED` / `guarded-by-caller-check` | A caller check exists somewhere in the same method | That the app is safe: a guard refutes one clause, not the finding |
| exhaustive `not-reached` → `REJECTED` / `not-reachable` | The complete traversal found no sink | That no sink exists via reflection, native code or multi-dex |
| truncated / no entry point / no index → `insufficient_evidence` | The search did not finish, or could not start | **Nothing about safety.** Treated as missing evidence, never as a negative |

The graph holds application classes only. A call into the framework is recorded as a boundary
call and is never followed, so the search cannot manufacture a path through `Context`.

## Claims audit

Statements that must **not** appear in any document until the corresponding row is `DONE`:

| Claim | Becomes true when |
|---|---|
| "MOBIUS investigates autonomously" | FSM + frontier + T-090 complete. The loop exists and closes scans, but it only dispatches work other tools queued — it cannot discover a new line of enquiry, so **not yet true** |
| "MOBIUS reduces false positives" | T-111 measured on a held-out set. **Still not available**: one 7-sample corpus, labelled by the implementer, with no baseline comparison. `BENCHMARK_RESULTS.md` states what may and may not be claimed |
| "MOBIUS validates findings independently" | T-084 + T-085 + T-086 green — gate + verdict **are** green; the independent *agent* is not |
| "The War Room reflects real activity" | T-087 + T-115 green |
| "MOBIUS detects stager/malware patterns" | DCL gate + negative controls (T-075/T-085) |
| "Model X outperforms model Y" | `MODEL_BENCHMARKS.md §6–7` populated |

## How to update this file

Every merged PR that changes behaviour updates exactly one row. The reviewer rejects the PR if the row
is missing. A status file that lags reality is worse than no status file, because it turns into a claim.
