# IMPLEMENTATION STATUS

> A **vertical slice of the backend is implemented and tested** (243 tests passing, 6 skipped).
> RECON decodes real binary manifests and SPECTRE now reads real dex: it builds a call graph and
> proves, or fails to prove, that an exported entry point reaches a sensitive sink. **No model is
> called anywhere** — SPECTRE v1 decides by deterministic graph search (ADR-022). No frontend
> exists. No confirmed true positive on real code has been produced yet. This file exists to prevent
> exactly the failure mode the project forbids: describing a proposal as if it were a working system
> (master prompt §23). Every row states its evidence; a row without a test is not `DONE`.

**Last updated:** 2026-11-13 · **Base commit:** `181bba9` · **Branch:** `arena/e74eccc1-mobius-ai`

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
| Frontier + scorer | `PARTIAL` | `AGENT_DESIGN.md §4` | `test_frontier.py`: arithmetic, determinism, unauthorised action scores `-inf`. **Never driven by a real agent loop** |
| Postgres schema + migrations | `PARTIAL` | `DATABASE_SCHEMA.md` | 14 tables via SQLAlchemy metadata; SQLite + Postgres dialects. **No migration tool**; `create_all` is dev/CI only |
| Event store + LISTEN/NOTIFY bridge | `PARTIAL` | `EVENT_ARCHITECTURE.md` | `test_events.py`: per-investigation `seq`, row-locked allocation, unique constraint. **No LISTEN/NOTIFY bridge** |
| API (applications/authorisations/scans) | `PARTIAL` | `API_SPECIFICATION.md` | 17 paths / 18 operations, driven end to end by `test_api.py`. **Auth is a stub** |
| WebSocket/SSE stream + replay | `DONE` | `API_SPECIFICATION.md §4` | `GET /scans/{id}/stream`: SSE with `Last-Event-ID` resume and a definite `stream_end`. `test_stream.py`. Polls the event table, not LISTEN/NOTIFY (ADR-021) |
| Tool runner sandbox | `NOT STARTED` | `AGENT_DESIGN.md §7` | |
| RECON adapter (androguard) | `PARTIAL` | `ANDROID_SECURITY_METHODOLOGY.md §2` | Manifest analysis is **real**: binary AXML decoded via androguard 4.1.4, 5 component kinds, permissions, export inference, evidence + observations + frontier. `test_android_manifest.py`, `test_recon.py`. **Manifest only** — no dex, strings, certs or native libs |
| Dex index (androguard) | `PARTIAL` | §5 | `index_apk`/`index_dex`: real classes, methods, call edges, string literals, boundary calls. `test_dex.py` + a committed real dex fixture. **Single dex only** — no multi-dex, no reflection, no framework entry |
| Call graph + reachability | `PARTIAL` | §5 | Bounded deterministic BFS, application classes only, node budget with `truncated`. `test_reachability.py` (24 tests): truncation is never absence, a guard off the path is not counted, same-method guard is conservative regardless of order (R-21). **No data flow, no CFG** |
| SPECTRE | `PARTIAL` | §5 | Turns RECON candidates into gate evidence and emits `code_analysis_complete`; `test_spectre.py` + 2 HTTP tests. **Validated on one real APK** (`com.politedroid_4.apk`): 10 classes / 34 methods / 41 calls → `not-reached` over a complete traversal → `REJECTED`. No true positive on real code yet |
| JADX / smali decompilation | `NOT STARTED` | §5 | Blocked on JDK host (R-01). SPECTRE does not need it for reachability, only for the model-backed pass |
| PHANTOM / emulator | `NOT STARTED` | §7 | **Blocked: no KVM** (R-02) |
| VECTOR / mitmproxy | `NOT STARTED` | §4 | Blocked: no egress from sandbox |
| VERITAS + gates | `PARTIAL` | `AGENT_DESIGN.md §6` | Gate evaluation, verdict persistence and `ValidatorMustDiffer` implemented and tested. **The VERITAS model agent does not exist**; attributes come from RECON or over HTTP. `test_recon.py::test_recon_candidates_can_never_confirm` pins the honest outcome |
| Authorisation enforcement (trigger) | `DESIGNED` | `DATABASE_SCHEMA.md §3.2` | SQL written in `adapters/sql/scope_guard.sql`; 6 tests exist but **skip — never executed on PostgreSQL** |
| Attack graph (data model) | `DESIGNED` | `DATABASE_SCHEMA.md §3.8` | Tables `graph_nodes`/`graph_edges` **not created**; only `GraphNode`/`GraphEdge` domain models exist |
| Attack graph (UI) | `NOT STARTED` | ADR-014 | Reachability view for v1 |
| ORACLE | `NOT STARTED` | `ORACLE_THREAT_INTEL.md` | **Deliberately out of v1 scope** |
| Reports | `NOT STARTED` | `REQUIREMENTS.md §1.9` | Markdown for v1 |
| Frontend shell | `NOT STARTED` | `SPECIALIST_REPORTS.md F` | |
| Benchmark corpus | `NOT STARTED` | `MODEL_BENCHMARKS.md §3` | Nothing labelled yet |
| Benchmark results | `NOT STARTED` | `MODEL_BENCHMARKS.md §6–7` | **No results exist. Do not cite any.** |

## Phase status

| Phase | Name | Status |
|---|---|---|
| 0 | Environment & repository audit | **DONE** |
| 1 | Research & architecture | **DONE (awaiting Director approval)** |
| 2 | Core platform foundation | **PARTIAL — vertical slice green**; auth, event stream and migrations outstanding |
| 3 | RECON | NOT STARTED |
| 4 | SPECTRE | **PARTIAL** — deterministic reachability works on real dex (ADR-022); JADX, data flow and the model pass outstanding |
| 5 | NEXUS + agent runtime | NOT STARTED |
| 6 | PHANTOM | NOT STARTED — **likely blocked permanently** |
| 7 | VECTOR | NOT STARTED |
| 8 | VERITAS + ARCHIVIST | NOT STARTED |
| 9 | War Room | NOT STARTED |
| 10 | ORACLE | **DEFERRED — not in v1 scope** |
| 11 | Reporting | NOT STARTED |
| 12 | Testing & evaluation | NOT STARTED |

## Verified in this build

Commands run and their observed output, so a reader can distinguish measurement from claim:

| Check | Result |
|---|---|
| `pytest` | **243 passed, 6 skipped** in ~6.0 s |
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
| "MOBIUS investigates autonomously" | FSM + frontier + T-090 complete |
| "MOBIUS reduces false positives" | T-111 measured on a held-out set |
| "MOBIUS validates findings independently" | T-084 + T-085 + T-086 green — gate + verdict **are** green; the independent *agent* is not |
| "The War Room reflects real activity" | T-087 + T-115 green |
| "MOBIUS detects stager/malware patterns" | DCL gate + negative controls (T-075/T-085) |
| "Model X outperforms model Y" | `MODEL_BENCHMARKS.md §6–7` populated |

## How to update this file

Every merged PR that changes behaviour updates exactly one row. The reviewer rejects the PR if the row
is missing. A status file that lags reality is worse than no status file, because it turns into a claim.
