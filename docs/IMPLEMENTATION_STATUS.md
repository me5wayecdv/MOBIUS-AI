# IMPLEMENTATION STATUS

> A **vertical slice of the backend is implemented and tested** (136 tests passing, 6 skipped). No
> analysis agent, no frontend and no Android tooling integration exists. This file exists to prevent
> exactly the failure mode the project forbids: describing a proposal as if it were a working system
> (master prompt §23). Every row states its evidence; a row without a test is not `DONE`.

**Last updated:** 2026-11-12 · **Base commit:** `88d456c` · **Branch:** `arena/4c61c1ea-mobius-ai`

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
| API (applications/authorisations/scans) | `PARTIAL` | `API_SPECIFICATION.md` | `test_api.py` drives the real app end to end. 14 routes. **Auth is a stub** |
| WebSocket/SSE stream + replay | `NOT STARTED` | `API_SPECIFICATION.md §4` | Polling `GET /scans/{id}/events?after=` is implemented instead |
| Tool runner sandbox | `NOT STARTED` | `AGENT_DESIGN.md §7` | |
| RECON adapter (androguard) | `NOT STARTED` | `ANDROID_SECURITY_METHODOLOGY.md §2` | Only adapter runnable without a JDK. **androguard is not installed here**; `/health` reports it absent |
| SPECTRE / JADX adapter | `NOT STARTED` | §5 | Blocked on JDK host (R-01) |
| PHANTOM / emulator | `NOT STARTED` | §7 | **Blocked: no KVM** (R-02) |
| VECTOR / mitmproxy | `NOT STARTED` | §4 | Blocked: no egress from sandbox |
| VERITAS + gates | `PARTIAL` | `AGENT_DESIGN.md §6` | Gate evaluation, verdict persistence and `ValidatorMustDiffer` are implemented and tested. **The VERITAS model agent does not exist**; callers currently supply attributes over HTTP |
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
| 4 | SPECTRE | NOT STARTED — blocked on JDK host |
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
| `pytest` | **136 passed, 6 skipped** in ~1.5 s |
| `pytest tests/test_layering.py` | Layer 1 imports no `sqlalchemy`/`fastapi`/outer layer |
| `uvicorn mobius.api.app:app` | Boots on `0.0.0.0:8000`; `/api/v1/health` → 200 |
| End-to-end over HTTP | upload → authorise → scan (`RECON`, seq 2) → confirm + reject → 8 audit events |
| Unauthorised scan | 409 `AUTH_REQUIRED` |
| Self-validation | 409 `VALIDATOR_MUST_DIFFER` |
| Negative control (exported launcher, no sink) | `rejected`, reason `not-reachable` |
| `MOBIUS_ENV=production` | process **refuses to start** (stub auth) |

**Not verified anywhere yet:** the PostgreSQL trigger, LISTEN/NOTIFY, androidsdk tooling, any
emulator, any model call, and every number in `MODEL_BENCHMARKS.md`.

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
