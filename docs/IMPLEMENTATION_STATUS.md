# IMPLEMENTATION STATUS

> **Nothing in this repository is implemented.** No backend, no frontend, no adapter, no test exists.
> This file exists to prevent exactly the failure mode the project forbids: describing a proposal as if
> it were a working system (master prompt §23). Every row is `NOT STARTED` until a test proves otherwise.

**Last updated:** 2026-11-12 · **Base commit:** `712f7b8` · **Branch:** `arena/bd856c58-mobius-ai`

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

| Component | Status | Spec | Notes |
|---|---|---|---|
| Domain core (models, FSM, gates) | `NOT STARTED` | `AGENT_DESIGN.md`, `ARCHITECTURE.md §4` | |
| Frontier + scorer | `NOT STARTED` | `AGENT_DESIGN.md §4` | |
| Postgres schema + migrations | `NOT STARTED` | `DATABASE_SCHEMA.md` | |
| Event store + LISTEN/NOTIFY bridge | `NOT STARTED` | `EVENT_ARCHITECTURE.md` | |
| API (applications/authorisations/scans) | `NOT STARTED` | `API_SPECIFICATION.md` | |
| WebSocket/SSE stream + replay | `NOT STARTED` | `API_SPECIFICATION.md §4` | |
| Tool runner sandbox | `NOT STARTED` | `AGENT_DESIGN.md §7` | |
| RECON adapter (androguard) | `NOT STARTED` | `ANDROID_SECURITY_METHODOLOGY.md §2` | Only adapter runnable without a JDK |
| SPECTRE / JADX adapter | `NOT STARTED` | §5 | Blocked on JDK host (R-01) |
| PHANTOM / emulator | `NOT STARTED` | §7 | **Blocked: no KVM** (R-02) |
| VECTOR / mitmproxy | `NOT STARTED` | §4 | Blocked: no egress from sandbox |
| VERITAS + gates | `NOT STARTED` | `AGENT_DESIGN.md §6` | |
| Attack graph (data model) | `NOT STARTED` | `DATABASE_SCHEMA.md §3.8` | |
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
| 2 | Core platform foundation | NOT STARTED — blocked on T-024, T-030 |
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

## Claims audit

Statements that must **not** appear in any document until the corresponding row is `DONE`:

| Claim | Becomes true when |
|---|---|
| "MOBIUS investigates autonomously" | FSM + frontier + T-090 complete |
| "MOBIUS reduces false positives" | T-111 measured on a held-out set |
| "MOBIUS validates findings independently" | T-084 + T-085 + T-086 green |
| "The War Room reflects real activity" | T-087 + T-115 green |
| "MOBIUS detects stager/malware patterns" | DCL gate + negative controls (T-075/T-085) |
| "Model X outperforms model Y" | `MODEL_BENCHMARKS.md §6–7` populated |

## How to update this file

Every merged PR that changes behaviour updates exactly one row. The reviewer rejects the PR if the row
is missing. A status file that lags reality is worse than no status file, because it turns into a claim.
