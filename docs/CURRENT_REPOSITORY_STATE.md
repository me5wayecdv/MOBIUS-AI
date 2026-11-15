# CURRENT REPOSITORY STATE

**Snapshot date:** 2026-11-12
**Base:** `main` @ `88d456c` (merge of PR #2)
**Branch under review:** `arena/4c61c1ea-mobius-ai`

> **Superseded in part:** this file described a documentation-only repository. Since Phase 2 began,
> `src/mobius/` and `tests/` exist. See §1a and `IMPLEMENTATION_STATUS.md` for the current inventory.
**Purpose:** Phase 0 deliverable. Answers one question factually: *what is in this repository right now?*

---

## 1. What exists

| Path | Contents | Lines |
|---|---|---|
| `README.md` | Project index, four design rules, v1 scope, ethics pointer | 75 |
| `.gitignore` | Python/Node/env + explicit exclusion of `*.apk *.dex *.jar *.so`, `data/ artifacts/ uploads/ apk/` | 37 |
| `docs/` | 23 markdown documents (Phase 0 + Phase 1 set) | ~5 500 |

## 1a. Added in Phase 2 (2026-11-12)

| Path | Contents |
|---|---|
| `src/mobius/core/` | Layer 1 — `ids`, `enums`, `schemas`, `fsm`, `gates`, `frontier`, `ports` (no I/O imports) |
| `src/mobius/adapters/` | Layer 2 — 14 SQLAlchemy tables, engine/session, event store, AXML decoding, `sql/scope_guard.sql` |
| `src/mobius/services/` | Layer 3 — intake/authorisation, evidence, gate validation, RECON |
| `src/mobius/api/` | Layer 4 — FastAPI factory, 16 paths / 17 operations incl. SSE, RFC 9457 errors |
| `tests/` | 307 tests (301 pass, 6 Postgres-only skips) |
| `pyproject.toml` | Packaging, deps, pytest config with registered markers |

Still absent: `web/`, `migrations/`, any analysis agent, any Android tool adapter.

## 2. What does not exist

| Absent | Consequence |
|---|---|
| Any source code (`.py`, `.ts`, `.tsx`, `.sql`) | Nothing can be run. Zero runtime surface. |
| Dependency manifests (`pyproject.toml`, `package.json`, …) | No dependency resolution, no lockfile, no supply chain to audit |
| `Dockerfile` / `docker-compose.yml` | The topology in `ARCHITECTURE.md §7` is a diagram, not a deployment |
| Alembic migrations | The DDL in `DATABASE_SCHEMA.md` has never been parsed by a database |
| Test suite | No `pytest`, no `vitest`, no Playwright. `AC-*` criteria are unverified. |
| CI configuration | No workflow, no gates, no automation |
| `.env.example` | Referenced by `NFR-SEC-4`; does not exist yet |

## 3. Verification of that claim

```bash
git ls-tree -r --name-only HEAD           # 25 files: README, .gitignore, 23 docs
find . -name '*.py' -o -name '*.ts' -o -name '*.sql' -not -path './.git/*'   # empty
ls pyproject.toml package.json Dockerfile 2>/dev/null                        # none
```

Re-run these three commands to confirm the repository has not silently acquired code.

## 4. Documentation inventory

**Phase 0 (4):** `ENVIRONMENT_AUDIT` · `REQUIREMENTS` · `TECHNICAL_RISK_REGISTER` · `CURRENT_REPOSITORY_STATE` (this file)

**Phase 1 (16, per brief §18):** `PROJECT_CONTEXT` · `ARCHITECTURE` · `AGENT_DESIGN` ·
`ANDROID_SECURITY_METHODOLOGY` · `DATABASE_SCHEMA` · `API_SPECIFICATION` · `EVENT_ARCHITECTURE` ·
`THREAT_MODEL` · `MODEL_ROUTING` · `MODEL_BENCHMARKS` · `HANDOFF_PROTOCOL` · `ARCHITECTURE_DECISIONS` ·
`TEAM_RESPONSIBILITIES` · `TASK_BOARD` · `IMPLEMENTATION_STATUS` · `REVIEW_LOG`

**Additional (3):** `00_EXECUTIVE_DECISION_REPORT` · `SPECIALIST_REPORTS` · `ORACLE_THREAT_INTEL`

## 5. Implementation status

**Zero components implemented.** See `IMPLEMENTATION_STATUS.md` — every row is `NOT STARTED`, and that
file's "claims audit" table lists the statements that must not appear until each row is `DONE`.

## 6. Branch and history

```
f3d189e  Merge pull request #1 (Phase 0 + Phase 1)
d3277c4  docs: Phase 0 audit and Phase 1 architecture for MOBIUS
712f7b8  Add project description to README.md        <- initial commit, 56-byte README
```

One merged PR. One documentation commit before it. Three commits total.

## 7. How to falsify this document

Every claim above is a command away. If any of §1–§3 is wrong, the repository has changed underneath this
snapshot and the document should be regenerated rather than trusted. A stale state document is worse than
none, because it becomes a claim.
