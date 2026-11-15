# CURRENT REPOSITORY STATE

**Snapshot date:** 2026-11-15  
**Snapshot branch:** `audit/main-architecture-gap-review`  
**Base commit audited:** `c8e612ad183879f1425a2557de51a26981e26913` (main after PR #11)  
**Purpose:** inventory of the repository at the stated base commit. This file is a snapshot, not a live assertion; regenerate it after material changes.

## 1. Repository inventory

The repository contains:

- `.github/workflows/ci.yml` — GitHub Actions CI for Python 3.11 and 3.12, PostgreSQL 16 integration service, SQLite migration smoke test.
- `src/mobius/core/` — domain enums, schemas, FSM, gates, frontier scoring, reachability and sink catalogue.
- `src/mobius/adapters/` — SQLAlchemy models/database plumbing, Android manifest and DEX adapters, PostgreSQL trigger DDL and event store.
- `src/mobius/services/` — intake, artifact/evidence storage, RECON, SPECTRE, NEXUS dispatcher, validation, ARCHIVIST/reporting, benchmark and state services.
- `src/mobius/api/` — FastAPI application, routes, schemas, configuration/dependencies and static War Room HTML.
- `migrations/` — Alembic environment and initial migration.
- `tests/` — unit, API, migration, stream, PostgreSQL-trigger and analysis tests, plus a DEX fixture.
- `corpus/` and `scripts/` — pinned APK corpus manifest and corpus fetch helper.
- `docs/` — project requirements, architecture, methodology, threat model, risk register, ADRs, implementation status, model-routing/handoff, team/task documents and reports.
- `web/` — separate marketing site; it is not the MOBIUS product frontend.

## 2. Implemented capabilities (with bounded claims)

- APK ZIP intake, SHA-256 identity, duplicate detection, local content-addressed storage.
- Authorization records bound to APK SHA-256; investigation creation checks hash, expiry, revocation and intensity.
- Binary Android manifest parsing through androguard.
- Single-DEX indexing and bounded application-level call-graph reachability.
- Deterministic evidence gates, persisted findings/verdicts and evidence references.
- NEXUS deterministic frontier dispatcher (not an adaptive/model-driven planner).
- Append-only per-investigation event store and SSE polling/replay.
- Markdown report generation from persisted rows.
- Alembic migration history; PostgreSQL 16 authorization-trigger integration tests run in CI.
- CI matrix for Python 3.11 and 3.12 plus SQLite migration smoke test.

## 3. Known absent or incomplete capabilities

- Real authentication and per-user/tenant resource isolation.
- Isolated analysis worker/container; APK parsing currently runs in the API process.
- Server/ingress multipart request-size and archive resource limits.
- JADX/Apktool tool runner, multidex coverage, CFG and taint/data-flow analysis.
- Model provider integration, adaptive NEXUS planner, model-backed SPECTRE and independent VERITAS model agent.
- PHANTOM dynamic analysis and VECTOR API/network analysis.
- Persisted attack-graph tables and graph UI.
- Full product frontend and browser-level E2E tests.
- Independently labelled, sufficiently large benchmark corpus.

## 4. Validation status

PR #11 merged as commit `c8e612ad183879f1425a2557de51a26981e26913`. Its GitHub Actions run passed both Python matrix jobs and exercised PostgreSQL 16 trigger tests and SQLite migration smoke tests.

This does **not** establish production readiness, authentication security, sandbox isolation, APK parser resilience, analysis accuracy, or dynamic-analysis capability.

## 5. Source of truth

- Current detailed component status: `docs/IMPLEMENTATION_STATUS.md`
- Architecture/security findings and prioritized next slice: `docs/MAIN_ARCHITECTURE_AUDIT_2026-11-15.md`
- Requirements: `docs/REQUIREMENTS.md`
- Architecture decisions: `docs/ARCHITECTURE_DECISIONS.md`

For a current inventory, inspect the Git tree at the commit under review rather than relying on this snapshot.
