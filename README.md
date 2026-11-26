# MOBIUS

**Evidence-driven autonomous Android security investigation platform.**
University graduation project.

> Don't just scan the code. Understand it. Investigate it. Correlate it. Prove it.

## Product goal

MOBIUS accepts an explicitly authorized Android APK and investigates it as a security researcher would:

1. Inventory the APK and establish code-analysis coverage.
2. Index and inspect supported code across all discovered DEX files.
3. Build evidence-backed observations and security hypotheses.
4. Use NEXUS to select bounded investigation actions and adapt its plan from new evidence.
5. Correlate weaknesses into candidate attack paths.
6. Execute safe, reproducible PoCs against a controlled lab target.
7. Validate findings independently and generate an evidence-backed report.
8. Show the real investigation in the War Room as it happens.

The War Room is not a decorative dashboard. Agent activity, code locations, tool executions, hypotheses, graph changes and PoC states must come from real backend records/events. No fake progress or simulated agent activity.

## Current implementation — read before making claims

The current backend is a tested foundation, not the completed autonomous Android agent:
- APK ZIP intake, SHA-256 identity and authorization binding, with bounded upload/archive checks.
- Real binary-manifest analysis and bounded multi-DEX indexing; selected-family code analysis records coverage gaps instead of treating missing evidence as safety.
- Persisted evidence, hypotheses, findings, graph relations, events and Markdown reports, with an API-backed War Room and graph UI.
- Deterministic NEXUS dispatch and bounded evidence-triggered follow-up. Optional consent-gated model hypothesis generation and advisory VERITAS review exist; models do not establish verdicts by prose.
- Digest-bound isolated RECON/DEX worker transport is CI-verified. A separate runtime/worker host still needs configuration; a fresh default local server is not a complete analysis deployment.
- Earlier public Allsafe emulator/provider and API/Frida smoke tests verified narrow runtime slices. They did not establish the complete model-to-runtime-to-report agent journey. The connected journey has no successful recorded workflow run in the 2026-11-22 audit.

**Readiness boundary:** green unit/API/browser/worker CI is not proof of reliable autonomous vulnerability discovery. Browser E2E uses explicitly seeded evidence/hypotheses and simulated local PoCs. The owned-Android traffic/capture/replay backend under `research/d061_android/` is HELD source preparation, not an activated or verified runtime.

**Local startup boundary:** `GET /ui` serving and `/api/v1/health` returning OK do not mean an APK investigation can run end to end. Default development mode refuses direct SPECTRE/NEXUS DEX parsing without a supported isolated-worker path or explicit local-development opt-in. Do not set test mode to bypass deployment checks. Authentication remains a single-user development stub, not production protection.

See [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) for the current evidence boundary and [docs/LOCAL_RUN.md](docs/LOCAL_RUN.md) for startup limitations. Historical test counts and old status rows are not current acceptance evidence.

## Graduation-demo engineering strategy

The project is demo-first, not production-SaaS-first. We prioritize one complete and reproducible investigation over enterprise infrastructure.

**First priorities:**
1. Full supported code inventory and multi-DEX indexing.
2. JADX/source navigation and bounded CFG/data-flow analysis for selected vulnerability classes.
3. Model provider + typed NEXUS reasoning and adaptive re-planning.
4. Evidence correlation and attack-path graph.
5. Safe PoC execution on an intentionally vulnerable lab APK/emulator or local harness.
6. Independent validation and evidence-backed reporting.
7. A live War Room showing only real backend activity.

PHANTOM and VECTOR remain part of the broader architecture; implement them if the available host and demonstration scenario support them. Production-only work such as billing, multi-tenant SaaS, Kubernetes, HA, autoscaling and enterprise SSO is deferred.

**Detailed product and engineering contract:** [docs/DEMO_FIRST_PRODUCT_PLAN.md](docs/DEMO_FIRST_PRODUCT_PLAN.md)  
**Prioritized work queue:** [docs/TASK_BOARD.md](docs/TASK_BOARD.md)

## Run the current backend

    python3 -m venv .venv
    .venv/bin/pip install -e '.[dev]'
    MOBIUS_DB_URL=sqlite+pysqlite:///dev.db .venv/bin/alembic upgrade head
    .venv/bin/python -m pytest
    .venv/bin/uvicorn mobius.api.app:app --host 127.0.0.1 --port 8000

Open http://127.0.0.1:8000/ui.

The committed CI workflow tests Python 3.11 and 3.12 and runs PostgreSQL integration tests plus a SQLite migration smoke test. Consult the current workflow result rather than relying on historical test counts in older docs.

## Architecture principles

1. **Deterministic control, bounded model judgement.** The FSM and policy layer control execution; models propose hypotheses and typed actions.
2. **Evidence before verdict.** LLM prose or scanner output alone cannot confirm a finding.
3. **Severity, confidence and verdict are separate.**
4. **Abstention is valid.** Incomplete analysis and insufficient evidence are reported honestly.
5. **Coverage is explicit.** Every discovered DEX and unsupported analysis surface is accounted for.
6. **No fabricated activity.** The War Room reflects actual backend events.
7. **Authorized lab testing only.** No arbitrary targets, unrestricted shell, destructive testing by default, stealth, persistence, credential theft or covert exfiltration.

## Repository map

- src/mobius/core/ — domain models, schemas, FSM, gates and analysis primitives.
- src/mobius/adapters/ — database and Android/tool adapters.
- src/mobius/services/ — intake, RECON, SPECTRE, NEXUS, validation, evidence and reports.
- src/mobius/api/ — FastAPI routes and current War Room.
- tests/ — unit, API, integration and analysis fixtures.
- docs/ — architecture, methodology, risks, status and implementation plan.
- web/ — separate marketing site; not the MOBIUS application.

APK files, decompiled output and analysis artifacts must not be committed to the repository.
