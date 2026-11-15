# MOBIUS

**Autonomous, evidence-driven Android security investigation platform.**
University graduation project.

> *Don't just scan the code. Understand it. Investigate it. Challenge it. Prove what's vulnerable.*

---

## Status

| | |
|---|---|
| Phase 0 — environment & repo audit | **Complete** |
| Phase 1 — research & architecture | **Complete — awaiting Project Director approval** |
| Phase 2 — core platform foundation | **Vertical slice running**; RECON analyses real APKs |

### What actually runs today

Upload an APK, authorise it by SHA-256, open an investigation, let RECON decode the
binary `AndroidManifest.xml` into evidence-backed observations, let SPECTRE index the real
dex and search the call graph for a path from an exported entry point to a sensitive sink,
then let NEXUS drive the worklist until the investigation closes, validating each claim
through a gate to a confirmed, rejected or *insufficient* verdict — streamed live over SSE. No model is called anywhere: every verdict is reproducible from the
APK bytes (ADR-022).

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest                 # 264 passed, 6 skipped
.venv/bin/uvicorn mobius.api.app:app --host 0.0.0.0 --port 8000
curl localhost:8000/api/v1/health
```

`GET /api/v1/health` reports which Android tools are present **before** a scan starts, so
a missing tool is visible rather than inferred from an empty result. `androguard` is present
and is what RECON and SPECTRE actually use; `jadx`, `apktool` and `adb` are absent, because
they are, which is why no decompilation is claimed.

### What is **not** real yet — stated plainly

| Not implemented | Consequence |
|---|---|
| VERITAS model agent, adaptive planner | No model is called. Gates and verdicts **are** real, and NEXUS drives the loop to `CLOSED` — but it is a deterministic dispatcher: it cannot re-plan or invent a line of enquiry (ADR-023) |
| Report writing | `ARCHIVIST` does not exist, so a closed investigation has events and findings but no report artefact. The API response says so in `notes` |
| Code analysis beyond reachability | Call graph and sink reachability are real (dex, application classes only). **No decompilation** (no JDK, R-01), **no data flow**, **no CFG**, no reflection, no multi-dex |
| RECON beyond the manifest | Strings are extracted from dex; certificates, native libraries and multi-dex are not |
| Dynamic analysis | `intensity` 3 is refused globally; ADR-016 still holds |
| Real authentication | Stub identity header; the app **refuses to start** with `MOBIUS_ENV=production` |
| War Room UI | No frontend exists |
| Attack graph, reports, benchmark | Tables and docs exist; no writer, no numbers |
| `enforce_authorization_scope` trigger | Written and unit-tested as SQL, **never executed** — no PostgreSQL here. Its 6 tests skip |

`264 passed, 6 skipped` is the real count from this build. The 6 skips are the Postgres
trigger tests; a skip is not a pass. See [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md)
for per-component detail and the claims audit.

## What MOBIUS is meant to be

Not a scanner. A scanner produces a list. MOBIUS must produce a **defensible argument**: what was
observed, what evidence supports it, what was done to test it, what could not be determined, and why the
conclusion follows. If a feature doesn't improve that chain, it isn't core.

## Start here

| If you want… | Read |
|---|---|
| The decision summary and what needs approval | [`docs/00_EXECUTIVE_DECISION_REPORT.md`](docs/00_EXECUTIVE_DECISION_REPORT.md) |
| What this machine can and cannot do | [`docs/ENVIRONMENT_AUDIT.md`](docs/ENVIRONMENT_AUDIT.md) |
| Scope, non-goals, ethics, authorisation model | [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md) |
| The system design | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| How the agents and investigation engine work | [`docs/AGENT_DESIGN.md`](docs/AGENT_DESIGN.md) |
| Android methodology and confirmed false-positive controls | [`docs/ANDROID_SECURITY_METHODOLOGY.md`](docs/ANDROID_SECURITY_METHODOLOGY.md) |
| Why each technology was chosen (and rejected) | [`docs/ARCHITECTURE_DECISIONS.md`](docs/ARCHITECTURE_DECISIONS.md) |
| What could go wrong | [`docs/TECHNICAL_RISK_REGISTER.md`](docs/TECHNICAL_RISK_REGISTER.md) |
| Who does what | [`docs/TEAM_RESPONSIBILITIES.md`](docs/TEAM_RESPONSIBILITIES.md) |
| What to do next | [`docs/TASK_BOARD.md`](docs/TASK_BOARD.md) |

## The four design rules

1. **Control flow is deterministic; judgement is model-driven.** The FSM decides *when* to validate; the
   model decides *what* to look at. The boundary is enforced in code, not in a prompt.
2. **A finding is confirmed by a gate predicate over evidence — never by model prose.** This is also the
   prompt-injection defence: an instruction hidden in an APK cannot satisfy a predicate.
3. **Severity, confidence and verdict are three independent values.** They are never averaged into a
   single score.
4. **Abstention is a legal outcome.** `INSUFFICIENT_EVIDENCE` is reported, counted, and never dressed up
   as "no vulnerabilities found".

## Scope at a glance (v1)

**In:** RECON (deterministic) · SPECTRE (targeted code investigation) · NEXUS (FSM + frontier) ·
VERITAS (independent validation) · evidence chain · reachability view · live console · reports ·
benchmark with negative controls.

**Out:** PHANTOM (pending a KVM host) · VECTOR · ORACLE · exploit generation · 9 of 14 proposed screens.

## Safety and ethics

MOBIUS is for **authorised** Android security testing only. No investigation may start without an
authorisation record bound to the APK's SHA-256. It does not implement spyware, credential theft, covert
exfiltration, covert tunnelling, or unrestricted shell execution. Threat-intelligence documents are used
for **detection** research only — see [`docs/ORACLE_THREAT_INTEL.md §0`](docs/ORACLE_THREAT_INTEL.md).

## Repository conventions

- Analysis artefacts (`*.apk`, `*.dex`, uploads, decompiled output) are **never committed** — see
  `.gitignore`.
- Every behaviour-changing PR updates one row of `docs/IMPLEMENTATION_STATUS.md`. No row, no merge.
- Interface changes require the `interface-change` label and a `docs/REVIEW_LOG.md` entry.
