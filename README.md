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
| Phase 2+ — implementation | **Not started** (by instruction) |

**No code exists yet.** Every component is `NOT STARTED`; see [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md).
This README will not claim otherwise.

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
