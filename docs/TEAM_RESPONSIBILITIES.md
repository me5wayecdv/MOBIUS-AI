# TEAM RESPONSIBILITIES & ONBOARDING

**Team size:** 6 · **Duration:** one semester · **Constraint:** 5 of 6 members are primarily Blue Team
with limited Android experience; 1 owns frontend.

> **The uncomfortable premise.** Six students, one semester, and a scope that would occupy six senior
> engineers full-time. This document is organised around one rule: **every person owns a deliverable that
> can be demonstrated alone**, so that partial team progress still produces a coherent project.

---

## 1. Ownership matrix

| Member | Primary ownership (code) | Secondary | Owns the *question* |
|---|---|---|---|
| **M1 · Director / Red Team Lead / AI Architect** | `core/fsm`, `core/frontier`, `core/gates`, NEXUS, VERITAS prompting | Architecture reviews, ADRs | "Is the investigation intelligent and is its reasoning auditable?" |
| **M2 · Recon & Static** | `adapters/tools/*` (androguard, jadx, apktool, aapt2), RECON, SPECTRE | Sensitive-API catalogue, `tools.lock.yaml` | "Did we see the attack surface correctly, and is the evidence exact?" |
| **M3 · Dynamic** | `adapters/tools/frida*`, `adb*`, emulator harness, PHANTOM | Logcat ingestion, capture fixtures | "Does the app do what the code suggests, and can we prove it?" |
| **M4 · API & Network** | `adapters/tools/mitmproxy`, VECTOR, HTTP/JWT analysis | Network security config parsing | "What leaves the app, where does it go, and who can read it?" |
| **M5 · Validation & Intel** | `core/gates` tests, VERITAS rubric, benchmark corpus, ORACLE detection rules | `tests/integrity`, threat model | "Is this actually a vulnerability, or does it just look like one?" |
| **M6 · Frontend** | `web/` entirely — War Room, findings, code studio, graph, report views | Design tokens, Playwright E2E | "Is everything on screen backed by a real event?" |

**Rule:** code ownership is exclusive for *merging*, shared for *review*. Every PR needs one reviewer
from a different row.

## 2. Interfaces frozen in week 2 (nobody edits these alone)

| Artefact | Owner | Frozen because |
|---|---|---|
| `mobius/schemas/*` (Pydantic) | M1 | Everything depends on it |
| `API_SPECIFICATION.md` routes + payloads | M1 + M6 | Frontend and backend build in parallel against it |
| Event catalogue (`EVENT_ARCHITECTURE.md §4`) | M1 + M6 | The War Room is written against event types |
| `ToolAdapter` protocol + `ToolSpec` | M2 | Every adapter implements it |
| Gate table (`AGENT_DESIGN.md §6`) | M1 + M5 | Findings depend on gate semantics |

Changing a frozen interface requires a PR labelled `interface-change`, reviewed by all affected owners,
and a note in `REVIEW_LOG.md`. This is heavy on purpose: interface churn is what kills 6-person projects.

## 3. Per-member plan

### M1 — Director / Red Team Lead / AI Architect
- **Weeks 1–2:** scope freeze; own `PROJECT_CONTEXT`/`REQUIREMENTS`/`ARCHITECTURE`; freeze schemas.
- **Weeks 2–3:** author the benchmark pilot with M5 and **run it** (R-03).
- **Weeks 3–6:** FSM + frontier + decision records; NEXUS hypothesis generation.
- **Weeks 6–9:** VERITAS prompting + gate predicates; reports.
- **Weeks 9–12:** integration, defence preparation, final report.
- **Also owns:** resolving R-01/R-02 (environment and PHANTOM) by week 3 — non-delegable.

### M2 — Recon & Static
- **Weeks 1–3:** Android fundamentals lab (DIVA, InjuredAndroid by hand); ground-truth labelling of G1.
- **Weeks 3–6:** androguard RECON adapter; manifest/component/permission/cert/NSC extraction; the API-31
  `exported` subtlety with its dedicated fixture.
- **Weeks 6–9:** JADX adapter with `fidelity` + smali fallback; targeted lookup primitives; sensitive-API
  YAML catalogue.
- **Deliverable:** "the surface is correct and the evidence is exact."

### M3 — Dynamic
- **Weeks 1–3:** emulator/ADR research; establish whether a KVM host exists (feeds R-02).
- **Weeks 3–6:** if in scope — emulator harness, AVD snapshot policy, adb wrapper, logcat capture.
- **Weeks 6–9:** Frida scripts for observation only (no bypass); dynamic evidence capture.
- **If PHANTOM is out of scope:** own the *recorded* dynamic session, the logcat fixture corpus (G4), and
  the dynamic-readiness design so it is additive later.
- **Deliverable:** "runtime behaviour is observed, isolated, and reproducible — or explicitly out of scope
  with a written rationale."

### M4 — API & Network
- **Weeks 1–3:** HTTP/TLS/JWT fundamentals; `network_security_config` semantics.
- **Weeks 3–6:** NSC parsing (shared with M2), endpoint discovery from strings/source, evidence capture.
- **Weeks 6–9:** mitmproxy adapter; request replay; auth/authorization observation; VECTOR gates.
- **Deliverable:** "what leaves the device and whether it is protected in transit."

### M5 — Validation & Intel
- **Weeks 1–3:** threat model; gate semantics review; the negative-control set (the most valuable artefact
  in the project).
- **Weeks 3–6:** VERITAS rubric; `tests/integrity`; rejection-reason taxonomy.
- **Weeks 6–9:** benchmark harness + scoring; injection suite (G7); ORACLE detection rules.
- **Weeks 9–12:** held-out precision measurement; false-positive taxonomy write-up.
- **Deliverable:** "we know, numerically, how often we are wrong."

### M6 — Frontend
- **Weeks 1–2:** design tokens, layout shell, API client generated from OpenAPI.
- **Weeks 3–5:** event stream (SSE/WS) + War Room feed; empty/idle/error states **first**, not last.
- **Weeks 5–8:** findings view, code studio (Monaco + highlight ranges), hypothesis panel.
- **Weeks 8–10:** bounded graph view; report view.
- **Weeks 10–12:** Playwright E2E incl. the anti-fabrication tests.
- **Deliverable:** "nothing on screen is invented."

## 4. Shared bootcamp (weeks 1–3, all six, mandatory)

| # | Topic | Session type | Assessment |
|---|---|---|---|
| 1 | APK/ZIP/DEX structure | Lecture + lab | Extract manifest by hand from a ZIP |
| 2–3 | Android component model, `exported` semantics, intents/filters/deep links | Lecture + lab | Enumerate DIVA's exported components by hand |
| 4 | Permissions, protection levels, UID sandbox | Lecture | Explain why `exported=true` is not automatically a vulnerability |
| 5 | MASVS v2.1 / MASTG v2 / MASWE and how to cite them | Lecture + exercise | Map 5 findings to `MASVS → MASWE` IDs |
| 6–7 | JADX + Apktool hands-on on DIVA | Lab | Decompile, find 3 vulnerabilities, cite file+line |
| 8 | Reading smali when JADX fails | Lab | Explain an obfuscated method from smali |
| 9 | Pydantic schemas + the event model | Lecture + lab | Emit a valid `Observation` through the API |
| 10 | Frida basics (conditional on PHANTOM) | Lab | Hook a method and print arguments |

**Mandatory gate:** the DIVA/InjuredAndroid manual write-up (2–3 pages, per person) must be submitted
before anyone's first analysis PR is merged. Rationale: you cannot evaluate an automated investigator on
apps you cannot investigate manually.

## 5. Working agreements

| Agreement | Detail |
|---|---|
| Weekly 60-min review | `TECHNICAL_RISK_REGISTER.md` is the agenda. Risks are re-scored, not re-read. |
| PR size | ≤ 400 changed lines, except generated code and migrations |
| Tests | Every PR touching `core/` needs unit tests; every adapter needs a fixture-based test |
| Definition of done | Code + test + doc update + `IMPLEMENTATION_STATUS.md` row updated. No row, no merge. |
| No mocks in `web/` | Any import from `mock/` in production code fails CI |
| Honesty rule | If a feature is stubbed, it is labelled `STUB` in `IMPLEMENTATION_STATUS.md` and the UI says so |
| Blocker protocol | A blocker older than 48 h goes to M1 with a written question, not a chat message |

## 6. What each member must be able to say at the defence

This is the real acceptance criterion. Each member answers one question, unaided, with evidence from the
system:

| Member | Question they must answer |
|---|---|
| M1 | "Show me a decision the system made and the evidence it used." |
| M2 | "Show me how you know this component is exported, and what could go wrong if you were wrong." |
| M3 | "Show me what runtime evidence proved or disproved a static hypothesis." |
| M4 | "Show me what left the device and whether it was protected." |
| M5 | "What is your false-positive rate on apps with no vulnerabilities, and how do you know?" |
| M6 | "Prove to me nothing in this feed was generated by the frontend." |

If any member cannot answer their question with the running system, the project has a gap regardless of
how many features exist.
