# TASK BOARD

**State:** Phase 0 complete · Phase 1 documentation complete · **Phase 2 blocked pending Director approval**
**Legend:** `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked · `[?]` undecided

---

## W0 — Phase 0 (complete)

| # | Task | Owner | State | Evidence |
|---|---|---|---|---|
| T-001 | Audit execution environment (measured, not assumed) | Arena | `[x]` | `ENVIRONMENT_AUDIT.md` |
| T-002 | Record repository state | Arena | `[x]` | `ENVIRONMENT_AUDIT.md §3` |
| T-003 | Establish `.gitignore` incl. APK/artefact exclusion | Arena | `[x]` | `.gitignore` |
| T-004 | Report actual agent-parallelism capability honestly | Arena | `[x]` | `ENVIRONMENT_AUDIT.md §2` |
| T-005 | Process supplied C2 research defensively only | Arena | `[x]` | `ORACLE_THREAT_INTEL.md §0` |

## W1 — Phase 1 (documentation complete, awaiting approval)

| # | Task | Owner | State |
|---|---|---|---|
| T-010 | Product context, scope, non-goals, ethics | Arena | `[x]` |
| T-011 | Requirements with acceptance criteria | Arena | `[x]` |
| T-012 | System architecture + trust boundaries | Arena | `[x]` |
| T-013 | Agent design, frontier, gates | Arena | `[x]` |
| T-014 | Android methodology + tooling research | Arena | `[x]` |
| T-015 | Database schema | Arena | `[x]` |
| T-016 | API specification | Arena | `[x]` |
| T-017 | Event architecture | Arena | `[x]` |
| T-018 | Threat model incl. prompt injection + abuse cases | Arena | `[x]` |
| T-019 | Model routing + benchmarking plan (no fabricated results) | Arena | `[x]` |
| T-020 | Seven specialist analyses + honesty ledger | Arena | `[x]` |
| T-021 | ADRs + risk register | Arena | `[x]` |
| T-022 | Team responsibilities + onboarding | Arena | `[x]` |
| T-023 | Handoff protocol | Arena | `[x]` |
| T-024 | **Director review & approval of Phase 1** | **Director** | `[ ]` |

## W2 — Gates before any implementation

These five tasks decide whether the project is viable. None is code.

| # | Task | Owner | Deadline | State | Why it gates everything |
|---|---|---|---|---|---|
| T-030 | **Confirm an execution host with a JDK** (+Docker) | Director | week 1–2 | `[!]` | R-01: without it nothing runs |
| T-031 | **Decide PHANTOM in/out** | Director | week 2 | `[?]` | R-02: changes M3's entire plan and the thesis |
| T-032 | **Run the BQ-2 benchmark pilot (30 items)** | M1 + M5 | week 3 | `[ ]` | R-03: validates or refutes the core premise |
| T-033 | Freeze scope; write the "will not build" list | Director | week 2 | `[ ]` | R-04 |
| T-034 | Provision Postgres (or confirm SQLite-dev fallback) | M1 | week 2 | `[ ]` | ADR-007 |
| T-035 | Android bootcamp (6 sessions) + DIVA/InjuredAndroid manual write-up by all | M1 | week 3 | `[ ]` | R-05 |
| T-036 | Hand-label 30-item pilot corpus with negative controls | M2/M5 | week 2–3 | `[ ]` | T-032 depends on it |

## W3 — Phase 2 core foundation (after approval)

| # | Task | Owner | Depends on |
|---|---|---|---|
| T-040 | Repo skeleton: packages, layer boundary, import-lint test | M1 | T-024 |
| T-041 | Pydantic schemas (frozen interface) | M1 | T-040 |
| T-042 | Alembic migrations for the full schema | M1 | T-041 |
| T-043 | `events` append + `LISTEN/NOTIFY` bridge | M1 | T-042 |
| T-044 | `frontier_entries` queue with `SKIP LOCKED` claim | M1 | T-042 |
| T-045 | FSM with event-on-every-transition + coverage test | M1 | T-043 |
| T-046 | `ToolAdapter` protocol + `ToolSpec` + runner sandbox | M2 | T-041 |
| T-047 | `ToolUnavailable` path end-to-end | M2 | T-046 |
| T-048 | API: applications, authorisations, scans (CRUD + state) | M1 | T-041 |
| T-049 | Auth (JWT) + authorisation guard middleware | M1 | T-048 |
| T-050 | Frontend shell, tokens, generated API client | M6 | T-048 |
| T-051 | Event stream client + idle/empty/error states **first** | M6 | T-043, T-050 |
| T-052 | `POST /ask` with grounding validator | M1 | T-048 |

## W4 — Phase 3 RECON (first real capability)

| # | Task | Owner |
|---|---|---|
| T-060 | Androguard manifest adapter (pure Python — works without a JDK) | M2 |
| T-061 | Component/permission/intent-filter extraction + `export_reason` | M2 |
| T-062 | **API-31 exported-by-implication fixture + test** | M2 |
| T-063 | Certificate parsing (v1/v2/v3, debug, expiry) | M2 |
| T-064 | Network security config parser | M2/M4 |
| T-065 | DEX/native/asset inventory | M2 |
| T-066 | Evidence write + `source_ref` provenance | M2 |
| T-067 | Graph nodes/edges from manifest (assertion=`observed`) | M1 |
| T-068 | RECON acceptance: DIVA component set precision/recall ≥ 0.9 | M2/M5 |

## W5–W6 — Phase 4 SPECTRE (needs JDK host)

| # | Task | Owner | Gate |
|---|---|---|---|
| T-070 | JADX adapter with cache-by-APK-hash | M2 | T-030 |
| T-071 | `fidelity` tagging + smali fallback + `decompiler-failed` | M2 | |
| T-072 | Targeted lookup primitives (class/method/api-refs/string/callers) | M2 | |
| T-073 | Sensitive-API YAML catalogue → MASWE mapping | M2/M5 | |
| T-074 | SPECTRE agent (workhorse tier) + prompt v1 | M1 | T-032 |
| T-075 | First three gates implemented as predicates + pos/neg tests | M1/M5 | |
| T-076 | Code Studio: real decompiled source + highlight ranges | M6 | T-070 |

## W7–W8 — Phase 5 NEXUS + VERITAS + end-to-end slice

| # | Task | Owner |
|---|---|---|
| T-080 | Frontier scorer + explainable components | M1 |
| T-081 | Hypothesis generation from observations (templated `required_evidence`) | M1 |
| T-082 | Decision records incl. rejected alternatives | M1 |
| T-083 | Budget enforcement + `BUDGET_EXHAUSTED` path | M1 |
| T-084 | VERITAS agent on a *different* model + startup assertion | M1 |
| T-085 | Remaining seven gates | M1/M5 |
| T-086 | `tests/integrity` — the four CI assertions | M5 |
| T-087 | War Room: battlefield + agent network + feed | M6 |
| T-088 | Findings view + hypothesis panel (`required` vs `satisfied`) | M6 |
| T-089 | Markdown report with coverage + unknowns | M1 |
| T-090 | **Slice acceptance: one real APK investigated end-to-end** | All |

## W8–W10 — Conditional: PHANTOM / VECTOR / graph UI

Only if T-030 and T-031 are resolved favourably **and** the slice is green.

| # | Task | Owner | Condition |
|---|---|---|---|
| T-100 | Emulator harness + isolation + snapshot policy | M3 | KVM host |
| T-101 | adb + logcat capture → evidence | M3 | T-100 |
| T-102 | Frida observation scripts (no bypass) | M3 | T-100 |
| T-103 | PHANTOM agent + runtime gates | M3 | T-102 |
| T-104 | mitmproxy adapter + request replay | M4 | |
| T-105 | VECTOR agent + auth/TLS gates | M4 | T-104 |
| T-106 | Bounded graph view (React Flow) + `truncated` signalling | M6 | |

## W10–W12 — Evaluation, hardening, defence

| # | Task | Owner |
|---|---|---|
| T-110 | Full benchmark run on all models; fill `MODEL_BENCHMARKS.md` | M5 |
| T-111 | Held-out precision measurement; false-positive taxonomy | M5 |
| T-112 | MobSF baseline comparison (HTTP, ADR-013) | M2 |
| T-113 | Prompt-injection suite (G7) + results | M5 |
| T-114 | Fault-injection suite (`AGENT_DESIGN.md §8`) | M1 |
| T-115 | Playwright anti-fabrication tests | M6 |
| T-116 | Recorded real scan for demo fallback (labelled as recorded) | M6 |
| T-117 | Final report + defence script answering §6 questions | All |

## Deliberately not on this board

`ORACLE` agent · C2 threat-research screen · 9 of 14 screens · Redis · graph database · microservices ·
fine-tuning · multi-model voting · exploit generation · PDF pipeline (Markdown + print). See
`REQUIREMENTS.md §3`.
