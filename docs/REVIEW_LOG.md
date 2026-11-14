# REVIEW LOG

Every review, decision request and supersession is recorded here. Newest first.

---

## 2026-11-13 · RL-006 · SPECTRE — the real APK found five bugs the fixtures hid

**Scope:** dex indexing, call graph, reachability search, SPECTRE service, `POST
/scans/{id}/spectre`. Tests 176 → 243 (6 skipped, Postgres-only).

Every finding below came from running the pipeline against a real APK
(`com.politedroid_4.apk`, 18 489 bytes) or from a test that contradicted an assumption — not
from review. The synthetic fixtures passed throughout; four of these bugs were invisible to
them.

| # | Finding | Resolution |
|---|---|---|
| 1 | A guard on the caller (`checkCallingPermission` and friends) was mapped to `not-reachable`, telling the analyst "there is no path" when the truth was "there is a path and it is checked" | New reason `guarded-by-caller-check`. A guard refutes `caller_check_absent`; it says nothing about reachability |
| 2 | The call graph contained only methods that had internal callees, so lifecycle methods with no in-app callees were simply absent — the entry point of the only candidate did not exist in the graph | Every method is seeded as a node; `internal_calls` counts edges separately from `graph_nodes` |
| 3 | Entry points were matched by `MethodRef(class, name)` with an **empty descriptor**, so real `onReceive(Context,Intent)V` never matched and the app reported `no-entry-point` | `CallGraph.methods_named()` matches by name and returns the overloads |
| 4 | A `None` clause value counted as a failed clause, so a candidate the tool had never refuted came out `rejected` — an absence of evidence reported as evidence of absence | `Clause.absence_is_evidence` + `GateResult.failed_decisively`; decisive failure is checked before missing, so `None` yields `insufficient_evidence` |
| 5 | **A false positive.** With the graph finally working, the real APK produced `confirmed`: exported receiver → `SharedPreferences.getString` → "shared-prefs" sink | The sink was not a sink. Reading a preference discloses nothing; reachability without data flow cannot tell that from exfiltration. `shared-prefs` and `intent-redirect` removed from the catalogue, with a regression test asserting they stay out |

| 6 | A complete search that reached **nothing** reported `caller_check_absent: true` and `path_length: 0` — a claim about a call chain that does not exist, reading as "the entry point is the sink" | Both are `null` when there is no path. Only a reached path can say anything about the checks on it |
| 7 | Stored `gate_evidence` collapsed the tri-state to booleans, so a clause nothing had been offered as evidence about was stored as `false`, indistinguishable from "refuted" | `as_gate_evidence()` emits `null` for never-established; `Finding.gate_evidence` and `VerdictRecord.gate_detail` accept the third state |
| 8 | The finding title said "reachability not established" on a finding whose verdict was a *decisive* refutation | The title now follows the verdict: "no sensitive sink reachable in the application code" |

Findings 6–8 were all found by reading the JSON of a live `curl` run rather than by a test —
the stored record disagreed with what the pipeline had actually established. Finding 5 is the
one worth keeping: the pipeline's first confirmed finding on real code was
wrong, and it was wrong because the catalogue was written by enumeration rather than by a
rule. The rule now stated in `sinks.py` is that a sink must be an operation whose *execution*
is security-relevant. After the tightening the same APK is correctly `not-reached` →
`REJECTED` over a complete traversal of six methods.

**What is proven now.** A real APK, parsed by real androguard, yields a real graph (10
classes, 34 methods, 41 internal calls) and a deterministic verdict. Truncation is never
refutation, asserted by test. The gate can reject on exhaustive absence.

**Still unproven.** No confirmed true positive on real code — the corpus has no app with the
pattern, so every "confirmed" verdict so far comes from synthetic dex. No multi-dex, no
obfuscated app, no reflection, no data flow. JADX-level understanding of the reachable
methods is not attempted. The Postgres trigger remains unexecuted.

---

## 2026-11-13 · RL-003 · Review findings resolved — **AWAITING DIRECTOR REVIEW**

**Addresses:** RL-002 findings I-01 … I-10.
**Scope:** documentation only; no code, no dependencies, no migrations.
**Base:** `f3d189e` (post-merge).

### Blocking findings — resolved

| # | Finding | Resolution |
|---|---|---|
| I-01 | `approvals` table did not exist | Added `DATABASE_SCHEMA.md §3.10` — 15 columns, 5 CHECK constraints, 2 indexes (incl. partial index on `state='pending'`), expiry enforced by worker filter + sweeper. ER diagram updated. §8 gains integrity assertion #5. |
| I-02 | `PAUSED` would be rejected by `state_known` | Resolved as a **flag, not a state** (ADR-017): `paused_at`, `paused_by`, `pause_reason`, `pause_is_coherent` CHECK. All four artefacts now agree — `state_known` stays at 15 values. |
| I-03 | `ModelGateway` in `adapters/`, imported by Layer 1 | Moved to `mobius/core/ports.py` with `EvidenceReader`, `ToolInvoker`, `EventEmitter`, `BudgetMeter`. Layering note added to `MODEL_ROUTING.md` and `AGENT_DESIGN.md`. |
| I-04 | `intensity_within_authorization` enforced nothing | Renamed to `intensity_range` (honest local guard) and the real cross-table control implemented as `enforce_authorization_scope()` trigger covering revoked, expired, null-authorisation and over-grant, with `INTAKE`/`SCOPE_BLOCKED` exempt so refused scans stay auditable. |
| I-05 | Agent count stated as 3 / 4 / 6 | Canonical wording fixed in `AGENT_DESIGN.md §5` and the executive report; ASCII architecture box redrawn; Specialist A's superseded "six" **annotated, not rewritten** (ledger integrity). |

### Non-blocking findings — resolved

| # | Finding | Resolution |
|---|---|---|
| I-06 | `agent_message` event dropped without record | Retirement documented in `EVENT_ARCHITECTURE.md §4`, with `investigation_paused`/`investigation_resumed` added. |
| I-07 | `pgr_path(...)` implied a rejected dependency | Replaced with a description of the bidirectional BFS and why path search is not SQL. |
| I-08 | `CURRENT_REPOSITORY_STATE.md` missing | Added as a Phase 0 deliverable with a falsification procedure. |
| I-09 | Docker not recorded as a sandbox dependency | **ADR-016** makes a container runtime a hard prerequisite for untrusted APKs and requires the degraded state to be reported, not assumed. |
| I-10 | `include_unknowns` could be set `false` despite text | Now rejects `false` with `422`; `paused` added to the scan response model. |

### New decisions in this revision
- **ADR-016** — container runtime required for the runner sandbox (closes A-07).
- **ADR-017** — pause is a flag, not an FSM state (closes I-02).

### Not addressed (requires a decision or an environment)
- Mermaid diagrams still unrender-validated (no renderer in the environment).
- SQL DDL still never executed against a real Postgres.
- R-01 (execution host), R-02 (PHANTOM in/out), ADR-015 (vertical slice) — all still **awaiting the
  Project Director**. Merging documentation does not resolve any of them.


---

## 2026-11-12 · RL-002 · Phase 1 documentation — **AWAITING DIRECTOR REVIEW**

**Produced by:** Arena.ai Agent Mode (single agent, sequential — see `SPECIALIST_REPORTS.md` preamble)
**Scope:** Phase 0 + Phase 1 documentation set (22 documents + README)
**No code written.** No existing files deleted. Base commit `712f7b8` untouched apart from added files.

### What was produced
`ENVIRONMENT_AUDIT` · `PROJECT_CONTEXT` · `REQUIREMENTS` · `ARCHITECTURE` · `AGENT_DESIGN` ·
`ANDROID_SECURITY_METHODOLOGY` · `DATABASE_SCHEMA` · `API_SPECIFICATION` · `EVENT_ARCHITECTURE` ·
`THREAT_MODEL` · `MODEL_ROUTING` · `MODEL_BENCHMARKS` · `SPECIALIST_REPORTS` · `ORACLE_THREAT_INTEL` ·
`ARCHITECTURE_DECISIONS` · `TECHNICAL_RISK_REGISTER` · `TEAM_RESPONSIBILITIES` · `HANDOFF_PROTOCOL` ·
`TASK_BOARD` · `IMPLEMENTATION_STATUS` · `REVIEW_LOG` · `00_EXECUTIVE_DECISION_REPORT`

### Key positions taken (all challengeable)
1. **Parallel multi-agent execution is unavailable.** Reported honestly rather than simulated.
2. **The environment cannot run the Android toolchain** (no JDK, Docker, or KVM). This is the top risk.
3. **Scope must be cut** to a vertical slice: 3 agents in code, 5 views. ADR-015 needs approval.
4. **Control flow must be deterministic**; the model supplies content only (ADR-003/004/012).
5. **Confirmation gates are code predicates**, which is also the prompt-injection control.
6. **No Redis, no graph DB, no agent framework, no message broker** — each rejected with a reason.
7. **The C2 research document is treated as defensive threat intel only** and drives a concrete
   architecture change (`dynamic-code-loading` gate with data-flow).

### Open disagreements escalated
| # | Disagreement | Needs |
|---|---|---|
| D-1 | Precision-first gates (E) vs recall and demonstrable coverage (G) | Director's posture decision |
| D-2 | PHANTOM deferred (B) vs PHANTOM essential to the thesis (G) | Director decision — **most consequential** |
| D-3 | Full graph vs reachability view | Resolved in ADR-014 for v1; v2 revisits |

### Decisions requested (see `00_EXECUTIVE_DECISION_REPORT.md §7`)
Q1 execution host · Q2 Postgres · Q3 PHANTOM in/out · Q4 scope approval (ADR-015) · Q5 LLM data-sharing
policy · Q6 negative-control app selection

### Reviewer's standing instruction
If a reviewer of this document concludes "looks good", the review has failed. The useful output is a
list of ways each gate and each architectural claim can be wrong (template in `HANDOFF_PROTOCOL.md §5`).

---

## 2026-11-12 · RL-001 · Phase 0 environment audit

**Result:** Environment measured; five capabilities the project assumed were found absent
(JDK, Docker, KVM, general egress, parallel agents). Recorded in `ENVIRONMENT_AUDIT.md`.
**Consequence:** ADR-002 (configurable tool plane) and R-01 elevated to Tier 1.
**No code changes.** No conflict with any prior decision (none existed).

---

## 2026-11-12 · RL-004 · Phase 2 vertical slice — what the tests found

**Scope:** first implementation pass: Layer-1 core, SQLAlchemy mapping, intake/validation
services, HTTP API, 142 tests.

**Findings that changed the code**, each found by a failing test rather than by review:

| # | Finding | Resolution |
|---|---|---|
| 1 | SQLAlchemy ordered INSERTs by mapper definition, not foreign key, and **dropped a pending parent entirely** (`users` was never emitted) → `FOREIGN KEY constraint failed` | ADR-019: explicit flush order in services; relationships deliberately not used |
| 2 | A "missing" attribute is not equivalent across predicate kinds: for `_is_empty` (no `android:permission`) absence **is** the evidence, for `_is_true` absence means unestablished | Kept the semantics, documented in `test_gates.py`; `missing_attributes` reported independently of `failed` |
| 3 | My first `Finding` fixture assumed a confirmed finding could hold confidence 0.42 | The schema refused it. Confirmed ⇒ confidence 1.0 stays |
| 4 | State spelling: I assumed lowercase `recon` on the wire | `API_SPECIFICATION.md` already specifies `RECON`. Code matched the spec; the test was wrong |

**Corrections to earlier claims in this log.** Nothing previously marked `DONE` regressed;
all prior rows were documentation and remain accurate. The README's "No code exists yet"
was true when written and is now false — updated in the same commit.

**Still unproven, restated:** the PostgreSQL trigger has never executed (6 tests skip);
no Android tool has been invoked; no model has been called; no benchmark number exists.

---

## 2026-11-12 · RL-005 · RECON and the event stream

**Scope:** binary manifest decoding, surface derivation, RECON service, SSE stream. Tests
142 → 176.

**Findings**, each from a failing test or a failing server rather than from review:

| # | Finding | Resolution |
|---|---|---|
| 1 | A hand-written AXML encoder produced a file androguard rejected from the third element onward: the start-element chunk size omitted the 20-byte `attrExt` header, so the parser lost alignment | Chunk size = `36 + 20*attrs`. Three encoder bugs found this way, none of which review would have caught |
| 2 | All `TYPE_STRING` attribute values decoded as empty | `rawValue` must be the string-pool index, as aapt writes it; `NO_ENTRY` made androguard return `b''` |
| 3 | androguard's XML output declares `xmlns:android` but writes attributes **unprefixed**, so `{uri}name` lookups silently returned `None` — a fully exported app read as inert | Bare-name fallback in `_android()`. Caught only because the binary fixture was checked end to end |
| 4 | `uvicorn` on a fresh checkout died with `sqlite3.OperationalError: unable to open database file` | `AppContext` now creates the artefact root and the SQLite parent directory; test added. An error that points at the wrong subsystem is worse than no error |

**Not a finding, worth recording:** RECON's outputs are deliberately insufficient to confirm
anything. `test_recon_candidates_can_never_confirm` asserts `insufficient_evidence` for every
candidate it produces. This is the first point where the project's central claim is enforced by
a test rather than by prose.

**Still unproven:** no real-world APK has been parsed (no sample available — only a synthetic
AXML fixture validated against androguard); no model has been called; no dex/string/certificate
analysis exists; the PostgreSQL trigger remains unexecuted.

---

## Supersessions

| ADR | Superseded by | Reason |
|---|---|---|
| — (master prompt: Redis pub/sub) | ADR-007 | Redundant hop; Postgres gives durability + replay with one fewer service |
| — (master prompt: per-agent models) | ADR-010 | Evaluation cost infeasible; two tiers capture most benefit |
| — (master prompt: 14 screens) | ADR-015 | Breadth forces mocks, which the brief forbids |
| Specialist A (full graph UI) | ADR-014 | G's critique: reachability view answers the same question for ~10% of the code |
