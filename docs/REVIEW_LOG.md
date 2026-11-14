# REVIEW LOG

Every review, decision request and supersession is recorded here. Newest first.

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

## Supersessions

| ADR | Superseded by | Reason |
|---|---|---|
| — (master prompt: Redis pub/sub) | ADR-007 | Redundant hop; Postgres gives durability + replay with one fewer service |
| — (master prompt: per-agent models) | ADR-010 | Evaluation cost infeasible; two tiers capture most benefit |
| — (master prompt: 14 screens) | ADR-015 | Breadth forces mocks, which the brief forbids |
| Specialist A (full graph UI) | ADR-014 | G's critique: reachability view answers the same question for ~10% of the code |
