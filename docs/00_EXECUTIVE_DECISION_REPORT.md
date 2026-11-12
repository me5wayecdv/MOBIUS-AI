# EXECUTIVE DECISION REPORT — MOBIUS Phase 0 / Phase 1

**To:** Project Director
**From:** Arena.ai Agent Mode (Chief Architect role)
**Date:** 2026-11-12
**Branch / base:** `arena/bd856c58-mobius-ai` @ `712f7b8`
**Status:** **AWAITING APPROVAL — no implementation has begun**

---

## 1. Executive summary

MOBIUS is a sound and unusually well-specified ambition, and its central thesis — *investigate, gather
evidence, challenge your own conclusions* — is both achievable and genuinely differentiating. But it
cannot be built as specified, and the gap is not a matter of effort.

Five findings dominate this report:

1. **The environment cannot run the product.** This sandbox has no JDK, no Docker and no `/dev/kvm`
   (`ENVIRONMENT_AUDIT.md` §1). It can *build* MOBIUS; it cannot *execute* the analysis pipeline. Until a
   host with a JDK is confirmed, Phases 3–7 are blocked. This is the most urgent action in the project.

2. **The scope is roughly 3–5× a semester.** Eight agents, fourteen screens, twelve phases and thirty
   entities — for six students, five new to Android. The brief itself demands that breadth not be faked,
   which makes breadth structurally impossible. Something must be cut; the only question is whether it is
   chosen deliberately now or panic-cut in week 11.

3. **The core premise is untested.** Everything assumes an LLM can triage Android code at useful
   precision. Published evidence is sobering: state-of-the-art agents reach ≤ 18% on PoC generation and
   ≤ 34% on patching for real security tasks [S1]. If negative-control precision lands near 40%, MOBIUS
   is an efficient false-positive generator and no amount of event architecture fixes that. **This must
   be measured in week 3, not discovered in week 12.**

4. **The right architecture is simpler than the brief proposes.** Deterministic control flow with
   model-driven content; Postgres for state, queue and events (no Redis); adjacency tables (no graph
   database); agents as typed functions (no framework). Each simplification is defended in
   `ARCHITECTURE_DECISIONS.md`, and each removes a failure mode rather than a feature.

5. **The supplied C2 document is usable defensively and has already earned its place.** Read as threat
   intelligence it produces a concrete architectural change: the `dynamic-code-loading` gate must use
   *data flow*, not API presence. Read as a build specification, it is out of scope and this project will
   have nothing to do with it (`ORACLE_THREAT_INTEL.md §0`).

**Recommended path:** approve a **vertical slice** — one complete investigation path from APK upload to
report, with three agents in code, five views, deterministic gates, full audit trail — and run the
precision pilot before building the War Room.

## 2. What was actually done

| Phase | Deliverable | State |
|---|---|---|
| 0 | Environment, repository and capability audit | **Complete, measured** |
| 1 | 22 specification/methodology/decision documents | **Complete, awaiting approval** |
| 2+ | Implementation | **Not started** — by instruction |

No existing file was deleted or rewritten. The repository contained a single 56-byte `README.md`.

**On the multi-model protocol (§2 of the master prompt):** true parallel agents are **not available**.
Seven specialist analyses were produced sequentially in one context and are labelled as such
(`SPECIALIST_REPORTS.md` preamble). `§8` of that document lists six places where a later analysis
*reversed* an earlier one — the honest evidence of non-independence, and also where the most useful
engineering happened.

## 3. Cross-specialist synthesis

### 3.1 Strong agreements

| # | Agreement | Consequence |
|---|---|---|
| 1 | Severity, confidence and verdict status must remain independent | Schema enforces it; no composite risk score |
| 2 | "Not found" ≠ "not present" | `INSUFFICIENT_EVIDENCE` is a first-class verdict |
| 3 | Scanner-style pattern matching is the failure mode to avoid | Ten confirmation gates as code predicates |
| 4 | Rejected findings must persist with reasons | `REJECTED` is a status, never a deletion |
| 5 | Prompt injection from APK content is a real, unaddressed risk | Defence in depth; gates are the load-bearing control |
| 6 | The event log is the product's spine, not logging | Append-only, correlated, replayable |
| 7 | Demonstrating precision matters more than demonstrating breadth | Benchmark-first, negative controls mandatory |

### 3.2 Conflicts — preserved, not smoothed

| # | Conflict | Positions | Status |
|---|---|---|---|
| **C-1** | Precision vs demonstrable coverage | E: strict gates, accept lower recall. G: systematic abstention may read as "it doesn't work". | **Unresolved → Director** |
| **C-2** | PHANTOM in or out | B: defer — highest cost, lowest certainty. G: it is the differentiator; deferring leaves a static analyser with an LLM on top, i.e. the thing the brief forbids. | **Unresolved → Director. Most consequential decision in this report.** |
| **C-3** | Full attack graph vs reachability view | A: full graph with React Flow. G: cut to a tree for v1. | Resolved: ADR-014 (reachability view in v1, real graph model underneath) |
| **C-4** | 7 agents vs 3 | C: full contract set. G: 3 for v1. | Resolved: 3 in code, contracts designed so the rest are additive |
| **C-5** | How agentic is it, really? | G: the frontier scorer is a hand-tuned best-first search, not "adaptive planning"; calling it that overclaims. | **Accepted.** The report must say "best-first search with a heuristic evaluation function". Honesty here matters more than the marketing. |

### 3.3 Unsupported assumptions exposed

| Assumption | Reality | Fix |
|---|---|---|
| "We can run an emulator" | No KVM; emulator detection is trivial even with one | Decide PHANTOM now |
| "The LLM can triage Android code" | Untested here; published ceilings are low [S1] | Week-3 pilot (T-032) |
| "The team can judge output quality" | 5 of 6 have limited Android background | Mandatory manual DIVA/InjuredAndroid lab |
| "Different models per agent is feasible" | Evaluation cost infeasible in one semester | Two tiers (ADR-010) |
| "Redis is needed for real-time events" | Postgres `LISTEN/NOTIFY` + a durable table suffices | ADR-007 |

## 4. Independent critique — the five things that can kill this project

1. **No execution host.** Highest probability, highest impact, cheapest to fix, and nobody has fixed it.
2. **The premise is unmeasured.** The whole design rests on an assumption with unflattering prior
   evidence. Measure it at week 3.
3. **Scope.** Even the trimmed slice is a full semester of full-time work for experienced engineers.
4. **Self-review bias.** One model validating its own findings is theatre. Enforce model diversity.
5. **The "MobSF + GPT" objection.** A panel will ask it. The only good answer is a number: precision on
   negative controls, abstention correctness, and gate-evidence completeness — measured against MobSF as
   a baseline.

## 5. Final architecture — one page

```
                    ┌──────────────────────────────────────────┐
   War Room (5) ────▶│ API  REST /api/v1 · SSE-or-WS /ws/scans  │
                    └───────────────┬──────────────────────────┘
                                    │ Postgres: state · events · frontier · graph
                    ┌───────────────▼──────────────────────────┐
                    │ Orchestrator — FSM + frontier + budgets  │
                    │  RECON(det) · SPECTRE(model) · VERITAS   │
                    │  (model, DIFFERENT model) · ARCHIVIST    │
                    └───────────────┬──────────────────────────┘
                                    │ validated argv only, no creds, no egress
                    ┌───────────────▼──────────────────────────┐
                    │ Analysis runner — unprivileged, rlimited │
                    │  androguard · jadx · apktool · aapt2     │
                    └──────────────────────────────────────────┘

Invariants: control flow deterministic · findings need gate predicates · every claim needs evidence ·
            every state change is an event · abstention is legal and reported
```

Full detail: `ARCHITECTURE.md`. Agent contracts: `AGENT_DESIGN.md`.

## 6. Technical risk summary

| Tier | Risks |
|---|---|
| **Tier 1 (project-threatening)** | R-01 no execution host · R-02 PHANTOM undeliverable · R-03 premise unvalidated · R-04 scope |
| Tier 2 (serious) | R-05 team Android background · R-06 gate overfitting · R-08 prompt injection · R-09 data sharing · R-10 real-time UI cost |
| Tier 3 (manageable) | 10 further risks, mitigated in place |

Full register: `TECHNICAL_RISK_REGISTER.md`.

## 7. Decisions required from the Project Director

| # | Decision | Options | Recommendation | Blocks |
|---|---|---|---|---|
| **D-1** | Approve Phase 1 documentation | approve / revise / reject | **Approve**, with `REVIEW_LOG.md` edits | Everything |
| **D-2** | Execution host with a JDK (+Docker) | team laptop / CI runner / cloud VM / none | **Name one owner and a date this week** | Phases 3–7, R-01 |
| **D-3** | PHANTOM in or out | in (accept schedule risk) / out (protect schedule, weaken thesis) / recorded-session compromise | **Recorded real session + designed-but-unbuilt PHANTOM** — the honest middle. Requires your call. | M3's plan, the thesis |
| **D-4** | Approve vertical slice (ADR-015) | approve / keep master-prompt phasing | **Approve** | Phase 2 start |
| **D-5** | LLM data-sharing policy | off by default / on with consent / never send code | **Off by default, per-scan opt-in, redaction, UI badge** | ADR/B6 design |
| **D-6** | Postgres availability | managed / dev container / SQLite-only | **Managed or container**; SQLite is demo-only | ADR-007 |
| **D-7** | Negative-control app selection | which 2–3 benign apps | **Choose apps you can justify to a panel** | Any precision claim |

**D-2 and D-3 cannot be deferred.** Every other decision can absorb a week of delay; these two determine
what the project is.

## 8. Proposed first milestone (do not start before approval)

**M1 — "One honest investigation"** (8 weeks)

> Upload DIVA → authorise → RECON produces a component/permission surface → NEXUS selects 3–4 targeted
> code checks → SPECTRE reads them → three gates evaluate → VERITAS validates on a different model →
> evidence stored → 15-node reachability view → War Room shows only real events → Markdown report that
> states what was found, what was rejected, and what could not be determined.

**Acceptance criteria:**
1. Runs unattended, end-to-end, on two APKs (DIVA + one benign control).
2. Every confirmed finding passes its gate, provably (`gate_evidence` stored).
3. Every claim resolves to stored evidence; the CI integrity test passes.
4. The War Room shows zero fabricated events (Playwright idle test).
5. The report's "not determined" section is non-empty.
6. Precision on the benign control ≥ 0.85, or a written explanation of exactly why not.

If milestone M1 is green, MOBIUS has a credible graduation project. If it is not green, no amount of
additional screens or agents would have saved it.

## 9. What I recommend *not* building

Fourteen screens → five. Eight agents → three in code. ORACLE as a module → a gate instead. Redis →
Postgres. Graph database → adjacency tables. Agent framework → 200 lines. PDF pipeline → Markdown.
Per-agent model routing → two tiers. "Adaptive planning" as a phrase → "best-first search with a
heuristic evaluation function".

Each removal is a *credibility* gain. A panel can verify five real views and three real agents. It cannot
verify fourteen mocked ones, and it will notice.

---

## Sources

- [S1] SEC-bench (2025), ≤ 18.0% PoC / ≤ 34.0% patching for SOTA code agents: https://arxiv.org/pdf/2506.11791
- [S2] SEC-bench Pro (2026), grader design inflates measured success by 43.6%: https://arxiv.org/html/2605.26548v1
- [S3] OWASP MASVS v2.1.0 / MASTG v2.0.0 / MASWE v1.0.0: https://mas.owasp.org/news/
- [S4] ReAct production failure modes: https://blog.llmgo.top/en/articles/agent-loop-state-machine/
- [S5] JADX 1.5.6 / Apktool 3.0.3 / Androguard 4.1.4 / MobSF 4.6.4 — release pages, Oct–Nov 2026
