# SPECIALIST ANALYSES (Agents A–G)

> **Honest framing (read first).** The master prompt asked for seven independent agents working in
> parallel before synthesis. **That capability does not exist in this environment** (`ENVIRONMENT_AUDIT.md` §2).
> These seven analyses were produced **sequentially in a single context**. They are therefore *not*
> independent in the statistical sense: a later analysis cannot be blind to an earlier one.
>
> Two mitigations are applied rather than hidden:
> 1. Each analysis was written to completion before the next was started.
> 2. **§8 lists the places where a later analysis reversed or overruled an earlier one.** That list is
>    the observable evidence of non-independence, and it is also where the most useful engineering
>    happened. If there are no reversals, be suspicious — consensus by default is a symptom, not a
>    result.
>
> Genuine independence requires separate sessions (`HANDOFF_PROTOCOL.md`).

Each section follows the required template: findings · evidence · assumptions · proposal ·
alternatives · advantages · disadvantages · risks · dependencies · complexity · open questions ·
recommendation. Fields with nothing substantive say so rather than padding.

---

## A — Principal System Architect

**Findings.**
1. The master prompt specifies 8 agents, 14 screens, 12 phases, 30+ entities and a real-time event
   pipeline — for a 6-person team, 5 of whom are new to Android, over one semester. That is roughly
   3–5× the work that can be built *and verified* at the quality the document itself demands.
2. The requirement "every visual state must be driven by actual backend data" is architecturally
   incompatible with a wide-but-shallow build: breadth forces mocks.
3. The proposed stack (FastAPI + Postgres + Redis + WS + React) is sound; the proposed *topology* is
   over-specified for the load.
4. The single highest-risk architectural ambiguity is **where the analysis workers run** — it is
   unresolved and it gates Phases 3–7.

**Evidence.** `ENVIRONMENT_AUDIT.md` §4 (measured absence of JDK/Docker/KVM); master prompt §10, §12,
§13 (breadth); `TECHNICAL_RISK_REGISTER.md` R-01.

**Assumptions.** A-01 (implementation host has JDK+Docker); the team can meet weekly; one member owns
frontend exclusively (per §17).

**Proposal.** Modular monolith, three entrypoints, one Postgres, Postgres-backed queue and event
stream, vertical slice first (`ARCHITECTURE.md` §8). Six agents in code, three of which are
deterministic, no model. **[Superseded — see §8 reversal #4: v1 ships 3 agents, not 6.]**

**Alternatives.** (a) Follow the master prompt literally → high risk of an unverifiable demo.
(b) Split into microservices → no benefit, large cost. (c) Ship a scanner + LLM summary → fast, but
fails the project's entire premise.

**Advantages of proposal.** Every displayed state is realisable from real data; the audit trail is
buildable; the team can work in parallel on frozen interfaces.

**Disadvantages.** Cuts 9 of 14 screens and 3 of 8 agents from v1. The panel will see less surface area.

**Risks.** The cut may be read as under-delivery. Mitigation: publish `IMPLEMENTATION_STATUS.md`
openly and frame the slice as depth-over-breadth with measured precision.

**Dependencies.** Director approval of scope; environment decision (Q1).

**Complexity.** Medium-high overall; low per component because of the interfaces.

**Open questions.** Is a *demonstrable* narrow system preferred over a broad partial one? (The
document says yes — §24 "genuine investigation intelligence" — but the Director must confirm.)

**Recommendation.** Adopt the vertical slice. Do not start Phase 3 until the analysis host is decided.

---

## B — Android Security Researcher

**Findings.**
1. MASVS v2.1.0 + MASTG v2.0.0 + MASWE v1.0.0 is the correct current chain; the widely-copied
   "MASVS-L1/L2" material is obsolete. MOBIUS should emit `MASVS → MASWE → MASTG` IDs.
2. The `android:exported` API-31 change is the highest-value parsing subtlety and a common source of
   both false positives and false negatives (`ANDROID_SECURITY_METHODOLOGY.md` §2.1).
3. Most "findings" produced by scanners in this space are surface patterns that fail a two-minute
   manual check (MD5 for cache keys, exported launchers, external-dir thumbnails). The gate model is
   the correct response.
4. Resilience/dynamic analysis (Frida, root bypass, pinning) is where schedules die.
5. A competent attacker in 2026 uses a thin stager + in-memory DEX modules, so **static analysis of
   `classes.dex` alone is insufficient by design** — that is an architectural fact, not an edge case.

**Evidence.** MASVS/MASTG/MASWE release notes [S1][S2]; tool versions and caveats [S3][S4][S5];
`ORACLE_THREAT_INTEL.md` §3.

**Assumptions.** Target apps are ordinary release APKs, not hardened banking apps (A-04).

**Proposal.** Ten vulnerability classes with explicit gates; deterministic RECON; JADX with
`fidelity` tagging and smali fallback; PHANTOM deferred.

**Alternatives.** (a) MobSF as the engine → GPL and same signals, no research contribution.
(b) Broad pattern matching → scanner behaviour, high FP. (c) Focus on native/Ghidra → high cost,
narrow relevance.

**Advantages.** Defensible verdicts; honest abstention; measurable precision.

**Disadvantages.** Narrower coverage than a scanner's rule list.

**Risks.** Gate predicates may be too strict → recall collapse. Mitigate by measuring on DIVA and
tuning gates against negative controls only (never against the positive set, which would overfit).

**Dependencies.** JADX availability (JDK host); hand-labelled ground truth (Member 2, ~2 weeks).

**Complexity.** Medium for static; high for dynamic.

**Open questions.** Is PHANTOM in scope at all? (Blocks Member 3's work assignment.)

**Recommendation.** Static-first. Treat "static analysis is insufficient, dynamic required" as a
first-class *finding*, not a failure.

---

## C — AI Agent Architect

**Findings.**
1. The master prompt's own example message schema conflates observation, inference and decision. That
   conflation is the mechanism by which agentic security tools lose the ability to distinguish fact
   from belief.
2. Unconstrained ReAct loops fail in production in four documented ways: retry storms, context
   snowball, dirty-state contamination, and no rollback [S6]. All four apply directly to a tool that
   runs decompilers.
3. Seven agents do not require seven loops. An agent-as-function with a typed contract is testable
   with a stub model; an agent-as-loop is not.
4. Prompt injection via APK content is the dominant *new* risk in this product class and is
   essentially unaddressed in the master prompt (`THREAT_MODEL.md` §4).
5. "Adaptive planning" is best implemented as arithmetic ranking over a persisted frontier, with the
   model supplying candidate hypotheses and parameters — not rankings.

**Evidence.** [S6] enumerated ReAct failure modes; [S7] on the planning/execution separation and its
cost/auditability trade-offs; `THREAT_MODEL.md` §4.

**Assumptions.** A-05 (structured-output support available).

**Proposal.** FSM for control flow; closed action registry; persisted frontier with an explainable
score; model output schema-validated with a bounded repair loop; confirmation decided by code
predicates, never by model prose.

**Alternatives.** (a) LangGraph/CrewAI → cedes the state model and audit trail. (b) Pure LLM planner →
non-reproducible, unbounded cost. (c) Fixed pipeline → fails the premise.

**Advantages.** Deterministic cost ceiling; replayable investigations; an injection cannot manufacture
a confirmed finding because gates are code.

**Disadvantages.** Less "emergent" behaviour; the demo depends on frontier scoring being well-tuned.

**Risks.** Frontier scoring coefficients are hand-tuned and may be poor initially; mitigations are
empirical priors and a hard depth decay. Bad scoring produces wandering, which looks unintelligent.

**Dependencies.** Registry of actions; the gate predicates from B; a stub model for tests.

**Complexity.** Medium. The score function is ~15 lines; the discipline is in not letting the model
control flow.

**Open questions.** Should the model be allowed to *propose new hypotheses* freely, or choose from a
hypothesis template library? (Recommend: free-form hypothesis text, templated `required_evidence`.)

**Recommendation.** Adopt. The central claim worth defending to a panel is: *control flow is
deterministic, judgement is model-driven, and the boundary is enforced in code.*

---

## D — Backend & Infrastructure Architect

**Findings.**
1. Redis is redundant: Postgres `LISTEN/NOTIFY` + a durable event table + `FOR UPDATE SKIP LOCKED`
   covers durability, ordering, replay and job dispatch with one fewer service (ADR-007).
2. `NOTIFY` payloads cap at 8000 bytes and notifications can coalesce — therefore the notification
   must be a wake-up hint only, with data read from the table. Getting this wrong produces a War Room
   that silently stops updating.
3. Tool execution must be out-of-process with no DB credentials. An adapter that runs inside the
   worker couples a JVM crash to the orchestrator.
4. Docker is absent in the current sandbox, so the compose topology cannot be validated here.
5. Migrations must be tested forward *and* backward; four integrity assertions should run in CI
   (`DATABASE_SCHEMA.md` §8).

**Evidence.** `ENVIRONMENT_AUDIT.md` §1, §4; Postgres docs on `NOTIFY` semantics.

**Assumptions.** A-02 (Postgres provisionable).

**Proposal.** Three processes, one image; Postgres as queue + event store + graph store; runner
sandboxed with rlimits and no egress.

**Alternatives.** Celery/Redis; Kafka; Temporal; Kubernetes — all rejected on cost/benefit at this
scale, each with a stated reason in ADR-006/007/008.

**Advantages.** One datastore, transactional consistency between state and events, no broker to
misconfigure at 2 a.m. before a demo.

**Disadvantages.** Postgres becomes a single point of failure; very high event rates would eventually
require a different transport (not at this scale).

**Risks.** The team may underestimate the runner sandbox. A decompiler exploit is a real (if unlikely)
path from "analysing a malicious APK" to "the analysis host is owned" (`THREAT_MODEL.md` B4).

**Dependencies.** A container host with a JDK; Postgres; object storage (local FS is fine for dev).

**Complexity.** Medium.

**Open questions.** Managed Postgres or a dev container? Does the team have any host with Docker at all?

**Recommendation.** Adopt. Resist adding Redis "for realism" — it adds failure modes and proves nothing.

---

## E — Security Validation Specialist

**Findings.**
1. Severity and confidence must never be combined into one score. Averaging manufactures false
   certainty, which is the defining failure of the tools MOBIUS claims to improve on.
2. Validation by the same model that produced the finding is correlated-error theatre. Independence
   must be enforced structurally (different model, different role, blind to the producer's rationale).
3. "Not found" ≠ "not present". Blocked analysis must produce `INSUFFICIENT_EVIDENCE`, never "no
   findings".
4. Rejection reasons must be categorised, or the same mistake recurs invisibly.
5. Rejected findings must persist. A tool that deletes its mistakes cannot be audited.
6. The most realistic threat to *correctness* is prompt injection from APK content; the most realistic
   threat to *credibility* is an unmeasured false-positive rate.

**Evidence.** `AGENT_DESIGN.md` §5–6 (gates); `THREAT_MODEL.md` §4; `DATABASE_SCHEMA.md` §3.7
(`confirmed_requires_validator`, `confirmed_needs_evidence`).

**Assumptions.** A second model is available for the reviewer role.

**Proposal.** Ten confirmation gates as code predicates with positive *and* negative unit tests;
four-valued verdicts; schema-level constraints enforcing that a confirmed finding has a validator and
evidence; integrity tests in CI.

**Alternatives.** (a) Single confidence score → rejected. (b) LLM-only validation → rejected.
(c) Human-only validation → does not scale and is not the research question.

**Advantages.** The database itself refuses to record an unsupported confirmation. That is the
strongest possible enforcement short of a human gate.

**Disadvantages.** Gates will suppress true positives that fail a clause (e.g. a real bug whose sink is
hard to prove). Recall will look worse than a scanner's.

**Risks.** Gate tuning against the test set = overfitting. Mitigation: tune on negative controls only;
hold out the positive set.

**Dependencies.** Ground-truth labels; the second model; `MASWE` mapping.

**Complexity.** Medium — the difficulty is methodological discipline, not code.

**Open questions.** Is `manual_review_required` an acceptable terminal state for a finding in the
report, or must every finding reach a binary verdict? (Recommend: four-valued, and *count* the manual
ones — the count is a quality metric.)

**Recommendation.** Adopt, and make the precision measurement the headline result of the project.

---

## F — Frontend & Product Experience Architect

**Findings.**
1. "Premium dark command centre" is achievable with Tailwind design tokens and restraint; it is
   destroyed by generic component libraries and by decorative animation.
2. Fourteen screens cannot all be fed with real data. Five can. A screen with fabricated rows is worse
   than a missing screen.
3. The most differentiating UI element is not the graph — it is the **hypothesis panel showing
   `required_evidence` vs `satisfied_evidence`**. That is the product's thesis rendered as UI.
4. A full graph render does not scale visually; bounded expansion with `truncated` signalling is both a
   performance and an honesty requirement.
5. Event gaps must be rendered explicitly. Silently jumping makes the feed untrustworthy.
6. Idle states are a feature. An idle War Room that says "no active investigation" is more credible
   than animated filler.

**Evidence.** Master prompt §10; `API_SPECIFICATION.md` §4.4; `EVENT_ARCHITECTURE.md` §8.

**Assumptions.** One member owns frontend; ~6 weeks of that member's time.

**Proposal.** Five screens — War Room (battlefield + agent network + feed), Findings, Code Studio,
Attack Graph, Report. React + TS + Vite + Tailwind tokens + React Flow + Monaco. Agent status derived
purely from the event stream.

**Alternatives.** (a) Next.js → no SSR need. (b) Cytoscape → better for huge graphs we bound away from.
(c) A polished mock with static data → explicitly forbidden by the brief and by ethics of the demo.

**Advantages.** Fully data-driven; the hypothesis/evidence panel communicates the thesis instantly.

**Disadvantages.** Fewer screens than a "dashboard-shaped" project; risk of looking sparse to a panel
that equates screens with work.

**Risks.** React Flow performance on 500+ nodes; mitigated by server-side caps and progressive
expansion. Monaco bundle size; mitigated by lazy loading.

**Dependencies.** Frozen event catalogue and API schema (delivered here).

**Complexity.** Medium-high; the design discipline is the hard part, not the code.

**Open questions.** Are screenshots of a real running scan acceptable for the panel, given the analysis
host may not be available during the demo? (Recommend: record a screen capture of a real run — real
data, not fake — as a fallback.)

**Recommendation.** Five screens, no mocks, hypothesis panel as the centrepiece.

---

## G — Independent Technical Critic

**Mandate:** challenge everything above. This section is deliberately adversarial.

**Challenges to A.** "Vertical slice" is the safe answer and it may be the *wrong* answer for a
graduation panel that expects visible breadth. The counter is measurement, not modesty — but A does not
say how the team proves depth in a 20-minute defence. **Missing: a demo script that makes depth
legible.**

**Challenge to B.** Deferring PHANTOM removes the one capability that distinguishes MOBIUS from a
glorified MobSF wrapper. An all-static "autonomous investigator" is a static analyser with an LLM on
top, which is precisely the thing the brief says MOBIUS must not be. **B's recommendation is the most
dangerous in this document.** It may be correct on cost, but it hollows out the thesis.

**Challenge to C.** The frontier scorer is a hand-tuned heuristic dressed as planning. Calling it
"adaptive planning" in the report would be overclaiming. It is a best-first search with a heuristic
evaluation function. Say so. Relatedly: if the LLM only generates hypotheses and fills parameters,
a reviewer will ask what is actually *agentic* — and "the model chooses what to look at next" is a thin
answer.

**Challenge to D.** Postgres-as-queue is right, but the runner sandbox story is hand-waved. "Unprivileged
UID + rlimits" does not contain a parser exploit that achieves code execution — it contains filesystem
damage. Without a container, the runner is a process, and the isolation claim is weaker than the
document implies. Either require Docker for the runner or stop claiming isolation.

**Challenge to E.** Ten gates with four-valued verdicts and abstention will produce a system that says
"insufficient evidence" a lot. A panel may read systematic abstention as a system that does not work.
**E has no answer to the presentation problem.** Also: `insufficient_evidence` as a correct answer is
methodologically right and commercially useless — MOBIUS is a *university* project, which helps, but
this needs an explicit framing.

**Challenge to F.** "Hypothesis panel as centrepiece" is a strong idea, but it presumes hypotheses are
well-formed. If NEXUS generates vague hypotheses with untemplated `required_evidence`, the panel shows
noise. This is an unvalidated dependency of the whole UI thesis on C's output quality.

**Fatal-ish concerns, ranked:**
1. **Nobody has validated that an LLM can do the core triage task at useful precision on Android code.**
   Every design above assumes it. `MODEL_BENCHMARKS.md` is therefore not a nice-to-have; it is the
   project's viability test, and it should be run in **week 2**, not week 10. If BQ-2 comes back at
   40% precision on negative controls, the entire architecture is a machine for generating plausible
   false positives, and no amount of event architecture fixes that.
2. **The environment cannot run the product.** A project that cannot execute its own pipeline cannot
   demonstrate it. This is unaddressed by every specialist above.
3. **Scope is still too large.** Even the trimmed slice has 6 agents, 5 screens, a graph engine, an
   event pipeline, gates, reports, and a benchmark corpus. That is a full semester of full-time work
   for 6 experienced engineers; these are 6 students with one semester.

**Simplifications G recommends (beyond the others):**
- Cut to **3 agents in code** for v1: RECON (deterministic), SPECTRE (targeted code read), VERITAS
  (gated validation), with NEXUS as the FSM rather than an agent. Add PHANTOM/VECTOR later.
- Cut the attack graph to a **component reachability view** (a tree, not a graph) for v1. It answers
  the same question, is 10% of the code, and React Flow can still render it.
- Cut PDF generation; Markdown + browser print.
- Replace "7 agents, 14 screens" in the report with a measured claim: *"3 agents, 5 views, and here is
  the precision on 120 labelled items."* That is a stronger graduation project.

**On §8 reversals (see below):** G reverses B on PHANTOM and reverses A on graph scope. It does **not**
reverse E — E's gates are the only thing standing between this project and a scanner.

---

## 8. Reversals and disagreements (the honesty ledger)

| # | Earlier position | Later position | Resolution |
|---|---|---|---|
| 1 | B: scope 10 vulnerability classes | E: gates will suppress many true positives | **Kept both, with explicit measurement**: report recall honestly and count abstentions as a metric. Not resolved — a real tension. |
| 2 | A: build the attack graph with React Flow as designed | G: cut to a reachability tree for v1 | **G wins for v1**; full graph retained as v2 (ADR-014). |
| 3 | B: defer PHANTOM to protect the schedule | G: PHANTOM is the differentiator; deferring hollows the thesis | **PARKED — Director decision required.** This is the single biggest unresolved disagreement in the project. |
| 4 | C: 7 agents, each a contract | G: 3 agents + FSM | **G wins for v1**; the contract design is retained so the other agents are additive, not a rewrite. |
| 5 | (initial) Redis per master prompt | D: Postgres NOTIFY | **D wins** (ADR-007). |
| 6 | (initial) per-agent model routing per master prompt | C/D: two tiers | **Two tiers for v1** (ADR-010), with the role enum reserved. |

**Unresolved and escalated to the Director:** #1 (recall vs precision posture) and #3 (PHANTOM in or
out). Both materially change what the project is.

---

## Sources

- [S1] OWASP MASVS v2.1.0: https://github.com/OWASP/masvs/releases
- [S2] MASTG v2.0.0 + MASWE v1.0.0: https://mas.owasp.org/news/
- [S3] JADX 1.5.6 (2026-07-10): https://github.com/skylot/jadx/releases
- [S4] Apktool 3.0.3 (2026-07-20); Androguard 4.1.4 (2026-06-05); MobSF 4.6.4 (2026-10-31) — release pages
- [S5] GPL-3.0 licensing of MobSF / Objection — relevant to the integration boundary (ADR-013)
- [S6] ReAct production failure modes: https://blog.llmgo.top/en/articles/agent-loop-state-machine/
- [S7] ReAct vs Plan-and-Execute (cost, auditability, staleness): https://atlan.com/know/ai-agent/react-vs-plan-and-execute-agent-architecture/
- [S8] SEC-bench (2025) / SEC-bench Pro (2026) — empirical ceilings on LLM security tasks: https://arxiv.org/pdf/2506.11791 , https://arxiv.org/html/2605.26548v1
