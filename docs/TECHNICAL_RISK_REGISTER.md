# TECHNICAL RISK REGISTER

**Scoring** — Probability (1–5) × Impact (1–5) = Severity. Anything ≥ 15 requires a mitigation owner
and a decision date.
**Review cadence:** every weekly team meeting; this file is the agenda.

---

## Tier 1 — Project-threatening

### R-01 · No environment can execute the analysis pipeline
**P** 4 · **I** 5 · **= 20** · **Owner:** Director · **Blocks:** Phases 3–7

No JDK, Docker or `/dev/kvm` in the current sandbox (`ENVIRONMENT_AUDIT.md` §4). Without a host that can
run JADX and (for dynamic work) an emulator, MOBIUS can be *written* but not *demonstrated*.

**Mitigations.** (a) Confirm a team laptop or CI runner with a JDK at week 1 — this is the single most
urgent action in the project. (b) Design around ADR-002 so the split is configuration. (c) Fallback:
pure-Python analysis (androguard) covers RECON; SPECTRE becomes smali/string-based and the report says so.
**Trigger to escalate:** no confirmed JDK host by end of week 2.

### R-02 · PHANTOM (dynamic analysis) may be undeliverable
**P** 4 · **I** 4 · **= 16** · **Owner:** Member 3 · **Blocks:** VECTOR partially, ORACLE DYN-*

Emulator requires KVM or Redroid+privileged Docker; neither exists here. Even with a host: emulator
detection is trivial, Play Integrity cannot pass, pinning needs per-app Frida work, and each of these is
a schedule sink.

**Mitigations.** (a) Decide now: in or out. (b) If out, replace with a *recorded* real dynamic session
from a physical device, clearly labelled as recorded, used to demonstrate event flow — never presented
as live. (c) Never fake dynamic events; that is explicitly forbidden by the brief and fatal to credibility.
**Unresolved disagreement.** Specialist B recommends deferring; Specialist G argues PHANTOM is the
differentiator and deferring hollows the thesis (`SPECIALIST_REPORTS.md §8` #3). **Director must decide.**

### R-03 · The core premise is unvalidated: can an LLM triage Android code at useful precision?
**P** 3 · **I** 5 · **= 15** · **Owner:** Member 1 + Member 5

Every design assumes yes. Published evidence is not encouraging: ≤ 18% PoC success and ≤ 34% patching for
state-of-the-art agents on real security tasks [S1]. If negative-control precision lands near 40%, the
architecture is an efficient false-positive generator and no amount of event plumbing fixes it.

**Mitigation.** Run `MODEL_BENCHMARKS.md` BQ-2 on a 30-item pilot **in week 2–3**, before building the
War Room. If the result is poor, the response is architectural (tighter gates, narrower classes, more
abstention) — and it is cheap to make at week 3 and impossible at week 12.
**This is the highest-value early experiment in the project.**

### R-04 · Scope still exceeds capacity even after cuts
**P** 4 · **I** 4 · **= 16** · **Owner:** Director

Even the vertical slice (6 agents → 3, 5 screens, graph, gates, events, reports, benchmark corpus) is a
full-time semester for experienced engineers. The team is 6 students with one semester and limited
Android background.

**Mitigation.** Freeze scope at the end of week 2 and write it down with a "will not build" list. Re-read
that list at every meeting. Additions require removing something.

## Tier 2 — Serious

### R-05 · Team has insufficient Android background to judge output quality
**P** 4 · **I** 3 · **= 12** · **Owner:** Member 1

Nobody can validate an automated finding they could not have found manually. This is the root cause of
most "the tool says X" credulity.

**Mitigation.** The mandatory DIVA + InjuredAndroid manual lab (`ANDROID_SECURITY_METHODOLOGY.md` §9)
completed by all six members in weeks 1–3, with written findings compared against published solutions.
Non-negotiable precondition for writing analysis code.

### R-06 · Gate tuning overfits to the test corpus
**P** 4 · **I** 3 · **= 12** · **Owner:** Member 5

Tuning predicates against the same items used to report precision produces numbers that do not
generalise, and a panel may ask exactly this.

**Mitigation.** Tune only on negative controls; hold out 30% of positives; report held-out results.
Declare the split in the report *before* reporting numbers.

### R-07 · Decompiler instability changes findings between runs
**P** 3 · **I** 3 · **= 9** · **Owner:** Member 2

JADX output varies by version; findings derived from it are not reproducible without pinning.

**Mitigation.** Pin tool versions in `tools.lock.yaml`; record detected version on every
`tool_execution`; `fidelity` field on every code observation.

### R-08 · Prompt injection from APK content
**P** 4 · **I** 4 · **= 16** (impact reduced to 2 by ADR-012) · **Owner:** Member 5

Crafted strings in resources can instruct the model to suppress or fabricate findings.

**Mitigation.** ADR-012 (gates are code) is the structural control — an injection cannot manufacture a
confirmed finding. Plus content delimiting, grounding requirements, and the G7 injection benchmark suite.
Residual risk: wasted budget, noisy observations, corrupted report *prose* (not verdicts).

### R-09 · Sending decompiled proprietary code to a third-party LLM
**P** 3 · **I** 4 · **= 12** · **Owner:** Director

A real data-protection issue that most agent demos ignore.

**Mitigation.** Sharing off by default; per-scan opt-in; redaction pass; UI badge; documented in the
threat model (B6) and in the report's methodology section.

### R-10 · Real-time UI complexity consumes the schedule
**P** 3 · **I** 3 · **= 9** · **Owner:** Member 6

WebSocket + reconnect + replay + gap detection + bounded queues is a week of careful work that produces
no visible feature.

**Mitigation.** Use SSE if time-constrained (ADR-007 addendum). Ship the feed on REST polling with a
cursor first, upgrade to live streaming second — the event store makes this a pure transport swap.

## Tier 3 — Manageable

| ID | Risk | P×I | Mitigation |
|---|---|---|---|
| R-11 | JADX fails on obfuscated apps → analysis gaps | 4×2=8 | smali fallback + `decompiler-failed` fidelity + explicit abstention |
| R-12 | React Flow slow on large graphs | 3×2=6 | server-side node cap + bounded expansion + `truncated` flag |
| R-13 | Postgres unavailable in dev | 3×2=6 | SQLite dev fallback (schema §7) — demo only, CI uses Postgres |
| R-14 | LLM API cost overrun during development | 4×2=8 | token budgets enforced in code; cached responses in tests; stub model for CI |
| R-15 | MobSF GPL contamination | 2×3=6 | HTTP-only boundary (ADR-013) |
| R-16 | Team members block on each other via unowned interfaces | 4×2=8 | interfaces frozen in week 2 (`API_SPECIFICATION.md`, `EVENT_ARCHITECTURE.md §4`) |
| R-17 | Demo-day network unavailable | 3×3=9 | offline model path + pre-recorded real scan (recorded, labelled) |
| R-18 | Integration left to the last two weeks | 4×4=16 → mitigated by ADR-015 | vertical slice forces early integration |
| R-19 | A grader asks "why is this not just MobSF + GPT?" | 3×4=12 | answer with the benchmark: precision on negative controls, abstention correctness, gate evidence completeness |
| R-20 | Legal/ethics objection to the project | 2×5=10 | authorisation model + purpose-built test apps only + written ethics statement |
| R-21 | Static reachability misses findings (reflection, obfuscation, no data flow, guard treated as protection regardless of instruction order) | 5×3=15 | every miss is reported as `insufficient_evidence`, never as "no vulnerability"; `truncated` is a distinct result; the limitation is stated in `IMPLEMENTATION_STATUS.md` and ADR-022. **Partly unmitigated by design** — a precise data-flow analysis is out of v1 scope |

## The three risks that actually decide the outcome

1. **R-01** — without an execution host there is no product.
2. **R-03** — without evidence that the model can triage, the architecture is unfounded. Run it early.
3. **R-18/R-04** — scope and integration discipline. Everything else is recoverable; these are not.

## Risk-to-milestone map

| Milestone | Gates on |
|---|---|
| Week 2 — scope freeze | R-04, R-16 |
| Week 3 — benchmark pilot result | **R-03** |
| Week 3 — execution host confirmed | **R-01** |
| Week 4 — PHANTOM in/out decided | R-02 |
| Week 8 — end-to-end slice runs | R-18 |
| Week 10 — precision measured on held-out set | R-06, R-19 |

---

## Sources

- [S1] SEC-bench (2025): at most 18.0% PoC generation, 34.0% patching success for SOTA code agents — https://arxiv.org/pdf/2506.11791
- [S2] SEC-bench Pro (2026): grader design can inflate measured success by 43.6% — https://arxiv.org/html/2605.26548v1
- [S3] Android emulator without KVM — Redroid vs software-mode SDK emulator constraints: https://codersera.com/blog/android-emulator-docker-without-kvm/
