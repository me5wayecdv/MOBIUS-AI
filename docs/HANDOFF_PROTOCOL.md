# HANDOFF PROTOCOL — human-mediated multi-model collaboration

**Status:** Active
**Applies to:** Arena.ai (research) · Codex (implementation) · Claude Pro (review) · Argon (evaluation)

---

## 1. The constraint this protocol exists for

The master prompt (§2, §14.2) is explicit and correct: the external platforms are **separate
environments** with no shared memory, no shared runtime, and no verified agent-to-agent channel. This
document therefore encodes **human-mediated handoff** rather than pretending an integration exists.

Verified reality on 2026-11-12:

| Assumption | Verified? |
|---|---|
| Arena agents can see the Codex workspace | ❌ no |
| Codex can read this conversation | ❌ no |
| Claude Pro can access the repo automatically | ❌ no |
| Any automatic cross-platform messaging | ❌ no |
| GitHub repository is shared ground truth | ✅ yes — this is the only shared state |

**Therefore:** the repository is the transport. Everything that matters is written here, in files, in a
form a human can paste into another environment.

## 2. The handoff packet

Every cross-platform request is a self-contained packet. Nothing is left implicit, because the receiving
environment has no context.

```markdown
## HANDOFF-<nnn> · <one-line task>

**From / To:** <env> → <env>
**Date:** <ISO date>
**Why this environment:** <the capability that decides it>

### Context the receiver needs
- Repo: me5wayecdv/MOBIUS-AI @ <commit sha>
- Read first: <file paths, in order>
- Frozen interfaces this must not change: <paths>

### Task
<imperative, bounded, single objective>

### Inputs
<exact files/paths/fixtures. Attach or paste — do not say "see the repo" if the receiver cannot see it.>

### Expected output
<format: file to create / PR / review memo / patch>
<acceptance criteria, testable>

### Constraints
- No new dependencies without justification
- Do not modify <frozen paths>
- Must pass: <test command>

### Out of scope
<explicitly, to prevent drift>
```

## 3. Routing table — which environment gets which task

| Task | Environment | Why |
|---|---|---|
| Android security domain research, MASVS/MASWE mapping | **Arena** | Web research + long-context synthesis |
| Architecture design, ADRs, trade-off analysis | **Arena** | Structured long-form reasoning; produces documents |
| Documentation sets, methodology, threat model | **Arena** | Same |
| Benchmark design; adversarial critique | **Arena** | Independent critique benefits from a separate context |
| Code: backend, frontend, adapters, tests, migrations | **Codex** | Real repo access, execution, iteration |
| Debugging a failing test in the actual repo | **Codex** | Needs the runtime |
| Security review of a completed module | **Claude Pro** | Independent reviewer; different model family = different blind spots |
| Adversarial red-team of the gate logic | **Claude Pro** | Same |
| Model benchmarking on the corpus | **Argon** (after capability verification) | Additional model diversity. **Do not assign responsibilities before verifying the model, version, interface and limits.** |

## 4. The three-boundary rule

A decision crosses platforms **once**, in one direction, with a written record.

```
Arena (research/design)  ──docs/ + ADR──▶  Codex (implementation)  ──PR──▶  Claude Pro (review)
        ▲                                                                         │
        └────────────────── review findings, via a new HANDOFF packet ────────────┘
```

Never: two environments editing the same artefact. Never: a decision "agreed in chat" without a file.
Never: an environment assuming another's context.

## 5. Review handoff (Claude Pro) — the highest-value use

The most valuable thing a second model family can do here is **attack the architecture**, not approve it.
The packet therefore asks for findings, not sign-off:

```markdown
## HANDOFF-0nn · Adversarial review of MOBIUS confirmation gates

Read: docs/AGENT_DESIGN.md §6, docs/THREAT_MODEL.md §4,
      docs/ARCHITECTURE_DECISIONS.md ADR-012, docs/ORACLE_THREAT_INTEL.md §2

Task: find ways the confirmation-gate model produces a WRONG verdict.
Specifically:
 1. A gate that confirms a false positive (name the vulnerability class and the code shape).
 2. A gate that rejects a true positive, and how often you'd expect that in practice.
 3. A prompt-injection path that survives ADR-012 (gates as code).
 4. Any place where the design still lets a model, rather than evidence, decide a verdict.

Output: a findings list, each with severity, the reasoning, and a concrete test that would expose it.
Do not rewrite the architecture. Do not approve it. Only break it.
```

**Why this framing works:** a reviewer asked "is this good?" returns approval. A reviewer asked "break
this" returns the bugs. Same cost, different output.

## 6. Sync points (mandatory)

| When | What is synchronised | From → To |
|---|---|---|
| End of week 2 (scope freeze) | `REQUIREMENTS.md`, `ARCHITECTURE.md`, frozen interfaces | Arena → Codex |
| End of week 3 (benchmark pilot) | `MODEL_BENCHMARKS.md` results | Codex/Arena → Director |
| Each completed module | PR + `IMPLEMENTATION_STATUS.md` row | Codex → Claude Pro |
| Each review | Findings memo → new ADR or `REVIEW_LOG.md` entry | Claude Pro → Arena/Codex |
| Before submission | `00_EXECUTIVE_DECISION_REPORT.md`, `MODEL_BENCHMARKS.md` filled | All → Director |

## 7. Anti-patterns this protocol forbids

| Anti-pattern | Why it is fatal here |
|---|---|
| "As we discussed earlier" in a packet | The receiver was not there |
| Pasting a chat summary instead of a file | Summaries lose the constraints |
| Two environments editing one file | Unresolvable merge conflicts in *intent*, not just text |
| Accepting a review that says "looks good" | No information; a review that finds nothing is a failed review |
| Assuming a capability because a vendor markets it | The prompt's explicit rule; verify or omit |
| Letting a model's approval stand in for the Director's | Master prompt §21 — the Director has final authority |

## 8. Verifying a new environment before trusting it (e.g. Argon)

1. Identify the exact model name and version, and the interface (web/API/CLI).
2. Test: does it accept a file? run code? browse? hold context over 20k tokens?
3. Run **one** item from each benchmark group (G1, G2, G6, G7) and record the result in
   `MODEL_BENCHMARKS.md` under a new column.
4. Only then assign a role, and only the role the data supports.

Do not assign a specialist responsibility to an unmeasured environment. A wrong model in the VERITAS role
degrades the one component whose independence the project's credibility rests on.
