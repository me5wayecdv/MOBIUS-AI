# PROJECT CONTEXT

**Codename:** MOBIUS — Autonomous Evidence-Driven Android Security Investigation Platform
**Type:** University graduation project, 6-person team
**Document status:** Phase 1 draft, awaiting Project Director approval
**Related:** `REQUIREMENTS.md`, `ARCHITECTURE.md`, `00_EXECUTIVE_DECISION_REPORT.md`

---

## 1. The claim MOBIUS must earn

MOBIUS is not a scanner. A scanner produces a list; MOBIUS must produce a **defensible argument**.

The distinguishing test is simple and should be applied to every feature:

> Given a suspicious pattern in an APK, can MOBIUS state *what it observed*, *which evidence
> supports it*, *what it did to test it*, *what it could not determine*, and *why it believes the
> conclusion* — and can a competent human auditor audit that chain?

If a feature does not improve that chain, it is not core.

## 2. Scope

### 2.1 In scope

| Area | Description |
|---|---|
| Static reconnaissance | Manifest, components, permissions, intents, deep links, network security config, certificates, native libs, SDK fingerprinting |
| Static code investigation | Decompiled Java/Kotlin and smali review targeted by hypotheses, not exhaustive-dump-and-grep |
| Adaptive investigation | NEXUS maintains a prioritised worklist and re-plans as evidence arrives |
| Independent validation | VERITAS tries to *break* each finding, with explicit confirmation gates |
| Evidence & auditability | Every claim traceable to a stored artifact; full investigation timeline |
| Attack surface graph | Evidence-backed, with explicit hypothetical vs confirmed edge status |
| Live investigation console | War Room driven only by real backend events |
| Technical reporting | Severity, confidence, reproduction steps, MASVS/MASWE mapping, remediation |

### 2.2 Explicitly out of scope (v1)

| Excluded | Reason |
|---|---|
| Automated exploitation / weaponisation | Not a graduation-project deliverable; legal and ethical exposure |
| Malware authoring, C2, droppers, payload delivery | Out of scope by policy — see §4 |
| Full-program decompilation accuracy claim | JADX output is a *reconstruction*, not source (see `ANDROID_SECURITY_METHODOLOGY.md §5`) |
| iOS analysis | Different domain entirely |
| Multi-tenant SaaS, billing, RBAC beyond owner/reviewer | Adds no research value |
| Neural/learned false-positive models | No labelled training corpus; needs data that does not exist yet |
| Exploit-chain construction across apps | Requires device-level compromise model; out of scope |

## 3. What "autonomous" will and will not mean

This word is dangerous in a graduation defence. Precisely:

- **Will:** MOBIUS selects the next action from a closed, validated action set based on accumulated
  evidence, without a human choosing each step; it re-plans when evidence contradicts expectation;
  it stops when its budget is exhausted and says so.
- **Will not:** MOBIUS will not execute unvalidated shell strings, will not perform irreversible or
  destructive actions without approval, and will not claim a finding is confirmed without passing a
  confirmation gate.
- **Bounded autonomy.** Every investigation has a hard step budget, wall-clock budget, and tool-call
  budget. When a budget is hit the investigation terminates in state `BUDGET_EXHAUSTED` with a
  partial report — it does not silently continue.

## 4. Policy on offensive tooling and the attached C2 research document

The Project Director supplied `android-c2.pdf`, a writeup of an Android C2 framework
("Dr01dc4ll") describing in-memory DEX module loading, a dropper/stager design, camera and
microphone capture, SMS/call-log/contact dumping, credential-harvesting overlays, SOCKS proxying,
and network tunnelling.

**This repository will treat that document as threat intelligence input only.** Concretely:

| Permitted | Prohibited |
|---|---|
| Deriving **detection** indicators (API co-occurrence, manifest signatures, DEX-loading patterns, stager/host behaviour) so MOBIUS can *flag* such apps | Implementing, debugging, improving, or extending the C2, its dropper, its modules, or its protocol |
| Writing the defensive analysis in `docs/ORACLE_THREAT_INTEL.md` | Producing operational guidance for building or evading detection |
| Using such apps as **analysis targets** (malicious input, analysed statically) | Producing any artefact that could be repurposed as working offensive tooling |
| Mapping observed techniques to MASVS-RESILIENCE / MASVS-CODE and MASWE weaknesses | Turning ORACLE into a "C2 development reference" |

This is consistent with the master prompt's own constraints (§16: no operational spyware, no
credential theft, no covert exfiltration, no covert tunnelling; ORACLE stays defensive and disabled
by default). If the intent was instead to develop or extend that framework, that is not something
this project — or this agent — will do, and the architecture is deliberately shaped so it cannot
be repurposed without an obvious, reviewable change.

**The genuinely useful insight from that document** is that a competent Android attacker in 2026
uses: (a) a thin stager + remote module delivery, (b) in-memory DEX loading with no on-disk
artefact, (c) emulator/root detection *before* the interesting behaviour, and (d) a custom binary
protocol rather than HTTP JSON. Each of these defeats a naive static scanner:
a scanner that only reads `classes.dex` sees the dropper and nothing else. **MOBIUS's hypothesis
loop is the architectural answer** — "this DEX loads code from a network response" is an
observation that must generate a *follow-up hypothesis*, not a one-line finding.
See `ORACLE_THREAT_INTEL.md §4`.

## 5. Authorisation model (non-negotiable)

MOBIUS performs security testing. Testing without authorisation is unlawful in most
jurisdictions and would destroy the project's credibility.

- No investigation may enter `RECON` without an `Authorization` record bound to the APK's SHA-256.
- The authorisation record captures: authoriser identity, target package name, testing scope,
  permitted test intensity (0–3), expiry, and a signed statement of ownership or permission.
- The APK hash is pinned: if the artefact changes, authorisation does not carry over.
- Test intensity gates dynamic actions:
  - **0 — Passive only.** Static analysis, no target execution.
  - **1 — Observational.** Launch and observe; no input injection.
  - **2 — Controlled interaction.** Approved intents, approved input, isolated network.
  - **3 — Destructive-capable.** Disabled in code for v1. Requires explicit unlock.
- An `EMERGENCY_STOP` halts all running investigations and revokes active tool leases.

This is not decoration. It is the control that makes the project defensible to an academic ethics
board and to a court.

## 6. Evaluation targets (ground truth is what makes false-positive claims real)

You cannot claim "MOBIUS reduces false positives" without a corpus where you know the right answer.
v1 evaluates against purpose-built vulnerable apps with published vulnerability sets:

| Target | What it exercises |
|---|---|
| DIVA (Damn Insecure and Vulnerable App) | Storage, logging, hardcoded secrets, exported components |
| InsecureBankv2 | Auth logic, crypto misuse, root detection |
| AndroGoat | Broad MASVS coverage, modern Kotlin |
| InjuredAndroid | Intent/component abuse, deep links |
| OWASP MSTG crackmes (Android) | Resilience / anti-tampering |
| 2–3 benign production apps (e.g. a FOSS client) | **False-positive measurement** — the negative control |
| Ground-truth-labelled malware samples (authorised, non-executed) | ORACLE detection hypotheses |

Metrics are defined in `MODEL_BENCHMARKS.md §5`. The essential one: **precision on the benign set**,
because a tool that flags everything has perfect recall and no value.

## 7. Success definition (measurable, not aspirational)

MOBIUS v1 succeeds if, on the evaluation corpus, it can demonstrate all of the following with
stored evidence:

1. Reconstructs the attack surface of an APK, and its component inventory agrees with manual review
   on ≥ 90% of entries (precision and recall reported separately).
2. For each of ≥ 6 seeded vulnerability classes, reaches a correct verdict (confirmed / rejected /
   needs-manual-review) on a majority of instances, **and explicitly abstains** rather than guessing
   on the rest.
3. Produces ≥ 1 non-trivial multi-step investigation where a later action was selected *because of*
   an earlier observation, with the decision record showing the link.
4. Precision on the benign control set ≥ 0.85 for `confirmed` findings.
5. Every confirmed finding is traceable to stored evidence via `evidence_refs` — verified by an
   automated audit that fails the build if a dangling reference exists.
6. The War Room shows only events that exist in the event store (assertion: no frontend-generated
   activity — enforced by the frontend consuming no local constants for feed content).

Anything not measurable above is aspiration, not scope.
