# ENVIRONMENT AUDIT — Phase 0

**Status:** Verified by direct measurement
**Audit date:** 2026-11-12
**Audited by:** Arena.ai Agent Mode (single agent, see §2)
**Branch:** `arena/bd856c58-mobius-ai`, based on `712f7b8`

> **How to read this document.** Every line in §1 and §3 was produced by running a command in the
> actual sandbox, not inferred. Where something is an assumption it is marked **[ASSUMPTION]**.
> Anything MOBIUS needs but does not have is marked **[MISSING]**.

---

## 1. Measured execution environment

| Property | Measured value | Command used |
|---|---|---|
| OS | Debian GNU/Linux 12 (bookworm) | `cat /etc/os-release` |
| CPU | 2 vCPU | `nproc` |
| RAM | 3.8 GiB total | `free -h` |
| Disk | 21 GB total, ~20 GB free | `df -h` |
| Python | 3.11.2 | `python3 --version` |
| pip | 23.0.1 (PEP 668 externally-managed) | `pip3 --version` |
| Node.js | v22.22.3 | `node --version` |
| npm | 10.9.8 | `npm --version` |
| git | 2.39.5 | `git --version` |
| gh | 2.23.0 | `gh --version` |
| Docker / docker-compose | **[MISSING]** | `command -v docker` |
| Java / javac (JDK) | **[MISSING]** | `command -v java` |
| adb | **[MISSING]** | `command -v adb` |
| aapt2 | **[MISSING]** | `command -v aapt2` |
| jadx | **[MISSING]** | `command -v jadx` |
| apktool | **[MISSING]** | `command -v apktool` |
| `/dev/kvm` | **absent** — no hardware virtualisation | `ls /dev/kvm` |

### 1.1 Network egress (measured)

| Host | HTTP status |
|---|---|
| `pypi.org` | 200 |
| `registry.npmjs.org` | 200 |
| `api.github.com` | 200 |

Egress is allowlisted to the package registries and GitHub. Arbitrary outbound internet from
*within* this sandbox is therefore not assumed. This matters for MOBIUS because VECTOR
(API/network testing) and any dynamic analysis phase must reach target endpoints — they cannot
do so from this sandbox.

---

## 2. Agent execution capability — the honest answer

The master prompt asks (§2, §25) whether true parallel multi-agent execution is available.
**It is not.** Being precise about what *is* available:

| Capability | Available? | Notes |
|---|---|---|
| Multiple models running the same task simultaneously for comparison | **No** | There is no mechanism to fan a task out to N models and collect N independent answers in this session. |
| Spawning sub-agents with separate context windows | **No** | All reasoning in this session occurs in one context. |
| Parallel *tool calls* within one response | **Yes** | Multiple `bash` / search / file calls execute concurrently. This is real concurrency of I/O, **not** independent reasoning. |
| Persistent filesystem workspace | **Yes** | `/home/user/MOBIUS-AI`, snapshotted. |
| Git push / PR to GitHub | **Yes** | `gh` authenticated; push restricted to the current branch. |
| Web research | **Yes** | Search + page fetch. |
| Code execution | **Yes** | Python 3.11, Node 22. No Java, no Docker. |
| Cross-agent communication | **N/A** | No agents to communicate. |
| Long-running background servers | **Yes** | Previewable on `0.0.0.0`. |

### 2.1 Consequence for Section 2 of the master prompt

Agents A–G (Principal Architect, Android Researcher, AI Agent Architect, Backend Architect,
Security Validation, Frontend Architect, Independent Critic) **cannot be run as independent
parallel agents.** The instruction "each specialist must work independently before reviewing the
others' conclusions" cannot be satisfied by actual context isolation here.

Rather than fake it, `docs/SPECIALIST_REPORTS.md` contains seven specialist analyses produced
**sequentially in one context, each written before the next was started, with disagreements
preserved rather than smoothed.** That is an honest substitute, and it is explicitly weaker than
true independence on one axis: a later report cannot be blind to an earlier one. The mitigation is
that `docs/SPECIALIST_REPORTS.md §8` records where a later report *reversed* an earlier one, which
is the observable symptom of non-independence.

**Recommendation:** genuine independence requires running the same prompt in separate sessions
(the human-mediated handoff described in `docs/HANDOFF_PROTOCOL.md`, using Claude Pro and Codex as
separate environments). This is a real limitation of the current setup, not a design choice.

---

## 3. Repository state

```
712f7b8  Add project description to README.md
README.md   (56 bytes: "# MOBIUS-AI \nAgentic AI for Android Penetration Testing")
origin      https://github.com/me5wayecdv/MOBIUS-AI.git
```

- **No source code exists.** No backend, no frontend, no schemas, no tests, no migrations.
- **No Dockerfile, no CI, no `.gitignore`** prior to this commit (a `.gitignore` is added in Phase 0).
- There is **nothing to preserve, refactor, or break**. Phase 2 starts from zero.

This is good news: there is no legacy to work around, and no risk of the "do not rewrite an
existing repository" constraint being violated.

---

## 4. Capability matrix against MOBIUS requirements

This is the critical table. It answers: *can MOBIUS actually be built and demonstrated here?*

| Requirement | Needs | Available here | Verdict |
|---|---|---|---|
| FastAPI backend | Python 3.11 | ✅ | **Buildable** |
| Postgres | server or Docker | ❌ locally | **Needs external** — use managed Postgres or a dev host |
| React/Vite frontend | Node 22 | ✅ | **Buildable** |
| WebSocket live events | Python + Node | ✅ | **Buildable** |
| RECON: AAPT2 / apktool | JDK 11+ | ❌ | **Blocked here** |
| SPECTRE: JADX decompile | JDK 11+ | ❌ | **Blocked here** |
| SPECTRE: Androguard | Python only | ✅ (pure Python) | **Partially buildable** — see §5 |
| MobSF integration | Docker | ❌ | **Blocked here** |
| PHANTOM: emulator | KVM or Redroid + privileged | ❌ | **Blocked here** |
| PHANTOM: Frida | adb + device/emulator | ❌ | **Blocked here** |
| VECTOR: mitmproxy | Python + network egress | ⚠️ lib yes, egress no | **Blocked here** |
| GHIDRA native analysis | JDK + RAM | ❌ | **Blocked here** |

### 4.1 The uncomfortable conclusion

**This sandbox can build the platform. It cannot run the platform's analysis engine.**
The APK analysis pipeline is the core of MOBIUS and it requires a JDK plus, for dynamic work, a
hardware-accelerated emulator. Neither exists here.

Practical resolutions, in order of preference:

1. **Split environments.** Build and unit-test in this sandbox; run analysis workers on a machine
   with a JDK + KVM (a team laptop, or a CI runner with nested virtualisation). The tool-adapter
   interface is designed to make this split a configuration concern, not a code change
   (see `ARCHITECTURE_DECISIONS.md` ADR-002).
2. **Redroid for headless dynamic analysis.** If no KVM is available anywhere, Redroid (containerised
   Android using the host kernel) avoids `/dev/kvm` entirely but requires binder kernel modules and
   `--privileged`, i.e. a Docker host — which this sandbox is not.
3. **Defer PHANTOM.** If no emulator is available in any environment, PHANTOM must be cut from the
   graduation scope rather than faked. See `docs/TECHNICAL_RISK_REGISTER.md` R-01.

> ⚠️ **Do not plan a demo that depends on the emulator until a host with KVM is confirmed.**
> A graduation project that shows a War Room driven by fake dynamic events is exactly what the
> master prompt forbids (§10: "Fake agent messages... Fake vulnerability discoveries").

---

## 5. What is genuinely achievable with zero external dependencies

Worth stating precisely, because it defines the minimum viable Phase 3:

- An APK is a ZIP. `zipfile` + a small amount of code can extract `AndroidManifest.xml` (binary
  AXML, parseable in pure Python), `classes*.dex` headers, `lib/`, `assets/`, `res/raw/`, and
  `META-INF/` signing blocks.
- `androguard` is pure Python and provides AXML parsing, DEX parsing, permission and component
  extraction. It is the one full analysis capability available with no JDK.
- `apkutils`, `pyaxmlparser` are alternatives.
- Certificate parsing: `cryptography` handles PKCS#7 / X.509.
- Secret scanning over `strings` output: pure Python.

So **RECON is ~80% implementable here**; SPECTRE's *source-level* review is not (needs JADX), though
smali/`strings`/DEX-level heuristics are.

---

## 6. Assumptions recorded

| ID | Assumption | Risk if wrong |
|---|---|---|
| A-01 | Implementation will happen primarily in an environment with a JDK and Docker, not this sandbox | If false, Phases 3–7 must be redesigned around pure-Python tooling |
| A-02 | Postgres can be provisioned (managed service or dev host) | If false, fall back to SQLite for dev; schema must avoid Postgres-only features |
| A-03 | The team has access to at least one Android emulator or physical test device | If false, PHANTOM is removed from scope |
| A-04 | Target APKs will be purpose-built vulnerable apps and authorised lab targets | If false, the project loses its legal and ethical footing |
| A-05 | LLM API access with structured-output (JSON schema) support is available | If false, all agent I/O must degrade to a parser + repair loop, raising cost |

---

## 7. Decision requested from the Project Director

1. Which environment will own the analysis workers (JDK + KVM)?
2. Is a Postgres instance available, or should v1 target SQLite-compatible SQL?
3. Confirm A-03 (emulator availability) — this decides whether PHANTOM is in scope.
