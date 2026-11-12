# ANDROID SECURITY METHODOLOGY & TOOLING

**Status:** Research complete, proposed
**Standards baseline:** OWASP MASVS v2.1.0 (18 Jan 2024) · MASTG v2.0.0 (Jun 2026) · MASWE v1.0.0 (78 weaknesses)
**Owner:** Member 2 (Recon/Static), Member 3 (Dynamic), Member 4 (Network)

> **Why the version matters.** MASVS v2.0 retired the old L1/L2/R *levels*. Any document or tutorial
> citing "MASVS-L2" is pre-2023 and should not be used for requirement mapping. The current chain is
> `MASVS control → MASWE weakness → MASTG test`, and MOBIUS findings should carry all three IDs.

---

## 1. The traceability chain MOBIUS must emit

```
MASVS-STORAGE-1  (control: "system credential storage facilities are used appropriately")
   └── MASWE-0001 (weakness: insertion of sensitive data into unencrypted/non-private storage)
        └── MASTG-TEST-0204 (test: sensitive data in app-private storage)
             └── MOBIUS finding  F-2026-0007
```

A finding that names only "MASVS-STORAGE" is too coarse to be actionable. One that names
`MASWE-0001` tells the developer exactly what class of defect to fix. MOBIUS stores
`masvs[]`, `maswe[]`, `mastg[]` as separate arrays on the finding.

## 2. Attack surface model (what RECON enumerates)

Android's IPC surface is the primary externally-reachable attack surface, and it is decided almost
entirely by `AndroidManifest.xml`. This is why RECON is deterministic code and not an LLM task.

| Element | Reachability determinant | What MOBIUS must capture |
|---|---|---|
| Activity | `android:exported` (explicit, or implied by intent-filter pre-API-31) | `exported` + `export_reason`, permission, intent filters, task affinity |
| Service | same, plus `foregroundServiceType` | permissions, `bind`/`start` exposure, `onBind` returning null vs a Binder |
| Receiver | same, plus whether registered dynamically in code | permission, `onReceive` sink reachability |
| ContentProvider | `exported`, `grantUriPermissions`, `<path-permission>`, `android:readPermission`/`writePermission` separately | URI structure, per-path perms, `openFile` implement |
| Intent filters | actions, categories, `data` scheme/host/path/mimeType | deep links, custom schemes, App Links (`autoVerify`) |
| Pending intents / implicit intents | code-level | sensitive extras, missing `setPackage` |
| WebView bridges | code-level | `@JavascriptInterface`, `loadUrl` of attacker-influenceable content |
| Deep links | manifest + code | whether parameters are validated before reaching a sink |
| Network | `network_security_config.xml`, `usesCleartextTraffic`, pinning | cleartext domains, trust anchors, debug-overrides |
| Exported by default | **pre-API-31 components with intent-filters lacked an explicit `exported`** | `export_reason="implied-by-intent-filter"` — a class of real CVEs |

### 2.1 The API 31 subtlety MOBIUS must get right

Before API 31, a component with an intent filter was exported *by default*. From API 31, an explicit
`android:exported` is **required** and the build fails without it — so an app that ships without it
was targeted at API ≤ 30 and its exported status is *implied*. Naive parsers that read
`android:exported` only and treat absence as `false` produce false negatives on old apps and false
positives elsewhere. This single rule affects the precision of the most important observation RECON
makes, so it gets a dedicated test fixture (an APK declaring `targetSdk=30` with an exported-by-implied
component).

## 3. Vulnerability classes and how each is actually tested

Ranked by *frequency of appearance in real Android pentests*, not by theoretical interest.

| # | Class | MASWE | Static signal | Validation that changes the verdict |
|---|---|---|---|---|
| 1 | Exported component → privileged sink | 0029–0040 | exported + no permission + `getIntent()`/`getExtras()` reaching a sink | Targeted code read proving the sink is reachable, and absence of `checkCallingPermission`/`Binder.getCallingUid` checks |
| 2 | Hardcoded secret / API key | 0001s (STORAGE) | high-entropy string, `AIza`, `sk_live`, `-----BEGIN` | Prove it is *used* in a security context **and** (if possible) that it is live — otherwise downgrade to "informational at best" |
| 3 | Insecure data storage | 0001 | `getExternalFilesDir`, `MODE_WORLD_*`, unencrypted `SharedPreferences` for tokens | Prove the *data* is sensitive; `getExternalFilesDir` for cache images is not a finding |
| 4 | Weak/broken crypto | CRYPTO | `DES`, `RC4`, `AES/ECB`, `MD5`/`SHA1` in auth, static IV, `SecureRandom` absent | Establish key provenance and whether it protects something that matters |
| 5 | Cleartext / TLS misconfiguration | NETWORK | NSC permits cleartext, custom `TrustManager` that accepts all, `onReceivedSslError` → `proceed()` | Identify an actual non-localhost endpoint and what flows over it |
| 6 | WebView unsafe configuration | 0029+ | `addJavascriptInterface` + `setJavaScriptEnabled(true)` | Show attacker-influenceable content source (or downgrade) |
| 7 | Dynamic code loading | CODE | `DexClassLoader`, `InMemoryDexClassLoader`, `PathClassLoader`, `.loadDex` | Determine byte source: network/external = high; bundled+verified = low |
| 8 | Intent redirection / implicit intent leakage | PLATFORM | `startActivity(getIntent())`, nested intent extras | Prove an unprivileged app can steer the inner intent |
| 9 | Unprotected provider + path traversal | PLATFORM | exported provider, `openFile` without canonicalisation | Show a caller-controlled `Uri` reaching the file open |
| 10 | Improper platform usage (`allowBackup`, `debuggable`, task hijacking) | PLATFORM/CODE | manifest flags | `debuggable` in a release build is a genuine high; `allowBackup` is medium |

## 4. Tooling: verified state, and what each is good for

Versions below are as observed in research on 2026-11-12; `tools.lock.yaml` will pin exact artefacts
by SHA-256 at build time.

| Tool | Version seen | Licence | Role in MOBIUS | Caveat that affects design |
|---|---|---|---|---|
| **Androguard** | 4.1.4 | Apache-2.0 | AXML/DEX parsing, manifest, permissions, components — **pure Python** | Slower than aapt2 on large DEX; API has churn between majors |
| **aapt2** | Android SDK build-tools | Apache-2.0 | Authoritative manifest/resource decode | Needs the SDK; licensing of redistribution to check |
| **JADX** | 1.5.6 | Apache-2.0 | Java decompilation, deobfuscation | **Output is a reconstruction, not source.** Fails on some obfuscated methods; must degrade to smali |
| **Apktool** | 3.0.3 | Apache-2.0 | smali, resource decoding, manifest | Slower; smali is exact but low-level |
| **MobSF** | 4.6.4 | **GPL-3.0** | Reference baseline; REST API automation | **GPL-3.0** — integrating by HTTP call keeps MOBIUS separate; linking code would impose GPL. Report generation is its own; MOBIUS should use it as a *cross-check*, not the engine |
| **Frida** | 17.x | wxWindows/LGPL | Runtime instrumentation | Detection by target apps is common; version must match the gadget |
| **Objection** | 1.x | GPL-3.0 | Frida wrapper | Same GPL consideration |
| **mitmproxy** | 11.x | MIT | Traffic capture | Needs a CA installed in a system-trusted store; modern apps pin |
| **Ghidra** | 11.x | Apache-2.0 | Native `.so` analysis | Heavy (JVM + RAM); justified only when a native crypto routine or packer is the blocker |

### 4.1 The MobSF licensing trap

MobSF is GPL-3.0. Calling it over HTTP as a separate service is an arm's-length interaction and does
not make MOBIUS a derivative work. Importing its Python modules would. Decision: **HTTP only, and only
for cross-checking** — see `ARCHITECTURE_DECISIONS.md` ADR-013. Also note that MobSF's engine is
JADX+Apktool+regex heuristics, i.e. largely the same signals MOBIUS derives; its value to the project
is as a *comparison baseline for the false-positive evaluation*, not as a dependency.

## 5. The decompilation fidelity problem (must be visible in the UI)

JADX output can differ from the original source in ways that change a security conclusion:

- Reordered/merged statements; inlined lambda bodies.
- Synthetic accessors; `switch`-on-string rewritten as two lookups.
- Generic type erasure.
- Control flow reconstructed from `goto`-heavy bytecode — sometimes unreadable, occasionally wrong.
- Obfuscation (ProGuard/R8) renames everything; string decryption stubs hide constants.
- Native code is not recovered at all.

Therefore every `CodeObservation` carries `fidelity ∈ {decompiled, smali, decompiler-failed, runtime}`
and the code viewer displays it. **A finding whose evidence is `fidelity=decompiled` must state that
the decompiler is not authoritative**, and a `CONFIRMED` verdict on such evidence should require a
second, independent evidence type (e.g. a runtime hit or a smali quote). This is the honest position
and it is also a good differentiator for a defences panel.

## 6. Resilience and anti-analysis (what to expect, what to do)

Modern apps (and all malware) detect analysis. MOBIUS must anticipate, not be surprised:

| Technique | How it appears | MOBIUS response |
|---|---|---|
| Root detection | `su` path checks, `test-keys` in `Build.TAGS`, Magisk paths, SafetyNet/Play Integrity | Record as an observation with MASVS-RESILIENCE mapping; do **not** attempt to bypass in v1 |
| Emulator detection | `Build.FINGERPRINT` contains `generic`, `ro.kernel.qemu`, sensor count heuristic | Record; relevant because it explains why dynamic tests see nothing |
| Debugger detection | `Debug.isDebuggerConnected()`, `ptrace` via native | Record |
| Frida detection | scanning `/proc/self/maps` for `frida`, port 27042 probe, thread name check | Record; a *detected* Frida attempt is itself evidence the app is defensive |
| Packing / dynamic loading | stub `Application` class, tiny `classes.dex`, `DexClassLoader` | **Escalate**: "static analysis is insufficient — dynamic required" is a legitimate finding |
| Obfuscation | identifier entropy, `StringFog`-style decryptors | Report reduced fidelity; do not claim absence of a vulnerability |

**Important honesty rule:** "not found" ≠ "not present". When resilience prevents analysis, MOBIUS
must emit `INSUFFICIENT_EVIDENCE — analysis blocked by <technique>`, never "no vulnerabilities found".
This distinction is the single clearest separator between MOBIUS and a scanner.

## 7. Dynamic analysis prerequisites (PHANTOM feasibility)

| Requirement | Reality check |
|---|---|
| Hardware acceleration | `/dev/kvm` on the host, or Redroid (no KVM, needs binder + `--privileged`) |
| Emulator detection | AOSP images are trivially detected; expect it |
| Root / Frida server | Requires a writable system or `frida-server` as root in the image |
| Certificate pinning | Bypass needs Frida scripts per-app; a moving target |
| Play Integrity | Cannot pass on an emulator; apps gated by it will refuse to run |
| Isolation | Emulator on a host-only network; no bridge to the corporate LAN |
| Snapshotting | Cold-boot snapshot per investigation for reproducibility |

**Assessment:** PHANTOM is the highest-cost, lowest-certainty module in MOBIUS. If no KVM host exists,
it cannot be delivered honestly. Recommend deferring it and spending the time on RECON/SPECTRE
quality — a recommendation the master prompt should accept given its own instruction to optimise for a
credible project (`TECHNICAL_RISK_REGISTER.md` R-01, R-02).

## 8. Methodology the team should actually follow (mapped to phases)

The MASTG's own flow, which MOBIUS mirrors:

1. **Reconnaissance** — collect metadata, manifest, certificates, libraries. *(RECON)*
2. **Static analysis** — manifest + code review against MASVS categories. *(SPECTRE)*
3. **Dynamic analysis** — runtime behaviour, instrumentation. *(PHANTOM)*
4. **Network analysis** — traffic, TLS, auth. *(VECTOR)*
5. **Resilience assessment** — anti-tampering posture. *(observations only in v1)*
6. **Reporting** — per MASVS category, with evidence and remediation. *(ARCHIVIST)*

## 9. Training requirement for the team

Five of six members are primarily Blue Team with limited Android experience (master prompt §17). The
minimum shared curriculum before anyone writes analysis code:

| Topic | Why | Depth |
|---|---|---|
| APK/ZIP structure, DEX format basics | Everyone will debug a parse failure | 1 session |
| Android component model + `exported` semantics | The core of the attack surface | 2 sessions |
| Permission model, protection levels, UID sandbox | Determines whether a component is actually reachable | 1 session |
| Intents, filters, deep links | Half the findings live here | 1 session |
| MASVS v2.1 category map + MASWE IDs | Every finding must cite one | 1 session |
| JADX/Apktool hands-on on DIVA | Tool fluency | 2 labs |
| Reading smali when JADX fails | Unblocks the hard cases | 1 lab |
| Frida basics (if PHANTOM in scope) | Dynamic entry point | 2 labs |

**Mandatory lab:** every member independently completes DIVA and InjuredAndroid by hand, writes up
findings, and compares with the published solutions. You cannot evaluate an automated investigator on
apps you cannot investigate manually. This is the highest-return activity in the project plan.

---

## Sources

- OWASP MASVS v2.1.0 release (18 Jan 2024), 8 categories / 24 controls: https://github.com/OWASP/masvs/releases
- OWASP MAS / MASTG v2.0.0 + MASWE v1.0.0 (78 weaknesses, `MASVS control → MASWE → MASTG test` chain): https://mas.owasp.org/news/
- OWASP Mobile Top 10 2024 (M1 Improper Credential Usage, M2 Supply Chain): https://owasp.org/www-project-mobile-top-10/
- JADX 1.5.6 (10 Jul 2026), Java 11+, Apache-2.0: https://github.com/skylot/jadx/releases
- Apktool 3.0.3 (20 Jul 2026), Androguard 4.1.4 (5 Jun 2026), MobSF 4.6.4 (31 Oct 2026): tool release pages
- Android `android:exported` behaviour change at API 31: Android developer documentation, "Behavior changes: Android 12"
