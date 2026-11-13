# ORACLE — DEFENSIVE ANDROID THREAT INTELLIGENCE

**Status:** Documentation only. ORACLE is **disabled by default** and **not implemented** in v1.
**Input:** `android-c2.pdf` (7 pages, supplied by the Project Director), a writeup of an Android C2
framework presenting itself as "Dr01dc4ll".
**Purpose:** turn that writeup into *detection* capability for MOBIUS.

---

## 0. Scope statement — read before anything else

This document is a **detection** analysis. It exists so MOBIUS can recognise and report the techniques
described. It deliberately does **not** contain, and the project will not produce:

- payload, dropper, loader or module implementations;
- protocol specifications sufficient to interoperate with such a framework;
- delivery, persistence, evasion or exfiltration techniques;
- anything that improves the framework described in the input document.

Where the source document describes an offensive capability, this analysis records **what a defender
observes** and stops there. Anything below the level of "what does this look like from outside" has
been intentionally omitted. This is consistent with `PROJECT_CONTEXT.md §4` and with the master prompt's
own §16 prohibitions. If the intent behind supplying the document was to develop or extend that
framework, this repository is the wrong place for it and the answer is no.

What *is* legitimately extractable, and what makes the document valuable, is this: **it is an accurate
description of the adversary class MOBIUS must be able to reason about.** A scanner cannot see these
apps. That is a design input, not a curiosity.

---

## 1. What the document describes, structurally

The writeup describes a **three-stage architecture**:

| Stage | Role | What a static analyst sees |
|---|---|---|
| Stage 1 — "dropper" | A single class shipped inside a repackaged (trojanised) legitimate app. Contacts an HTTP server, retrieves a payload, executes it from memory. | Almost nothing. This is the whole point of the design. |
| Stage 2 — agent | Retrieved at runtime, executed in memory. Handles command channel and loads further modules. | **Not present on disk** unless captured dynamically. |
| Stage 3 — modules | Feature modules retrieved on demand and loaded into memory; unloadable. | Not present on disk. |

**The design insight, stated defensively:** the on-disk artefact is intentionally uninformative. Any
analysis that stops at `classes.dex` concludes "this app looks normal" — which is the correct behaviour
of the design and the incorrect conclusion for an analyst.

### 1.1 Claimed module set (as described) — and what it implies for detection

Recorded here only to define the *behavioural surface* a detector must cover.

| Claimed module | Behavioural surface (what it does that is observable) |
|---|---|
| Permission acquisition assistance | Repeated permission prompts; social-engineering UI |
| App control | Activity starts, package install/uninstall, notification posting, broadcast sending, running-app enumeration |
| File system access | Directory listing, file read/write, upload/download |
| Sensor capture *(camera, microphone, location)* | Camera/mic/location API use without user-visible foreground justification |
| Data collection | SMS, call log, contacts, installed packages, network interfaces, SIM/SSID access |
| Credential capture via overlay on a live app | Overlay/accessibility-based UI capture |
| Local tunnelling through the C2 channel | Long-lived outbound connection; unusual protocol |
| SSH tunnelling, SOCKS proxying | Device acting as a network pivot |

Two observations matter for MOBIUS:

1. **Every row above is a MASVS-PLATFORM / MASVS-PRIVACY concern expressed as an API co-occurrence.**
   Individually each API is legitimate — a messaging app reads SMS; a camera app uses the camera. The
   signal is the *combination*, requested at runtime, in an app whose declared purpose does not explain
   them.
2. **Several rows are hostile to the device owner rather than to a remote server.** This is where
   defensive classification differs sharply from a vulnerability scan: the question is not "is this
   exploitable" but "is this app behaving outside its stated purpose".

## 2. Why this defeats a conventional Android scanner

| Scanner assumption | How the described design breaks it |
|---|---|
| "The vulnerability is in `classes.dex`" | The interesting code is never on disk |
| "Suspicious API calls are statically visible" | The API calls are in a module that arrives later |
| "Permissions in the manifest define capability" | Runtime permission requests are made on the user's behalf by a loaded module |
| "Hardcoded C2 addresses can be extracted" | No C2 address in the APK; the stage-1 server address is the only constant, and the agent receives its endpoint at runtime |
| "HTTP traffic is inspectable as JSON" | Traffic is described as a custom binary protocol over TCP/WebSocket |
| "Analysing the app tells you what it does" | The app is a loader; behaviour is determined at runtime |

**Consequence for MOBIUS's design:** the *correct* output for such an APK is **not** a list of
vulnerabilities. It is:

> "This application loads executable code from a network source at runtime and provides no integrity
> verification of that code. Static analysis cannot determine its behaviour. Dynamic analysis is
> required, and even then the behaviour observed may not be the full behaviour."

That is a legitimate, defensible, highly useful finding — and producing it requires the architecture to
support `INSUFFICIENT_EVIDENCE` as an honoured verdict and to treat "static analysis insufficient" as a
first-class escalation rather than a failure (`ANDROID_SECURITY_METHODOLOGY.md` §6).

## 3. Detection indicators (the deliverable)

MOBIUS's `dynamic-code-loading` gate already covers the core case. These indicators extend it into a
detection ruleset suitable for an ORACLE report.

### 3.1 Static indicators — code loading

| ID | Indicator | Weight | Notes |
|---|---|---|---|
| `DCL-1` | `DexClassLoader` / `InMemoryDexClassLoader` / `PathClassLoader` instantiated with a non-constant `dexPath` | high | The single strongest static signal available |
| `DCL-2` | `InMemoryDexClassLoader` specifically (loads from a `ByteBuffer`, i.e. never touches disk) | high | Rare in benign apps; near-diagnostic when combined with network I/O |
| `DCL-3` | Reflective `Class.forName` / `getMethod` on classes whose names come from a variable or decoded string | medium | Extremely common in benign obfuscated apps — alone, not a finding |
| `DCL-4` | `dalvik.system.*ClassLoader` in an app with no plugin/update/RASP feature and no `DexClassLoader` documentation | medium | Purpose mismatch is the discriminator |
| `DCL-5` | Network response bytes flowing directly into a class loader or into `DexFile` APIs | **critical** | This is the stager pattern, at the data-flow level |

### 3.2 Static indicators — staging and purpose mismatch

| ID | Indicator | Weight |
|---|---|---|
| `STG-1` | Tiny `classes.dex` (< ~200 KB) in an app that declares heavy permissions | medium |
| `STG-2` | Very few classes with essentially no business logic but full network + storage permissions | medium |
| `STG-3` | Repackaging evidence: signature differs from the publisher's known key, or self-signed cert with a package name matching a popular app | **high** |
| `STG-4` | `Application` subclass or `ContentProvider` used purely as an early-execution hook (`onCreate` doing network I/O with no user-visible feature) | medium |
| `STG-5` | Native library present solely to provide string decryption, with no other evident function | medium |

### 3.3 Static indicators — capability clustering

The discriminator is **co-occurrence**, not any single permission. A cluster worth flagging:

```
RECORD_AUDIO + CAMERA + READ_SMS + READ_CALL_LOG + READ_CONTACTS
  + ACCESS_FINE_LOCATION + READ_PHONE_STATE + INTERNET
```
…in an app whose declared category does not account for it. A flashlight app requesting this set is a
finding; a messaging app is not. **Purpose must be part of the predicate**, which is why MOBIUS records
the app's declared category, launcher label and feature surface.

### 3.4 Dynamic / behavioural indicators (PHANTOM, if in scope)

| ID | Indicator |
|---|---|
| `DYN-1` | Outbound connection to an endpoint absent from the APK's strings |
| `DYN-2` | Bytes received on a connection are not written to disk and are immediately followed by class loading |
| `DYN-3` | Long-lived connection with periodic small binary frames on a non-standard port |
| `DYN-4` | Runtime permission prompts for permissions absent from the manifest (impossible — indicates the module *is* requesting them, which means dynamic registration) |
| `DYN-5` | Accessibility service or overlay window registered after startup with no corresponding manifest declaration |
| `DYN-6` | Sensor access (camera/mic) with no foreground UI in the foreground |

`DYN-4` is worth noting as a data point: a manifest/runtime permission mismatch between what the app
declares and what is requested is a strong staging indicator.

### 3.5 Anti-analysis indicators (defensive value: they reveal intent)

The document states the framework checks for emulators and rooted devices **before** loading modules.
Defensively this is useful in two directions:

1. **It explains a null result.** An app that detects the emulator and stays dormant will show no
   dynamic findings. "No runtime behaviour observed" must not be reported as "no malicious behaviour".
2. **It is itself an indicator.** A consumer app performing emulator/root/instrumentation detection
   without a documented anti-fraud or DRM purpose is a signal. Map to MASVS-RESILIENCE, and record the
   detection technique used rather than attempting a bypass (v1 policy:
   `ANDROID_SECURITY_METHODOLOGY.md` §6).

### 3.6 What we deliberately do not specify

- The protocol format (framing, opcodes, encoding).
- The loader's memory-execution mechanics.
- The server component's behaviour.
- Any detail that would let a reader rebuild any part of the framework.

A detection rule needs to know *that* a custom protocol exists and *what it looks like on the wire in
aggregate* (long-lived, binary, small frames, non-standard port). It does not need the grammar.

## 4. How MOBIUS should report an APK of this class

The honest report has this shape:

```markdown
## Finding F-2026-0012 — Runtime code loading from network source without integrity verification
Severity: high        Confidence: 0.9        Status: CONFIRMED
MASVS: MASVS-CODE-4, MASVS-RESILIENCE-1     MASWE: MASWE-00xx

### Observed
- `com.example.sync.SyncProvider.onCreate` calls `InMemoryDexClassLoader(ByteBuffer, parent)`
  where the buffer is populated from an HTTPS response body (evidence ev_…a1, ev_…b7).
- No signature, hash, or certificate check on the retrieved bytes (searched: 0 references to
  MessageDigest / Signature in the loading path) (evidence ev_…c3).
- Manifest requests CAMERA, RECORD_AUDIO, READ_SMS, READ_CALL_LOG, READ_CONTACTS, ACCESS_FINE_LOCATION;
  the app presents as a "Battery Saver" utility (evidence ev_…d9).

### Not determined
- What the downloaded code does. It is not present in the artefact.
- Whether a download actually occurs in this build (endpoint unreachable from the analysis host).

### Why this matters
Code loaded at runtime cannot be analysed statically. This is the characteristic structure of a
stager, not of a normal application update mechanism — normal update mechanisms ship via the Play
Store and are signed. The capability cluster is not explained by the stated purpose.

### Recommended action
Treat as untrusted. Do not install on a personal device. If required for research, analyse on an
isolated emulator with network capture.
```

Note what this report does **not** do: it does not claim the app is malware. It says what was observed,
what could not be determined, and why the observation is anomalous. That restraint is the difference
between a defensible finding and an accusation.

## 5. MASVS / MASWE mapping for this class

| Observed behaviour | MASVS | Weakness class |
|---|---|---|
| Runtime code loading without verification | MASVS-CODE (code integrity / update) | Dynamic code loading without integrity checks |
| Undeclared behaviour after module load | MASVS-RESILIENCE | Anti-analysis / dynamic loading |
| Capability cluster vs stated purpose | MASVS-PLATFORM, MASVS-PRIVACY | Excessive permission / purpose mismatch |
| Sensor access without user-visible indication | MASVS-PRIVACY | Background sensor access |
| Overlay-based credential capture | MASVS-PLATFORM | Overlay abuse |

Exact MASWE IDs must be assigned against the MASWE v1.0.0 list at implementation time rather than
guessed here (78 weaknesses, IDs MASWE-0001…0078) [S1].

## 6. What this analysis changes in the MOBIUS architecture

Four concrete changes, which is the return on reading the document:

1. **`dynamic-code-loading` is promoted from a nice-to-have rule to a core gate** with data-flow
   analysis (DCL-5), not just API presence. A grep for `DexClassLoader` produces noise; a data-flow
   from a network response into a loader produces a finding.
2. **`INSUFFICIENT_EVIDENCE` must be a first-class, honoured outcome.** Without it, MOBIUS would have to
   either fabricate a conclusion or claim "clean" — both worse than abstaining.
3. **Purpose mismatch must be modelled.** The report needs the app's declared purpose so a capability
   cluster can be judged against it. This adds a small field to `Application` and a heuristic.
4. **"Static analysis insufficient" is an escalation, not a failure.** The FSM needs a path where RECON
   concludes that static analysis cannot answer the objective, and the investigation says so explicitly.

Point 1 is the one that justifies the whole analysis: it converts a threat-intelligence document into a
concrete, testable improvement in the product.

## 7. Test corpus addition

Add to the G2/G6 benchmark groups: 3–5 APKs implementing *benign* runtime code loading (a legitimate
plugin/theme loader, a hot-patch SDK) as **negative controls** for DCL-1…DCL-5. Without them, the
detector will flag every app using a plugin architecture, which includes mainstream software. This is
the same negative-control discipline the rest of the benchmark relies on.

## 8. Status and recommendation

| Item | Status |
|---|---|
| Detection indicators documented | ✅ (this document) |
| `dynamic-code-loading` gate | Designed (`AGENT_DESIGN.md` §6) |
| ORACLE as a module | **Not implemented** — deferred; optional by design |
| Dynamic indicators (DYN-*) | Blocked on PHANTOM availability |
| Negative controls for DCL | To be added to corpus |

**Recommendation:** do not build ORACLE as a separate agent. Build the `dynamic-code-loading` gate, the
purpose-mismatch observation, and the abstention path — these are ~2% of the effort and deliver ~90% of
the defensive value. A dedicated "C2 threat research" screen is not justified.

---

## Sources

- [S1] MASWE v1.0.0 (78 weaknesses, consecutive IDs, grouped by MASVS category): https://mas.owasp.org/news/
- [S2] MASVS v2.1.0 (MASVS-RESILIENCE, MASVS-PRIVACY): https://github.com/OWASP/masvs/releases
- Input artefact: `android-c2.pdf` (supplied 2026-11-12). Not reproduced in this repository.
