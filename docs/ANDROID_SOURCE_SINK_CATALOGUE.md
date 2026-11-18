# Android source/sink catalogue (D-014)

**Catalogue:** `mobius.android.source-sink` · **Version:** 1 · **Platform:** Android

The source/sink catalogue is data-driven in `src/mobius/data/android_source_sink_catalogue.yaml`.
It records exact DEX owner descriptors and method names, plus source method descriptors, trust-boundary
labels, confidence, impact, MASWE/MASVS mappings and OWASP references. Adding a rule is a YAML data
change; the loader validates identifiers, descriptors, mappings and duplicate IDs/API keys.

## Interpretation rules

- A source entry is a *candidate untrusted-input origin*. The API call alone does not prove its
  value is attacker-controlled: the producer, caller, URI origin or IPC context must be established.
- A sink entry is a security-relevant operation candidate. A sink match alone is not a finding.
  Taint/data-flow, sanitization, path containment, origin validation and control-flow order are not
  implemented by D-014; bounded data-flow is D-015.
- Confidence describes catalogue/API matching confidence, not exploitability or finding confidence.
- Guards are caller-check indicators. Their presence does not prove that a check dominates a sink,
  checks the correct permission, or is not bypassable.
- Matching is exact on class descriptor and method name; no substring matching is performed.
- No runtime network lookup is performed. The YAML file is versioned with the code and packaged
  into the distribution.

## Current families

| Family | Candidate sources | Candidate sinks | Mapping |
|---|---|---|---|
| Intent / deep link | `Intent.getStringExtra`, `getData`, `getDataString`, `Uri.getQueryParameter` | WebView URL load; file/process/SQL operations where separately reached | MASWE-0029, 0032, 0035, 0050 |
| Bundle / content URI | `Bundle.getString`, `ContentResolver.openInputStream` | File open/write, provider file open, SQL | MASWE-0050 |
| Clipboard | `ClipboardManager.getPrimaryClip` | No sink implied by source alone | MASWE-0030 |
| WebView bridge | — | `WebView.addJavascriptInterface` | MASWE-0033 |
| WebView local resources | — | `WebSettings.setAllowFileAccess`, `setAllowContentAccess`, file-URL access setters | MASWE-0034 |
| Dynamic code | — | `DexClassLoader.<init>` | MASWE-0049 |
| Process execution | — | `Runtime.exec`, `ProcessBuilder.start` | MASWE-0050 |

The exact per-rule mappings and OWASP references are authoritative in the YAML entries. They are
curated against the current MASWE v1.0.0 / MASVS v2 control identifiers; do not revive older beta IDs.

## Test strategy

- Positive tests: known exact Android source/sink APIs resolve and retain MASWE/MASVS/reference metadata.
- Data-only extension test: a fixture YAML adds a source and sink without changing Python code.
- Negative tests: unknown methods, substring-only class matches, ordinary value reads and generic
  `startActivity` calls do not resolve as sinks.
- Schema tests: duplicate API keys and malformed identifiers/mappings fail closed.

## Explicit limitations

D-014 does not connect sources to sinks, infer attacker control, evaluate sanitizer correctness,
perform CFG/dominator analysis, or emit findings. Existing reachability still answers only whether a
catalogued sink API is reachable from an entry point. D-015 owns bounded CFG/data-flow and guard order.
D-021 remains partial until actual decompiled source is persisted and included as bounded evidence.


## OWASP references

- [MASWE-0033 — Sensitive Native Functionality Exposed in WebViews](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0033/)
- [MASWE-0034 — WebViews Allow Access to Local Resources with Untrusted Content](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0034/)
- [MASWE-0035 — WebViews Loading Untrusted Content](https://mas.owasp.org/MASWE/MASVS-PLATFORM/MASWE-0035/)
- [MASWE-0049 — Unsafe Dynamic Code Loading](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0049/)
- [MASWE-0050 — Unsafe Handling of Untrusted Data](https://mas.owasp.org/MASWE/MASVS-CODE/MASWE-0050/)
