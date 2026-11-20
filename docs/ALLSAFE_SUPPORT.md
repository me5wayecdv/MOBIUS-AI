# Allsafe capability matrix

**Status date:** 2026-11-20, current main `5f62271`.
**Target:** the pinned Allsafe training APK, SHA-256
`d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9` (Apache-2.0/GPL security-education
app, source: `github.com/t0thkr1s/allsafe`, challenge list from its README).
**Rule for this document:** Allsafe is never described as "passed". A complete static run that
finds nothing is a boundary statement, not a clean bill. The only measured end-to-end journey
(2026-11-19, ancestor `c6f0b82`, scan `scn_01M7RW55B200GZ5KGC8HKSR5Z7`) closed all 5 investigated
components at `insufficient_evidence` / `manual_review_required`; it is historical provenance and
was not re-run on the current head.

## Cross-cutting bounds on current main

- **Method-count bound.** The DEX index runs under ONE aggregate budget of 50,000 methods
  (`--max-methods`, capped at 50,000; the worker payload schema caps `methods` at `le=50000`).
  Allsafe's discovered method count (~88k aggregate per the latest handoff measurement; the
  historical journey recorded 92,817 across 7 DEX entries) exceeds that bound on the current
  head: the worker path refuses with an explicit "too large" service limit, and inline indexing
  would truncate at the budget with per-entry coverage marked `truncated`. Either way the result
  is a disclosed boundary, never a full-index verdict.
- **Static only.** Nothing is executed. Runtime, dynamic-instrumentation and network behaviours
  are outside the analysis by design.
- **Bounded, selected-family data flow.** Candidate sources are the Intent/deep-link,
  Bundle/content-URI and clipboard families; sinks are the catalogued WebView, file, SQL,
  dynamic-code and process-execution APIs, matched on direct calls within one method under the
  bounded CFG/data-flow rules (D-014/D-015). External caller control is never inferred.
- **The single confirming category** is `exported-component-no-permission` with all four gate
  clauses established (exported, no permission, no caller check, catalogued sink reachable).

## Per-challenge support

| # | Allsafe challenge (its README) | Current-build support | Why |
|---|---|---|---|
| 1 | Insecure Logging | **Out of scope** | Logcat disclosure is runtime observation; no catalogued logging sink, static-only build |
| 2 | Hardcoded Credentials | **Not in the supported flow** | A secrets-analysis worker exists but its enqueue route defaults OFF and its image is unpublished; DEX string extraction is indexing inventory, not a wired credential detector |
| 3 | Root Detection (Frida practice) | **Out of scope** | Dynamic bypass exercise; presence of root checks is at most inventory |
| 4 | Arbitrary Code Execution (DexClassLoader) | **Surface level** | `DexClassLoader.<init>` is a catalogued sink (MASWE-0049); reachability can be measured, attacker control cannot be established |
| 5 | Secure Flag Bypass | **Out of scope** | Frida/dynamic exercise, not an app weakness this build measures |
| 6 | Certificate Pinning Bypass | **Out of scope** | Network/runtime behaviour |
| 7 | Insecure Broadcast Receiver | **Surface level; the one confirmable shape** | Exported-receiver surface is decoded, and if a catalogued sink is reachable in-bounds the `exported-component-no-permission` gate can confirm; otherwise manual review, never "safe" |
| 8 | Deep Link Exploitation | **Surface level** | Intent/deep-link source family and exported deep-link surface exist; confirmation still requires a catalogued sink reachable in-bounds |
| 9 | SQL Injection | **Surface level** | SQL sinks appear in the Intent and Bundle/content-URI rows "where separately reached"; bounded direct-call flow only, no inter-component or content-provider resolution |
| 10 | Vulnerable WebView | **Surface level** | WebView bridge (MASWE-0033) and file/content-access (MASWE-0034) sink families exist; reachability in-bounds is measurable, exploitability is not |
| 11 | Smali Patching | **Not applicable** | Tampering technique against the APK, not a weakness in it |
| 12 | Native Library | **Out of scope** | Native libraries are inventory-only by design |

## Reading

"Surface level" means the build can show the relevant component/surface and, where the catalogue
covers it, measure bounded reachability. It does not mean the challenge is detectable end to end:
the historical journey's five investigated components all closed undetermined, and the current
head's 50,000-method aggregate bound refuses or truncates this APK before any of that. Raising
the bound or loosening the soundness policy to change these outcomes is out of scope for this
document and is a product decision, not a repair.

## Sources

- Allsafe challenge list: `github.com/t0thkr1s/allsafe` README (fetched 2026-11-20).
- Catalogue families: `docs/ANDROID_SOURCE_SINK_CATALOGUE.md` (D-014), with its own explicit
  limitations section.
- Gate semantics: `src/mobius/services/validation.py`, `docs/ARCHITECTURE_DECISIONS.md` (ADR-010/012).
- Method bound: `src/mobius/worker/dex_index.py`, `src/mobius/adapters/dex_payload.py`,
  `src/mobius/worker/provider_analysis.py`.
- Historical journey: `docs/DEMO_SCENARIOS.md` scenario C, `docs/TASK_BOARD.md` (2026-11-19).
