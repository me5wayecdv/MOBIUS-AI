# Targeted evidence packages — D-021

The `EvidencePackageBuilder` composes bounded context from persisted, investigation-scoped rows. It returns observations, finding gate evidence, bytecode method/caller references, sink and guard references, evidence metadata, and explicitly captured JADX source excerpts.

## API

- `POST /api/v1/scans/{scan_id}/code/source/evidence?class_name=com.example.Entry&method_name=onCreate` — resolve one unambiguous method from the verified APK-SHA-256/JADX-version cache and persist an immutable source-evidence record.
- `GET /api/v1/scans/{scan_id}/evidence-package?component=com.example.Entry` — include matching persisted excerpts in the bounded package.

Both routes enforce the same investigation ownership check as other scan routes. Source capture is cache-only: it never invokes JADX, starts a worker, or bypasses the approved immutable-image gate. A missing cache remains an explicit failure. Ambiguous method declarations are rejected rather than guessed.

## Source evidence contract

Each captured excerpt is at most 40 lines and is stored through the existing content-addressed `EvidenceService`. Its hash binds a canonical payload containing the exact source text, APK SHA-256, JADX version, class/method reference, relative source path, line range and fidelity (`decompiled` or `smali`). The persisted evidence event records the evidence ID and provenance. Repeated identical captures are idempotent under the existing per-investigation content hash.

The API evidence-package route and NEXUS hypothesis generation read only same-investigation source/smali evidence carrying the D-021 metadata marker. NEXUS receives the same bounded package, and its persisted decision records the source evidence IDs among the considered evidence. They re-check the stored payload SHA-256 and metadata agreement before including source text. Component filtering matches the captured class/component reference. Every snippet carries its evidence ID and hash.

## Bounds

Default limits:
- 40 observations
- 30 findings
- 40 referenced evidence records
- 48,000 characters of evidence summaries
- 500 method references
- 20 source snippets
- 24,000 source-text characters total

When rows or text exceed a limit, `truncated=true` and the package lists a limitation. Omitted rows or excerpts must not be interpreted as absent. Source excerpts are evidence of decompiled text, not proof that the decompiler preserved source-level intent or that the referenced behavior is exploitable.

## Remaining limitations

- Source excerpts are included only after an explicit capture request; a missing excerpt is not evidence that a class or method is absent.
- JADX output is a decompilation, not original source. Reflection, dynamic loading, native code, framework behavior and obfuscation fidelity remain bounded by the underlying analysis.
- Method references from the SPECTRE bytecode graph remain bytecode-derived identifiers. Reachability does not prove tainted data flow or exploitability.
- The API process never executes JADX. Cache misses require the separately approved isolated worker image and configured runtime; no image publication is performed by this feature.

No database migration, new dependency, paid library or service is introduced.
