# D-016 — APK code coverage and limitations manifest

The coverage manifest is a read-only, investigation-scoped summary of what MOBIUS actually inventoried and analyzed. It is exposed as JSON and embedded in every ARCHIVIST report.

## API

`GET /api/v1/scans/{scan_id}/coverage-manifest`

The endpoint uses the same owner check as the report and evidence routes. It reads the APK from the content-addressed artifact store and derives analysis claims only from persisted evidence and worker-job rows.

## Manifest sections

- **Artifact identity:** application ID, APK SHA-256, package/version identity and byte size.
- **APK inventory:** every root-level `classes*.dex` entry up to the bounded inventory limit; native `lib/*.so`, assets and resources are counted and sampled. Inventory is not semantic analysis.
- **RECON:** manifest evidence and observation counts.
- **DEX:** per-entry indexed/failed/skipped/truncated/not-indexed status, class/method counts, call-graph nodes/edges, completeness and evidence ID/hash. A DEX result is complete only when its digest-verified evidence covers the APK's complete enumerated DEX entry set.
- **JADX:** latest decompile worker state, APK digest binding, tool version, fidelity and source-file count/sample when a matching successful result exists.
- **Reachability:** SPECTRE observation and truncation counts.
- **Budgets:** DEX method default, inventory/sample caps, and the actual SPECTRE reachability depth/node budgets persisted with new DEX index evidence. Older evidence without those fields is explicitly marked as missing per-investigation budget provenance.
- **Limitations:** reflection, dynamic loading, native code, assets/resources, obfuscation, control-flow/data-flow and framework-boundary limitations.

## Status semantics

| Status | Meaning |
|---|---|
| `complete` | The named inventory/index completed for its declared scope and all enumerated entries are accounted for. It does not mean all code semantics were analyzed. |
| `partial` | Some entries failed, were skipped, were not indexed, or a reporting cap was reached. |
| `not_run` / `not_requested` | No persisted evidence/job proves that stage ran. |
| `inventory_only` | Names/counts were collected; content was not analyzed. |
| `unsupported` / `not_implemented` | The capability is not provided by this baseline. |

Overall status remains `partial` while unsupported capabilities exist. Truncation and parse failures are explicit; a missing entry or absent finding must never be read as proof of safety.

## Integrity and bounds

- APK inventory first verifies the content-addressed APK SHA-256, then reads ZIP central-directory metadata only; it does not extract or execute APK contents.
- DEX coverage is taken from the latest same-investigation DEX evidence whose stored bytes pass SHA-256 verification. New SPECTRE evidence records the actual reachability depth/node limits; older records are not retroactively assigned defaults.
- JADX worker results are accepted only when their reported APK SHA-256 matches the investigation artifact.
- Archive inventory and the DEX entry list are capped at 20,000 entries; native/assets/resources samples at 50 each; JADX source-file sample at 20.
- No schema migration, new dependency, image publication, or tool execution is performed by the manifest builder.

The manifest reports the scope and evidence available to this run, not a guarantee that every possible code path or behavior was discovered.
