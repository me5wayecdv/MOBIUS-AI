# Targeted evidence packages — D-021

The `EvidencePackageBuilder` composes bounded context from persisted, investigation-scoped rows. It supports optional component filtering and returns observations, finding gate evidence, method references from recorded paths, sink and guard references, and referenced evidence metadata including SHA-256 hashes.

## API

`GET /api/v1/scans/{scan_id}/evidence-package?component=com.example.Entry`

The route applies the same development identity ownership check as the other scan routes. The service does not read evidence from another investigation, does not invoke a model, and does not create findings or hypotheses.

## Bounds

Default limits:
- 40 observations
- 30 findings
- 40 referenced evidence records
- 48,000 characters of evidence summaries
- 500 method references

When rows exceed a limit, `truncated=true` and the package lists a limitation. Omitted rows must not be interpreted as absent. Statements, source refs, gate evidence and method identifiers retain their originating row/evidence IDs.

## Important coverage limitation

The current SPECTRE index evidence stores graph/index summaries, not decompiled source text. Packages therefore provide bytecode-derived method/caller identifiers and evidence provenance, not source snippets. D-012 (JADX integration and source-reference persistence) remains necessary to satisfy the full D-021 acceptance criterion for actual relevant code excerpts. This is explicitly partial, not silently treated as complete.

No paid library or service is used.
