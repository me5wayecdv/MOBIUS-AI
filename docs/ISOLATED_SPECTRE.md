# Isolated SPECTRE execution

**Status: security gate implemented; isolated DEX worker not yet implemented.**

SPECTRE currently calls `index_apk()` through Androguard. This parses DEX entries extracted from an uploaded APK. APK ZIP limits reduce archive expansion risk, but they do not make a complex DEX parser safe to execute inside the API process.

Until a dedicated DEX worker exists:
- The `POST /scans/{id}/spectre` endpoint returns HTTP 503 outside the test environment unless `MOBIUS_SPECTRE_INLINE=1` is explicitly set.
- The `POST /scans/{id}/nexus` endpoint is gated by the same policy because its dispatch loop can invoke SPECTRE internally.
- Tests retain the in-process path so deterministic graph and validation behaviour remains covered.
- `MOBIUS_SPECTRE_INLINE=1` is for isolated local development only. Do not set it on a shared or internet-facing API.

## Required next step

Implement a separately deployed DEX indexing job using the existing `worker_jobs` queue and OCI boundary:
1. Add a closed `dex_index` job kind with strict worker-side dispatch.
2. Run Androguard only inside a digest-pinned OCI image with network disabled, read-only root, non-root UID, dropped capabilities, no-new-privileges, resource limits, and per-investigation workspace.
3. Return a bounded, versioned, schema-validated representation of the call graph, boundary calls, string constants, DEX coverage, and class/method provenance.
4. Verify the result is bound to the queued APK artifact SHA-256 before the API accepts it.
5. Reconstruct the typed `CodeIndex` in the API and persist evidence, observations, findings, and events only in the API process.
6. Add real APK DEX fixtures, malformed DEX tests, partial multi-DEX coverage tests, output-size tests, worker crash/retry tests, and a networkless container smoke test.
7. Only then remove the local-development gate from shared SPECTRE/NEXUS execution.

The manifest worker is not a substitute for DEX isolation. Do not describe SPECTRE as operationally isolated until this path is deployed and smoke-tested.
