# Isolated DEX indexing worker

**Status on this branch:** generic queue dispatch, DEX OCI tool registration, worker result schema, digest binding, and API apply endpoints are implemented with tests. The image still needs to be published and its immutable digest smoke-tested before shared SPECTRE execution is re-enabled.

## Job lifecycle

1. An analyst-owned investigation must be in `SURFACE_READY` and have a live authorization bound to the uploaded APK SHA-256.
2. `POST /api/v1/scans/{scan_id}/spectre/jobs` creates a `dex_index` row in the existing durable `worker_jobs` queue.
3. The separately deployed worker claims only registered kinds: `recon_manifest` or `dex_index`. It reads the APK from the content-addressed, read-only artifact volume.
4. The worker stages the APK in its per-investigation workspace and invokes `mobius-dex-index` in a digest-pinned OCI image.
5. The container runs without network, with read-only root, dropped capabilities, no-new-privileges, non-root UID, a bounded no-exec `/tmp` tmpfs, PID/memory/CPU/file-size/output/time limits, and only its investigation workspace mounted.
6. Androguard enumerates each root-level `classes*.dex` entry, applies the existing method budget, and emits a versioned JSON call graph with DEX coverage, class/method provenance, boundary calls, and string constants.
7. The worker stores only the JSON result in `worker_jobs`; it has no access to investigation, authorization, evidence, finding, or event tables.
8. The API validates the strict result schema, size, coverage, and artifact SHA-256 binding before reconstructing `CodeIndex`.
9. The API runs SPECTRE over the reconstructed index and persists evidence, observations, findings, verdicts, state changes, and events. Applying a job is exactly-once.

Endpoints:
- `POST /api/v1/scans/{scan_id}/spectre/jobs` — enqueue DEX indexing (202)
- `GET /api/v1/scans/{scan_id}/spectre/jobs/{job_id}` — poll status
- `POST /api/v1/scans/{scan_id}/spectre/jobs/{job_id}/apply` — validate and apply the result once

## Worker configuration

The worker process now supports both:
- `MOBIUS_RECON_IMAGE` — immutable digest reference for the manifest decoder
- `MOBIUS_DEX_IMAGE` — immutable digest reference for the Androguard DEX indexer

Other required variables remain `MOBIUS_WORKER_DB_URL`, `MOBIUS_ARTIFACT_ROOT`, `MOBIUS_WORKSPACE_ROOT`, and `MOBIUS_OCI_RUNTIME`.

Install and run:
```sh
pip install '.[worker]'
MOBIUS_WORKER_ONCE=1 mobius-recon-worker
```

The worker must use a dedicated DB role with SELECT/UPDATE only on `worker_jobs`, and a read-only mount for APK artifacts. Do not mount a rootful Docker socket into the API or into a workload container.

## DEX result contract and budgets

- Schema version: `1`
- Artifact binding: SHA-256 computed from the exact staged APK bytes; API compares it to the authorized application digest.
- Maximum result JSON: 19 MiB. Oversized or truncated worker output fails closed.
- Maximum DEX method budget: 50,000. If reached, the index reports `truncated`/ `skipped` coverage; it is not treated as a complete absence search.
- Per-entry coverage records: `indexed`, `failed`, `skipped`, or `truncated`.
- No model output is accepted as graph evidence.

## Publication

`.github/workflows/dex-worker-image.yml` builds and publishes `ghcr.io/<owner>/mobius-dex`, then runs the published image against the repository's real Apache-2.0-licensed DEX fixture with network disabled. The exact immutable image reference is emitted in the Actions summary. Do not set `MOBIUS_DEX_IMAGE` to a mutable tag.

Until that workflow succeeds and a worker deployment smoke test is completed, do not claim DEX parsing is operationally isolated in a deployed environment. The API's legacy synchronous SPECTRE and NEXUS paths remain disabled outside test/local development. The queued SPECTRE apply path is the intended route once the image digest and worker deployment are configured.


## Image smoke-test correction

The first published-image smoke test failed because the test invocation used a read-only root filesystem without the bounded `/tmp` tmpfs that the production `OciBackend` supplies. Androguard uses Python temporary files while parsing DEX. The workflow now mounts a 128 MiB `/tmp` tmpfs with `noexec,nosuid,nodev` and sets `HOME`/`TMPDIR` to that mount. A digest is not considered verified until the updated workflow passes its real-DEX smoke test.
