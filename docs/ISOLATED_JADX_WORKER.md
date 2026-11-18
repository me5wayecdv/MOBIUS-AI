# Isolated JADX worker (D-013)

**Engineering status:** implemented on this branch; CI verification pending. **GHCR publication:** blocked until explicit project-owner approval. No publication workflow has been run for JADX.

## Queue lifecycle

1. An owner-scoped investigation must be in `SURFACE_READY` with a live authorization bound to the uploaded APK SHA-256.
2. `POST /api/v1/scans/{scan_id}/code/decompile` (or the explicit `/jobs` alias) enqueues a `jadx_decompile` row in the existing durable `worker_jobs` table and emits `worker_job_queued`.
3. The existing isolated worker claims only registered kinds: `recon_manifest`, `dex_index`, and `jadx_decompile`. Queue claiming remains leased and retry-bounded.
4. The worker reads the content-addressed APK, stages it in its per-investigation workspace, and uses the pinned `JadxAdapter` + `ToolRunner` + `OciBackend` registration.
5. The JADX image reference must be immutable (`repository@sha256:<64 hex>`). Missing or mutable configuration fails closed.
6. The OCI container runs with no network, read-only root, dropped capabilities, no-new-privileges, non-root UID, bounded `/tmp`, resource limits and only the investigation workspace mounted.
7. The adapter writes the cache under `<MOBIUS_JADX_CACHE_ROOT>/<apk-sha256>/1.5.6`, with a manifest containing per-source SHA-256 and byte size. Cache hits revalidate the manifest and every source file.
8. The worker stores only cache metadata in `worker_jobs.result_json`; the source tree stays in the shared cache volume. API lookup endpoints read only the verified cache and remain owner-scoped.

## API

- `POST /api/v1/scans/{scan_id}/code/decompile` — queue isolated decompilation (202)
- `POST /api/v1/scans/{scan_id}/code/decompile/jobs` — explicit queued-job alias (202)
- `GET /api/v1/scans/{scan_id}/code/decompile/jobs/{job_id}` — job status/result metadata
- `GET /api/v1/scans/{scan_id}/code/classes` — list cached classes
- `GET /api/v1/scans/{scan_id}/code/methods?class_name=...` — bounded method declarations
- `GET /api/v1/scans/{scan_id}/code/source?path=...&start_line=1&end_line=40` — verified bounded snippet

Queue creation returns 503 until `MOBIUS_JADX_IMAGE` is configured as an immutable SHA-256 reference. The API process does not run JADX or call the OCI runtime. The worker needs `MOBIUS_JADX_IMAGE`, `MOBIUS_OCI_RUNTIME`, and `MOBIUS_JADX_CACHE_ROOT`.

## Shared cache volume

- Worker: read/write access to `MOBIUS_JADX_CACHE_ROOT`.
- API: read-only access to the same cache path.
- The APK artifact volume remains read-only to the worker.
- The cache must be persisted across worker restarts and shared with API instances. Do not use an ephemeral container filesystem for the cache.

## Local-only CI image verification

`.github/workflows/jadx-worker-image-ci.yml` uses Buildx with `load: true` and `push: false`. It loads `mobius-jadx:ci` into the GitHub runner's local Docker daemon, then runs the checked-in `AnalysisTest.dex` fixture in a hardened networkless container.

The smoke test exercises the real pinned JADX 1.5.6 binary through the adapter and verifies:
- non-empty Java/smali output was produced;
- cache identity binds the exact DEX SHA-256 and JADX version;
- the source inventory is recorded in the manifest;
- a second call is a verified cache hit;
- a bounded source snippet can be resolved from the verified cache.

The smoke writes a JSON artifact. CI does not log in to GHCR, request package-write permission, push an image, or create a remote digest.

## Publication gate

`.github/workflows/publish-jadx-worker-image.yml` is a separate `workflow_dispatch`-only workflow. It requires `owner_approval=APPROVED` and a non-empty approval reference. It has no `push`, `pull_request`, schedule, or workflow-call trigger. **It has not been run.** Do not run it until the project owner has made the decision and the user has explicitly approved publication.

After approved publication, record the immutable GHCR digest in the deployment configuration. Until then, `MOBIUS_JADX_IMAGE` must remain unset and queued decompilation must fail closed with 503.

## Boundaries

- The CI fixture is the checked-in DEX fixture, not a user APK or graduation-demo APK.
- No emulator, device, real APK execution, deployment, production database migration, paid service or inference is involved.
- The smoke's direct process backend exists only inside the outer hardened test container. Production execution uses the host-side digest-pinned `OciBackend`.
- D-021 remains partial until decompiled source is persisted as investigation evidence and linked as bounded excerpts in evidence packages.
