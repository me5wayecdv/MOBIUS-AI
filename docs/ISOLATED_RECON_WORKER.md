# Isolated RECON worker queue

**Status: durable queue/API, worker consumer, OCI manifest tool image, and tests implemented. Deployment still requires building and publishing the image, pinning its digest, and provisioning a restricted worker database role.**

## Request flow

1. API validates the analyst owns the investigation and creates a `worker_jobs` row in `queued` state.
2. The API emits `worker_job_queued` in the investigation event log in the same transaction.
3. A separately deployed `mobius-recon-worker` process claims a job using a five-minute lease and PostgreSQL `FOR UPDATE SKIP LOCKED`.
4. The worker reads the APK by its content-addressed key from a read-only artifact volume.
5. The worker stages the APK in a per-investigation workspace and invokes the manifest decoder through `OciBackend`.
6. The OCI container runs with no network, read-only root, dropped capabilities, no-new-privileges, non-root UID, PID/memory/CPU/file-size/output/time limits, and only the job workspace mounted.
7. The worker stores the decoded manifest result in the queue row. It does not query investigation, user, authorization, evidence, or event tables.
8. The API exposes job status. An authorized analyst calls the apply endpoint; the API rechecks ownership, applies the manifest through RECON, records evidence/state/events, and marks the job applied exactly once.

Endpoints:
- `POST /api/v1/scans/{scan_id}/recon/jobs` — enqueue (202)
- `GET /api/v1/scans/{scan_id}/recon/jobs/{job_id}` — poll
- `POST /api/v1/scans/{scan_id}/recon/jobs/{job_id}/apply` — apply completed output once

The old `POST /recon` endpoint is disabled by default. Tests may use the inline path; local developers must explicitly set `MOBIUS_RECON_INLINE=1`. It returns 503 otherwise. Do not enable this fallback in a shared or production environment.

## Build and pin the parser image

Build from repository root:

```sh
docker build -f workers/recon-image/Dockerfile -t mobius-recon:local .
```

Publish it to a trusted registry, resolve the immutable digest, and configure the worker with the full `registry/repository@sha256:<64-hex>` reference. The application intentionally has no default image digest and will fail closed without one.

## Worker process configuration

Required environment:
- `MOBIUS_WORKER_DB_URL` — a dedicated PostgreSQL role, not the API's database credential
- `MOBIUS_ARTIFACT_ROOT` — artifact volume mounted read-only to the worker host
- `MOBIUS_WORKSPACE_ROOT` — private writable ephemeral worker directory
- `MOBIUS_OCI_RUNTIME` — absolute path to rootless Podman or an equivalently isolated runtime
- `MOBIUS_RECON_IMAGE` — immutable parser image digest

Run:
```sh
mobius-recon-worker
```

For a one-job smoke test:
```sh
MOBIUS_WORKER_ONCE=1 mobius-recon-worker
```

## Least-privilege database role

The worker only needs SELECT and UPDATE on `worker_jobs`. It must not receive access to the application tables, users, authorizations, investigations, findings, evidence, reports, or events.

Example for PostgreSQL (run as the database owner; replace role/database names):

```sql
CREATE ROLE mobius_worker LOGIN PASSWORD 'replace-with-secret';
GRANT CONNECT ON DATABASE mobius TO mobius_worker;
GRANT USAGE ON SCHEMA public TO mobius_worker;
GRANT SELECT, UPDATE ON TABLE worker_jobs TO mobius_worker;
```

The API role retains INSERT/SELECT/UPDATE access required to create and apply jobs. The worker's database URL is separate from `MOBIUS_DB_URL`.

## Recovery and limitations

- Claims use a five-minute lease. An expired job may be reclaimed up to three attempts; an exhausted lease is marked failed.
- A worker crash does not leave a job permanently locked, though recovery waits for lease expiry.
- The worker writes only queue results; API applies results to investigation state and evidence.
- Result XML is bounded to 10 MiB and stored in the job JSON field. A later object-store result channel may be preferable at larger scale.
- The worker must run on a dedicated host/VM with rootless Podman preferred. Do not mount a rootful Docker socket into the API or a workload container.
- The parser image digest has not been published or verified by this repository. Until a trusted digest is configured and a real worker deployment is smoke-tested, isolated execution is implemented but not operationally enabled.
- Real authentication remains a separate release blocker. The header-based analyst identity must not be exposed to an untrusted network.
