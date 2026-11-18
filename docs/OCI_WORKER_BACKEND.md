# OCI worker backend

**Status: backend adapter, policy tests, and queued JADX worker registration implemented; deployed worker host not verified.**

The adapter invokes a configured Docker/Podman-compatible runtime with a fixed container policy.
It is not enabled by default and no JADX image is registered by the application.

## Enforced settings

- Immutable image references (repository plus SHA-256 digest); no pull-at-runtime.
- Network disabled; network-enabled jobs fail closed.
- Read-only container root, all Linux capabilities dropped, no-new-privileges.
- Unprivileged UID/GID, PID, memory, CPU, CPU-time and file-size limits.
- Private bounded tmpfs, minimal environment, no host home or credential mounts.
- Only the per-investigation workspace is bind-mounted at /work.
- Host-side streaming capture enforces combined stdout/stderr limits and wall-clock timeout;
  timeout/output overflow kills the runtime process group.

## Trust boundary

The host OCI daemon/runtime remains trusted computing base. A user controlling a rootful Docker
socket can generally obtain host-level control. Prefer rootless Podman or a dedicated isolated
worker VM and a narrowly scoped runtime account. Never mount the daemon socket into a workload.

The readiness check verifies runtime availability and that configured digest images are present.
It is an operational preflight, not cryptographic attestation of daemon policy.

## Limitations

- Not invoked by the API process or NEXUS directly. The existing durable queue worker uses this backend for RECON, DEX and queued JADX jobs when immutable image references are configured; no image is enabled by default.
- No immutable JADX image digest published by this project. The CI workflow builds/loads locally and runs the real DEX fixture smoke with no push; publication is a separate owner-gated manual workflow and remains disabled pending approval.
- JADX jobs stage the authorized APK in the per-investigation workspace and persist verified cache metadata in `worker_jobs`; source cache files require a shared writable worker/read-only API volume. ToolExecution rows and ARCHIVIST integration remain out of scope.
- Existing manifest/DEX parsing remains in the API process. Production remains NO-GO until
  intake parsing is moved to a constrained worker and authentication/ownership checks exist.


## JADX worker registration

D-013 adds `jadx_decompile` to the durable worker queue. The worker uses the same OCI policy
and requires `MOBIUS_JADX_IMAGE` to be an immutable digest reference. The API only enqueues jobs
when that setting is present; it does not invoke the runtime. See
[`ISOLATED_JADX_WORKER.md`](ISOLATED_JADX_WORKER.md).

The local CI image smoke is intentionally not a publication: Buildx uses `load: true` and
`push: false`, then runs `AnalysisTest.dex` in a networkless, read-only-root container. The
separate GHCR publication workflow has only a `workflow_dispatch` trigger and requires an
explicit owner approval input plus a decision reference. It has not been run.
