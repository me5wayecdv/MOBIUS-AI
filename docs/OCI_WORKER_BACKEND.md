# OCI worker backend

**Status: backend adapter and policy tests implemented; deployment not verified.**

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

- Not wired to API/NEXUS and not configured by default.
- No immutable JADX image digest selected or published by this project.
- No APK input staging, artifact persistence, ToolExecution row, or ARCHIVIST events.
- Existing manifest/DEX parsing remains in the API process. Production remains NO-GO until
  intake parsing is moved to a constrained worker and authentication/ownership checks exist.
