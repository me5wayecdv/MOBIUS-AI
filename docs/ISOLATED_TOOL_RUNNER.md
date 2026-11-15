# Isolated Tool Runner — implementation contract

**Status: PARTIAL (contract and fail-closed dispatcher only).** This is not yet a production
sandbox and does not execute JADX or any other binary.

## Boundary

- Tool names resolve only through a server-owned registry.
- Each registered tool pins an absolute executable path, version identifier, strict Pydantic
  argument schema, trusted argv builder, and resource/network limits.
- User/model input supplies data fields only. It cannot select an executable, append flags,
  or supply a shell command.
- The dispatcher never invokes subprocesses itself.
- Execution is refused unless an injected backend explicitly reports a verified isolation
  boundary. A fake/test backend is only for unit tests.
- Workspaces are private per investigation and checked to remain under the configured root.
- Output is bounded and stderr is reduced to a bounded tail.

## Required backend guarantees before enabling real tools

A production backend must enforce, outside the API process:

1. Unprivileged UID/GID, read-only root filesystem, no host mounts except a per-job workspace.
2. Network disabled by default; no host network, Docker socket, cloud metadata, or credential mounts.
3. CPU, memory, PID, disk, wall-clock, and output quotas enforced by the runtime.
4. Process-tree termination on timeout/cancel and guaranteed workspace cleanup.
5. APK mounted read-only; output mounted separately with bounded size.
6. Pinned image digest and tool version, seccomp/AppArmor or equivalent, and auditable lifecycle events.
7. A health/attestation check that proves the configured runtime policy is active before accepting jobs.

A boolean readiness signal from a backend is a trust boundary, not a security proof. The concrete
container/VM backend needs independent integration tests and deployment review before production use.

## Current limitations

- No backend implementation is wired to the API or NEXUS.
- No tool binary is registered by default.
- No subprocess is started by this module.
- No database persistence or ARCHIVIST event emission is integrated yet.
- The existing API still processes current APK parsing in-process; this contract does not fix that
  existing exposure. Production/internet deployment remains blocked pending worker isolation and
  authentication/authorization work.
