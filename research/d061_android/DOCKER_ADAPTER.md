# Docker lifecycle adapter (HELD, source-only, nothing run)

Status: preparation only. No docker call, pull, SDK/JDK, emulator, ADB, APK or runtime has happened. SDK terms are user-approved
(2026-11-21 19:21 "اه") but NOT executed. The red result of the cgroup probe (run 44913618178) is inconclusive; the "own cgroup has no delegated
controllers" explanation is a hypothesis, not a host fact. Docker engine availability and enforcement on the runner are unverified until a run.

## Compatibility choice (explicit)
Option B, translate: Docker is the OUTER resource and lifecycle provider for two exact run-bound sibling containers (runtime, control).
The reviewed inner unshare/mount provisioning of `namespace_supervisor` is not run inside a container, because a default container's seccomp and
dropped capabilities block it and the only workaround is privilege (rejected: no --privileged, no host PID/net/IPC, no docker socket in any payload).
Its controls become container configuration. The owner, relay, staging, export and evidence modules are reused unchanged.

## Control translation (spec lives in docker_lifecycle.py, enforced as an exact-match predicate over a supplied `docker inspect`)
| Old control | Container configuration | Proof status |
|---|---|---|
| no uplink | `--network none` (loopback only), `--ipc none`, no ports/links | inspect shows none; actual egress absence still needs the existing no-egress evidence, not the flag |
| PID namespace | default private PID ns (`PidMode` empty) | inspect only; member absence is a separate check |
| mount root / read-only | `--read-only` rootfs, one run+role-specific bind at /work, no other mounts | exact Mounts match |
| priv drop | `--user 65534:65534`, `--cap-drop ALL`, `no-new-privileges` | exact match |
| cgroup leaf limits O2 | `--memory`=`--memory-swap`, `--pids-limit`, `--cpus` | inspect equality; kernel enforcement NOT verified (needs the existing readback/behavior test) |
| KVM | runtime only: `--device /dev/kvm`; control never | exact Devices match |
| image | digest-pinned, `--pull never` (must already exist) | name only, closure/digest checks stay with staging |

## Changed proof obligations (what no longer holds and what replaces it)
- O1 owner record: add container name/ID and run ID to the owner locator BEFORE `docker create`. A name not created by this owner is never removed (ownership rule unchanged).
- O2 limits: replaced by validate_inspect equality plus the existing behavioral limit check, still to be defined for Docker. Not proven.
- O3 lifetime: owner holds the daemon API as a root-only resource; no payload gets it. Independent recovery after owner death stays UNVERIFIED (no signals, no mutation), unchanged.
- O4 absence: `docker rm`/exit code alone is NEVER accepted. Needs both (a) `inspect` returns not-found after removal and (b) the container's cgroup dir (path read from inspect/daemon cgroup driver, opened read-only by the owner before start) reports `populated 0` or is gone. `absence_verdict` validates a supplied record of both; missing either is UNVERIFIED.
- Runtime/control separation: two containers, two private work dirs, no shared mount. Control must outlive runtime and have no SDK/emulator/ADB/KVM. The order check stays: runtime termination, control survival, then control absence.
- Evidence export: payloads never write a shared dir. Owner (root) reads each /work after the container stops, through the existing allowlisted exporter. The channel between relay and payload (handoff) is the OPEN item below.

## Open, not decided here
1. Relay-to-payload control channel without a shared mount or network: candidates are the owner copying fixed closed input files into each /work before start and reading results after stop (no live channel), or one narrow fifo/file per role. Needs reviewer choice; I recommend no live channel.
2. Whether Docker exists and enforces the limits on the standard runner is unknown. The first fact needed is docker version/info plus one create-inspect-remove of an inert pinned image, which is a NEW run and needs main/user authority; not requested here.
3. KVM device node permission for uid 65534 inside the container (udev rule on the runner) is unverified.
4. Evidence that `--cpus`/`--memory` actually limit is a behavior test inside the container, not defined yet.
