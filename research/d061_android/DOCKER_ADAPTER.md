# Docker lifecycle adapter v2 (HELD, source-only, nothing run)

Status: preparation only. No docker call, pull, image build, SDK/JDK, emulator, ADB, APK or runtime has happened. SDK terms are user-approved
(2026-11-21 19:21) but NOT executed. The cgroup probe red (run 44913618178) is inconclusive. Docker presence/enforcement on the runner is unverified.
The relay is NOT unchanged: three call-site groups change (below). The adapter is a source skeleton with exact-spec predicates, not a runnable launcher.

## Correction to v1
v1 recommended "no live channel, preseed inputs and read after stop". That was wrong: the product journey is live and bidirectional
(sibling_supervisor.main). The existing channel is already owner-mediated root files over two bind dirs per role, and v2 keeps it exactly.

## Live handoff mapping (existing protocol unchanged; only the transport under it is Docker)
Per role the container gets two binds, the same two dirs namespace_supervisor binds today:
`/work` rw = `<root>/<role>/work` (child writes, relay reads with bounded anchored reads) and `/control` ro = `<root>/<role>-in` (relay writes, immutable once published).
| # | Existing step (sibling_supervisor) | Files | Docker mapping |
|---|---|---|---|
| 1 | relay writes context.json into runtime-in and control-in before launch | `<role>-in/context.json` | `/control` ro in each container |
| 2 | launch runtime, wait provision-ready (240s) | runtime work: `provision/ready.json`, evidence zero-state, apk, CA, build-result | runtime `/work` rw; relay reads from host path |
| 3 | relay validates, snapshots public files into control-in, ready.json LAST | `control-in/snapshot/*` | control `/control/snapshot` ro, written before control launch |
| 4 | launch control, wait control commit (30s) | control work: `commit.json` (and `cancel.json`) | control `/work` rw; relay `pump()` polls cancel.json unchanged |
| 5 | relay sends commit to STILL-LIVE runtime; emulator-stage request/ack | `runtime-in/commit.json`, `runtime-in/emulator-stage-ack.json`, `runtime/work/emulator-stage-request.json` | runtime `/control` ro (relay writes while runtime runs) and `/work` rw |
| 6 | wait operation-returned (60s), read events/receipts | `runtime/work/evidence/*` | unchanged host reads |
| 7 | runtime teardown 60s, absence proven, THEN collect | `check_absent(runtime)` | REPLACED: stop bound ID, wait, extended absence (below) |
| 8 | relay publishes accepted result into STILL-LIVE control inbox, control persists and reports | `control-in/result/*`, control waits `/control/result/result.json` | control `/control/result` ro appears while control runs |
| 9 | failure path: kill runtime, write host-failed result, control returns | killpg, `result.json` | REPLACED: kill only the bound ID |
Because the bind is a host directory mount, files the relay creates later inside `<role>-in` appear live in the running container. That must be confirmed by a real run (propagation rprivate does not block host-side file creation inside the mounted directory, but this is unverified here).
Changed call sites: (a) `launch(role)` = intent, create, bind ID, gated start, bind observed identity, release; (b) every `killpg`/`poll`/`wait` on a role = operations on the BOUND container ID only; (c) `check_absent` gains the extended checks. `pump()`, all JSON/file protocol, expected-context consumption, collect/publish and cancellation polling are reused as is.

## Exact spec (docker_lifecycle.py), fields per Docker Engine API schema (moby swagger.yaml v27.3.1)
Ported from namespace_supervisor: uid 65534; runtime gid = kvm_gid (control gets 65534:65534, no KVM, no extra group); fixed env; entrypoint `/runtime/bin/python`, cmd `container_gate.py <driver> /work`;
workdir /work; rlimits cpu 300, as 8GiB, fsize 4GiB; no uplink; read-only rootfs; cap-drop ALL; no-new-privileges.
Device tuple compared whole: `/dev/kvm:/dev/kvm:rw` (runtime only). Mounts compared whole: Type, Source, Destination, RW, Propagation (rprivate), plus HostConfig.Mounts BindOptions allowlist, nothing else mounted.
Image: `docker image inspect` read independently; Id must be sha256 and RepoDigests must contain the requested digest; the container's Image must equal that Id. Entrypoint, Cmd, Env (exact set), WorkingDir, declared Volumes, Healthcheck, log driver (none), restart policy, GroupAdd, DeviceRequests, Runtime (runc), Cgroupns (private), UTS, extra hosts/DNS/ports/links/volumes-from checked. This is a PARTIAL ALLOWLIST of security-relevant fields. It validates supplied records only; fixtures are hand-built from the documented schema, not captured from an engine. Not every engine field is covered.

## Launch lifecycle (no ID before create)
1. `launch_intent` record (name, may_remove_by_name false) persisted BEFORE `docker create`.
2. `after_create`: ID bound only from a well-formed 64-hex line. Missing/garbled output = create_unverified: never delete by name, report UNVERIFIED.
3. `docker start -i` with the owner holding the stdin pipe; `container_gate.py` blocks on `os.read(0,1)`. EOF without the byte exits 3 and never runs the driver (owner death means no workload).
4. `bind_started`: owner reads State.Pid from inspect AND its own `/proc/<pid>/cgroup` and pid/mnt/net namespace inodes; cgroup path must contain this container ID, net ns must differ from the host's. Identity record persisted, THEN the one byte is written.
A created-state inspect has no pid/cgroup; those exist only after start, which is why step 4 follows a gated start.

## Absence (preserved obligations, not two booleans)
`absence_verdict` needs ALL of: inspect not-found after removal, held cgroup unpopulated or gone, namespace member scan empty (existing check_absent semantics), namespace handles absent, leader reaped. Any False is PRESENT, any missing is UNVERIFIED. Docker removal/exit code alone is never accepted. Independent recovery after owner death stays UNVERIFIED (no signals, no mutation); only the live owner kills, by bound ID.

## Requirements that change or are lost (honest list)
- `nosuid,nodev,noexec` on the `/control` inbox cannot be expressed for Docker bind mounts. Mitigations: ro, cap-drop ALL, no-new-privileges, non-root. noexec on the inbox is lost.
- The jail copied a verified closure into a fresh rootfs; with Docker the closure is the IMAGE. Closure-lock verification must bind to image content, and building that image (SDK download) is itself SDK execution, held. `role_closure_ok` is a predicate over a supplied file list (control must lack SDK/ADB/emulator/qemu); how the list is acquired is open.
- RLIMIT_AS maps to `--ulimit as` but kernel enforcement is unverified; memory/pids/cpu equality is config only.
- /dev/shm: `--ipc none` leaves no shared-memory tmpfs; the emulator may need one. Unknown.
- Mount propagation of later relay writes into the running container, uid 65534 KVM access, Docker version flags (`--no-healthcheck`, `--cgroupns`) on the runner: all unverified.

## Not done / needs authority
No docker-info/create diagnostic run is proposed here; that would be a new run needing main/user authority and reviewer clearance.
