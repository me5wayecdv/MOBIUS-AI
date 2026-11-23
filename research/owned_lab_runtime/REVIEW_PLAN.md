# Exact signed lab runtime, held design

No runtime execution is permitted by these sources. `probe.py` defaults held and has no CLI execution route. The manual workflow is deliberately outside workflow registration and stops at the transfer gate. No source is pushed by preparing this packet.

## Fixed input

APK SHA256 `6b7081010eb6dfb2b90e27b94a761020528e4ea8b17d300bdd372e0b130deca8`, certificate SHA256 `197ce8054d16f0c8bded9802c0ada2a4908ed0f7fd1b923decb7d37c1074f75c`. Retain the existing artifact, never rebuild or re-sign to satisfy a transfer problem. The signing key was discarded. Any substitute digest requires a new review, not a text edit to this constant.

## Transfer decision, explicitly unresolved

A GitHub-hosted runner cannot read the current retained local file. No upload is authorized. Possible routes are a repository blob (permanent public audience/history) or temporary Actions artifact (public-repo run audience and retention/storage implications). A hidden gist, anonymous host or different repository is NOT an assumed private route. Do not silently choose either. A runner rebuilding/re-signing changes identity and is not an equivalent route. Resolve exact audience/destination/retention first, then add one digest-checked transfer step. Until then the workflow is not feasible to dispatch.

## Proposed resource and source envelope

One standard public-repo ubuntu24.04 hosted job, 30-minute outer cap, no cache/image publication. Two guest vCPUs, 2048MiB RAM, one fresh API29 default x86_64 AVD in a run-owned0700 directory, no snapshots, no personal data/accounts, no Play services. Check KVM access, >=4GiB free host RAM and >=10GiB disk before any guest start; otherwise fail, no software fallback. These are proposed admission checks, not proof current hosted capacity exists.

Google system-image metadata currently lists API29 default x86_64 revision8, 689676765-byte download with SHA1 e4b798d6fcddff90d528d74ef22ce3dd4a2ca798. Emulator37.3.10 and platform-tools37.0.3 archive URLs/sizes/SHA1 are now pinned from official metadata in toolchain-pins.json, but not downloaded or executed. Do not use a mutable action that silently installs current emulator tools. Pin all archives against official metadata and record the actual host image version. Prior successful Allsafe jobs establish historical hardware-emulator capability only. Their target, writes/deletes and collector must not be reused.

## Supervisor requirements before implementation/activation

- Run-owned adb server port and exact even emulator console port/serial. No global adb kill-server. Bind console/adb to loopback and disable emulator outbound networking where supported; no guest internet needed for fixed providers. The precise offline network enforcement still needs verification, not a flag-only claim.
- Track new emulator process as a dedicated session leader, record PID, PGID, /proc start time and executable identity, and retain the Popen owner. Capture owned AVD path and inode, never infer ownership from a matching process name. Boot<=240s; install<=90s; each read<=45s; total probe<=180s; aggregate supervisor<=15min with job<=30min.
- Bounded stdout/stderr streaming collector, <=256KiB per command, kill/reap exact owned process group on deadline/overflow. `collector.py` now bounds combined stdout/stderr and deadline, signals its exact child through pidfd and reaps it. RetainedChild records process identity and exact owner reaping. Descendant cleanup remains explicitly UNVERIFIED, so these are NOT an active emulator supervisor. No raw command output in repo logs.
- Verify apksigner certificate/digest before install, exactly one installed base APK/hash before probes, shell UID2000. No root. Install without replacement flags onto only a freshly created emulator. Negative provider must explicitly deny because not exported, then positive query returns exactly the one fixed synthetic row. No selection, projection override, update/delete/insert, fuzzing or model.
- Stop before positive if private denial is unclassified. Success proves shell plain-read exposure only, never injection, ordinary application UID access or whole-agent completion.

## Cleanup and evidence requirements

In finally, if retained owner/PID/PGID/starttime/executable still agree, TERM own group, wait5s, KILL only that group if still owned, then reap. Record unresolved ownership as UNVERIFIED, not cleanup success. Remove only owned AVD/work directory after final process absence and exact path/inode checks. Do not delete shared SDKs, other AVDs or processes. On runner cancellation, an always-step must independently verify the same identity record; if identity cannot be proven, report unresolved rather than signal broadly. Disposable-runner destruction is a final platform containment layer, not an observed cleanup proof.

Allowlisted visible log fields: fixed stages, exact APK/cert/system-image digests, typed private-denial/seeded-row outcomes, UID2000, deadline/overflow status, owned-process cleanup state. Raw adb/install/guest output stays in0700 job files, never uploaded by default. No artifact publication until its audience is separately decided.

## Remaining decision

First decide the exact signed APK transfer destination/audience/retention. Complete descendant/network containment and independently review supervisor/collector/toolchain pins before asking for one API29 emulator install+two read probes on the exact digest, with stated log audience and no retry. Existing three-worker canary yes explicitly excluded emulator use. Main publication for that separate workflow remains unanswered and does not authorize this design.
