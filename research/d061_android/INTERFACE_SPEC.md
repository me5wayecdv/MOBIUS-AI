# Held interface specification (not executed, not wired, no producer evidence)

Status: specification only. No behaviour here has run. Nothing in this file clears an
execution, legal or audience hold. Records below are the shapes a REVIEWED producer
must hand over; today no such producer exists as reviewed source.

## A. TLS-negative evidence: producer handoff into `negative_verdict.evaluate`

Evaluator inputs (current source, `negative_verdict.py`): `scenario` (closed set),
`logcat_text`, `nonce`, `run_id` (canonical string), `app_window{start,end}` (ints, common
monotonic clock), `capture{year,tz_offset_minutes,device_clock_offset_ms}`,
`expected_app{pid,uid}`, `build_record`, `premises`, `native_ledger`, `origin_ledger`,
`proxy_refusal`, `teardown_absence_verified`. The evaluator checks supplied records for
consistency only. It cannot authenticate any of them.

Handoff order each producer owes, and the proof each hand-off needs from its OWN trusted source:
1. Run owner (outer owner): issues `run_id` and `nonce` before anything starts, in a root-owned record.
2. Build producer: `build_record` incl. `embedded_anchor_sha256`, `proxy_upstream_trust_sha256`
   and the exact APK/source sha. Needs the reviewed source/stage lock. Unavailable today.
3. Certificate originals: canonical DER for trust anchor and presented chain, written by the
   proxy/origin setup, hashed into the run record before the app starts.
4. Ledgers: native listener and origin each write `{run_id,scenario,nonce,window_start,window_end,complete,count}`
   from the root side. Payload self-report is never accepted as ledger.
5. App window and `expected_app{pid,uid}`: observed by the root-side driver, not by the app.
6. Logcat capture plus the clock mapping measured by the driver at capture time.
7. Proxy refusal record `{run_id,scenario,nonce,upstream 127.0.0.1:18443,leaf sha256,reason,observed_at}`.
8. `teardown_absence_verified` from the independent namespace recovery check, only after the
   namespace is released.
Failure rule: any missing producer evidence means the scenario is NOT evaluated, never defaulted.
A synthetic record passes the predicate and proves nothing about a device.

## B. Outer-owner / cgroup lifetime obligations (interface contract, nothing proven)

A root-capable host must provide, each independently checkable by a recovery process:
- O1 Owner record: root-owned dir, mode 0700, holding `{attempt_id, owner_pid_identity, pidfd-able start time, namespace inode, cgroup path}` written atomically before any child starts.
- O2 Cgroup: a dedicated cgroup v2 leaf created by the owner with `memory.max`, `pids.max`, `cpu.max` set BEFORE the first member joins. Obligation: read back the three values and refuse to start if they differ. `cgroup.kill` is the termination primitive. Nothing outside the leaf may be signalled.
- O3 Lifetime: the owner holds the namespace fd and a cgroup dir fd for the whole attempt. Independent recovery after owner death stays strictly UNVERIFIED (no signals, no root mutation), as in the reviewed lifecycle contract. Only a live owner terminates.
- O4 Absence: after release, `cgroup.procs` is empty and `cgroup.events populated 0` read from the held dir fd, and the namespace member scan is empty. A bounded retry that ends unverified is reported as unverified.
- O5 Handles held by outsiders are blockers, never kill targets.
Not established anywhere yet: that any host delegates cgroup v2 controllers, allows PID namespaces, or provides /dev/kvm. `runner_capability_probe.py` only reads metadata.

## C. Benign real-root fault plan (plan only; needs a reviewed run, held)

A reviewed one-shot run on a root-capable host, with no SDK, no APK, no network, no model, only `sleep`-class payloads:
- F1 Capability check (real, not metadata): create the cgroup leaf and read back limits; try to unshare a PID namespace; record success or errno. Pass criterion: both succeed, else report the exact errno and stop.
- F2 Normal exit: owner starts a `sleep 1`, absence check per O4 reports verified.
- F3 Cancel: owner receives its cancel path while a `sleep 60` runs; leaf is killed via `cgroup.kill`; O4 absence verified.
- F4 SIGKILL of the owner: independent recovery must report UNVERIFIED and send no signals; the owner-held handles then let a second, authenticated owner-successor (if designed) or the runner teardown clean up. Pass criterion: recovery performs NO mutation and leaves a bounded diagnostic.
- F5 Fork-bomb bound: a payload that forks past `pids.max` is refused by the kernel, the leaf stays intact.
- F6 Memory bound: a payload exceeding `memory.max` is OOM-killed inside the leaf only.
- F7 Output: a closed schema of booleans/ints/errno only (see `audience_gate.validate_content` `capability_metadata`), written to a verified private destination, never to the public workflow log.
Each step records start, end, errno and result. It is one run, not repeated polling.

## D. Artifact audience and retention (interface)

Repository is PUBLIC. Logs, job summaries, artifacts, PR text and commits are public audiences.
`audience_gate.py` validates a supplied plan only (`validated_plan_only`), verifies a private
local directory at use time, and validates content by fixed schema. Retention is declared,
not enforced. A creator must also own expiry and deletion follow-through. Internal handoff to main
is not a publication and needs no new user permission; any public disclosure remains separate.

## E. Unresolved decision preserved for main (no interpretation made here)

Decision: whether, and on what legal basis, the Android SDK license may be treated as accepted for
(a) hash-only reading of the six archives and (b) later staging and use of the SDK packages to
build and run the owned fixture. No acceptance marker or agreement action exists or was created.
- Governing text for platforms;android-35, build-tools;35.0.0, platform-tools and the stable
  emulator 37.3.10: license id `android-sdk-license` in
  https://dl.google.com/android/repository/repository2-3.xml (the `license` element, 16,962 chars).
- The `android-sdk-preview-license` applies only to the dev-channel emulator 37.4.1, not used.
- The system image license ref in https://dl.google.com/android/repository/sys-img/android/sys-img2-3.xml
  was not separately read for this spec and is unverified.
- Temurin JDK: notice not retrieved; release sidecar and release metadata only.
- Scope needed for eventual use: the SDK components on a CI runner, for developing and testing the
  user's own Android fixture app, with outputs kept private.
