# Held interface specification (not executed, not wired, no producer evidence)

Status: specification only. No behaviour here has run. Nothing in this file clears an
execution, legal or audience hold. Records below are the shapes a REVIEWED producer
must hand over; today no such producer exists as reviewed source.

## A. TLS-negative evidence: producer handoff into `negative_verdict.evaluate`

Authority note: the bullets below SUMMARISE the evaluator. `negative_verdict.py` is authoritative for every constraint (exact non-negative int types, not bool;
same run/scenario/nonce binding; zero request ledger counts; certificate profile, peer name and reason sets; teardown exactly True).

Clock domains. Evaluator timestamps (`app_window`, ledger windows, `proxy_refusal.observed_at`, and the
certificate validity check) are HOST UNIX EPOCH MILLISECONDS. Logcat calendar fields are converted to that
domain by `capture`. Monotonic time is used only for supervision deadlines, never in evaluator records.

Exact current closed schemas (copied from `negative_verdict.py`):
- `scenario`: one of `untrusted-ca`, `wrong-hostname`, `untrusted-origin`.
- `nonce`: 32 lowercase hex. `run_id`: `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, typed str.
- `capture`: exactly `{year, tz_offset_minutes, device_clock_offset_ms}`, all int; year 2000..2100; |tz|<=840; |offset|<=2000.
- `expected_app`: exactly `{pid, uid}`, ints, observed independently.
- `app_window`: exactly `{start, end}`, ints, start<end.
- `build_record`: exactly `{run_id, scenario, apk_sha256, installed_apk_sha256, embedded_anchor_sha256, proxy_upstream_trust_sha256}`;
  run_id and scenario equal the run; apk_sha256 == installed_apk_sha256; all hashes 64 lowercase hex. The source/stage lock
  binding lives in a SEPARATE producer manifest, not in this record.
- `premises`: `untrusted-ca` and `untrusted-origin`: exactly `{trust_anchor_der, presented_chain_der}`;
  `wrong-hostname`: exactly `{trust_anchor_der, presented_chain_der, peer_name}`. Canonical DER, pinned fixture profile at `app_window.start`.
- `native_ledger`, `origin_ledger`: exactly `{run_id, scenario, nonce, window_start, window_end, complete, count}`; complete True; window covers the app window.
- `proxy_refusal` (required for `untrusted-origin`): exactly `{run_id, scenario, nonce, upstream, upstream_leaf_sha256, reason, observed_at, count}`;
  upstream is the fixed 127.0.0.1:18443; leaf sha256 equals the presented leaf DER; observed_at inside the app window; count >= 1.
- `teardown_absence_verified`: supplied by the independent namespace recovery check.

Handoff order each producer owes, each from its OWN trusted source:
1. Run owner issues `run_id` and `nonce` in a root-owned record before anything starts.
2. Build producer supplies `build_record` (needs the reviewed source/stage lock; unavailable today).
3. Certificate originals (DER) are written by the proxy/origin setup and hashed into the run record before the app starts.
4. Both ledgers are written root-side. Payload self-report is never a ledger.
5. The app window and `expected_app` are observed by the root-side driver.
6. Logcat capture plus the clock mapping measured by the driver.
7. The proxy refusal record (untrusted-origin only).
8. `teardown_absence_verified` only after the namespace is released.
A missing producer means the scenario is NOT evaluated. A synthetic record passes the predicate and proves nothing about a device.

## B. Outer-owner / cgroup lifetime obligations (interface contract, nothing proven)

A root-capable host must provide, each independently checkable by a recovery process:
- O1 Owner record: root-owned dir, mode 0700, holding `{attempt_id, owner_pid_identity, pidfd-able start time, namespace inode, cgroup path}` written atomically before any child starts.
- O2 Cgroup: a dedicated cgroup v2 leaf created by the owner with `memory.max`, `pids.max`, `cpu.max` set BEFORE the first member joins. Obligation: read back the three values and refuse to start if they differ. `cgroup.kill` is the termination primitive. Nothing outside the leaf may be signalled.
- O3 Lifetime: the owner holds the namespace fd and a cgroup dir fd for the whole attempt. Independent recovery after owner death stays strictly UNVERIFIED (no signals, no root mutation), as in the reviewed lifecycle contract. Only a live owner terminates.
- O4 Absence: after release, `cgroup.procs` is empty and `cgroup.events populated 0` read from the held dir fd, and the namespace member scan is empty. A bounded retry that ends unverified is reported as unverified.
- O5 Handles held by outsiders are blockers, never kill targets.
Not established anywhere yet: that any host delegates cgroup v2 controllers, allows PID namespaces, or provides /dev/kvm. `runner_capability_probe.py` only reads metadata.

## C. Benign real-root fault plan (plan only; needs a reviewed run, held)

Phase 1, benign lifecycle on a root-capable host. No SDK, APK, network or model; `sleep`-class payloads only:
- F1 Capability check (real, not metadata): create the cgroup leaf and read back limits; unshare a PID namespace. Pass: both succeed, else the errno and stop.
- F2 Normal exit: owner starts `sleep 1`; absence per O4 verified.
- F3 Cancel: owner takes its cancel path while `sleep 60` runs; leaf killed via `cgroup.kill`; O4 absence verified.
- F4 Owner SIGKILL. Owner-held fds close when the owner dies, so they give NO cleanup assurance afterwards. Independent recovery stays UNVERIFIED with no signals and no root mutation.
  Cleanup is an unresolved external obligation: a reviewed, bounded, independent host-teardown path and a named evidence owner (for example the runner VM teardown or a separately reviewed supervisor). F4 must NOT start until that path is designed and reviewed. A successor that is not yet designed is not cleanup assurance.
Phase 2, pressure cases, held separately and only after phase 1 is proven:
- F5 pids bound and F6 memory bound. Each has a finite child and byte ceiling, an outer watchdog with a deadline, and cleanup evidence. They are not sleep-only.
Output for every step is the closed `fault_result` schema in `audience_gate.validate_content`: `{step in F1..F6, ok bool, errno 0..4095, start_epoch_ms, end_epoch_ms}`.
No free text. Diagnostics beyond this need a new reviewed closed schema. Written only to a verified private destination, never the public workflow log. One run, no polling.

## D. Artifact audience and retention (interface)

Repository is PUBLIC. Logs, job summaries, artifacts, PR text and commits are public audiences.
`audience_gate.py` validates a supplied plan only (`validated_plan_only`), through the single seam `publish_private` binds plan to destination directory and typed content to the write, serializes internally, writes `<name>.part`
then renames, and unlinks a partial on failure (existence of the final name marks completion; route_evidence_ref stays a label); and validates content SHAPE by fixed schema.
Shape is not redaction: inventories keep package member paths and link targets, so they are valid only for exact
pinned official containers and private reporting. `provenance_note` is a fixed constant. Retention is declared,
not enforced. A creator must also own expiry and deletion follow-through. Internal handoff to main
is not a publication and needs no new user permission; any public disclosure remains separate.

## E. Unresolved decision preserved for main (no interpretation made here)

Decision: whether, and on what legal basis, the Android SDK license may be treated as accepted for
(a) hash-only reading of the six archives and (b) later staging and use of the SDK packages to build and run the owned fixture.
No acceptance marker or agreement action exists or was created.
- `android-sdk-license` element in https://dl.google.com/android/repository/repository2-3.xml covers platforms;android-35, build-tools;35.0.0,
  platform-tools and the stable emulator 37.3.10.
- The system image `system-images;android-29;default;x86_64` r8 (`x86_64-29_r08-linux.zip`) also uses license ref `android-sdk-license` in
  https://dl.google.com/android/repository/sys-img/android/sys-img2-3.xml. Per the reviewer, that referenced element is dated 2019-01-16;
  its section 2.1 requires agreement before SDK use, 2.2 describes click acceptance, and 3.5 gives open-source components their own licenses.
  Do not substitute another currently served terms version for this metadata's actual text.
- `android-sdk-preview-license` applies only to the dev-channel emulator 37.4.1, which is not used.
- Temurin JDK 17.0.21.1+2: release-linked build NOTICE.template at commit 8d9fd6fa96e5066571a13823b07c2934e5958d8b declares GPL-2.0 WITH
  Classpath-exception-2.0 and points Java 9+ users to the installed `legal/` directory. Sources:
  https://api.github.com/repos/adoptium/temurin17-binaries/releases/tags/jdk-17.0.21.1%2B2 and
  https://raw.githubusercontent.com/adoptium/temurin-build/8d9fd6fa96e5066571a13823b07c2934e5958d8b/sbin/NOTICE.template.
  LIMIT: this is build-source notice, NOT the notices packaged inside the exact binary, which remain unread.
- None of this is a legal determination. Scope for eventual use: the SDK on a CI runner, to build and test the user's own fixture, private outputs.

## F. Smallest benign host-primitive run (proposal; never run; source `host_primitive_probe.py`, held)

One shot on a disposable root-capable Linux host: F1 plus one natural F2 only. No SDK/JDK, APK, archive member reads, model, network, KVM VM,
pressure, cancel injection or owner SIGKILL.

Source contract (unit-tested only through an injected fake; the real primitives are untested because no root cgroup host exists in the sandbox):
- Controllers `pids memory cpu` must ALREADY be enabled in the parent `cgroup.subtree_control`. The probe never edits the parent; absence is an errno result.
- It creates one unique exclusive leaf `mobius-probe-<run_id>`, writes `pids.max=16`, `memory.max=64 MiB`, `cpu.max=20000 100000`, and reads each back. No member
  joins before every readback matches.
- A gated child (stdin pipe) is spawned outside the leaf, joined into the exact leaf via `cgroup.procs`, verified through `/proc/<pid>/cgroup`, and only then released.
  It then calls `unshare(CLONE_NEWPID)` and reports 0 or its own errno. A grandchild executes `sleep 1` through a pinned, sha256-checked executable fd. Parent waits under a 10 s
  monotonic deadline.
- Cleanup (live parent only): `cgroup.kill` on the held leaf (else pidfd kill of the held direct child), bounded reap, `cgroup.procs` empty, `cgroup.events populated 0`, `rmdir` of its
  own empty leaf. No broad process discovery or numeric-PID signals.
- Result is the closed `host_primitive_result` record: fixed envelope `{run_id, source_commit (40-hex git commit), sleep_sha256 (64-hex), probe}` plus four separate results
  `limit_readback, pidns_create, child_exit, cleanup_absence` each `{check, ok, errno}`. `pidns_create` has the NARROW meaning carried in the envelope as `pidns_claim`: the child's `unshare(CLONE_NEWPID)` returned 0 and the parent saw the child's `pid_for_children` namespace id differ from its own. No PID1 membership or namespace-wide absence is claimed. A denial or later-skipped check is `ok False`. A pass
  means only those observed primitives plus bounded normal-exit cleanup. It is never full containment, KVM function, SDK closure, app traffic or owner-death safety.
- Output goes only through `audience_gate.publish_private` to a verified private destination. Nothing is printed, uploaded or logged.

Preconditions NOT satisfied and not designed here (each is main's decision, not mine):
1. A named independent disposable-host teardown/evidence owner for parent death. One candidate for main to consider is destruction of the GitHub-hosted runner VM at
   job end, with the cgroup leaf and processes dying with it. I have NOT verified that this teardown is observable or sufficient as evidence, so it is a proposal, not a design.
2. An authorized no-spend route and a workflow to run it (workflow registration/dispatch are held; the repository is public so logs are public).
3. Retention and deletion ownership for the private output.
