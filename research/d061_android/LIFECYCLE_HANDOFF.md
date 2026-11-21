# HELD lifecycle correction: separate control and runtime boundaries

Status: held source implementation candidate, never executed or activation-ready.
This corrects the earlier single-namespace product sequencing in
PROVISIONING_HANDOFF.md. That earlier design cannot satisfy its own absence gate:
an API process inside the runtime namespace keeps that namespace alive while
its adapter attempts to verify absence. Never mark it absent early.

## Required ordering

1. A trusted disposable supervisor creates a no-uplink control boundary for the
   ordinary product API/test driver. No model gateway, external account or
   production state is configured. Its DB/store are private disposable data.
2. A separately tracked nested PID/net/mount runtime child contains ALL Android
   emulator/QEMU/slirp, private ADB server/client, build tools, origin and proxy.
   It has only private loopback, no veth/uplink/default route or inherited host
   sockets. A child namespace is not a route to host-network ADB or services.
   Exact immutable runtime closure and KVM trust dependency still need review.
3. The runtime child provisions under the separate fixed ceiling: boot, owned
   CA/origin keys, native capture listener with zero originals/receipts, build
   actual owned APK. It exposes ONLY bounded public APK/public CA/build metadata
   to a private handoff. No app install/launch/action or positive/control request
   happens before the fresh product grant.
4. The control API uploads the actual APK and creates an explicit fixture-only
   source-backed hypothesis/case/authorization/approval. No Allsafe import,
   model call, real finding or owner-consent claim. The fixed plan binds APK,
   public CA digest, owned profile and exact60/60/10-second operation/cleanup/
   collection budgets. Existing stdlib grants never transfer.
5. The trusted host adapter delivers one bounded fixed control record to the
   runtime child. The child can read but not modify the control mount. A separate
   mutable result mount does not expose control files, host homes/sockets or keys.
   No argv/script/arbitrary URL/path input is accepted. Fresh committed authority
   is checked by product before launch and after returned host evidence.
6. The child installs the exact digest, creates only fixed reverse18080, prepares
   the app, observes package PID/UID/command, commits socket connection, records
   the live guest TCP tuple/UID/inode and releases that same app to send its one
   request. Native addon saves that original and replays its request once, with
   two independent backend receipts and four-way canonical comparison.
7. Stop producers and scope-clean app/reverse/emulator/ADB/proxy/origin/keys.
   Runtime PID1 exits, the trusted supervisor reaps it, and a read-only independent
   checker verifies stage-required records, net/mount/PID members and namespace
   handles, exact jail/private-material absence. Missing records remain unverified.
   Root-owned supervisor records stay outside the fixture-writable work mount.
8. Only after runtime teardown does the adapter return the original allowlisted
   evidence. Product validates/budgets/persists, fresh API readback rehashes it,
   and the report references the actual persisted run/plan/evidence. The separate
   control boundary can still exist here; runtime absence means runtime absence,
   never a false assertion that the active control API has disappeared.
9. The outer workflow independently closes/checks the control boundary as well,
   with bounded stage-aware recovery on failure/cancel/timeout. No retry is an
   implicit permission, and failed attempts stay failed.

## Source that exists versus source still missing

The typed owned_android_fixture product target/action/CA-input schema and
separate adapter are now prepared in product source, default host injection is
None. Old PoCTestPlan serialization has no new null field, preserving old plan
hashes. Failure/rejection persistence and readback use a distinct owned-android
link kind and do not describe failed attempts as proof no APK action happened.
Pure/static and failure-only API tests exercise these mechanics, not runtime.

The held namespace_supervisor.py is an INNER runtime candidate only. It does
not implement the outer control supervisor, immutable handoff mounts, approval
barrier or complete contained_driver. Do not dispatch it as a complete harness.
A reviewed closure still cannot be produced honestly because complete transitive
runtime staging, source lock review and actual pinned compatibility checks are missing. Emulator option/listener
compatibility, guest proc access, independent collector/recovery/fault tests,
app TLS negatives and outer boundary closure also remain unresolved.

This document is a design correction, not a way around the runtime hold.

Source ceiling accounting: provisioning240s, fixed approval handoff wait30s and
approved operation+teardown+collection130s total400s. The proposed inner driver
wall timeout420s and trusted outer reaping/sanitation wall timeout480s are global
infrastructure ceilings, not extensions to the approved60s action. These values
are source proposals only; no timing/compatibility experiment has occurred.

Pure source protocol checkpoint: handoff_protocol.py closes provisioning keys,
public byte/source digests, zero-preapproval-app/receipt counts, exact typed
commit, distinct phase ceilings and failure-terminal state transitions. It has
no launcher or file/network effects and cannot create an approval. Unit tests
exercise substitutions, extra keys, premature traffic and illegal ordering;
they do not supply the still-missing trusted root relay/control mounts.

## Sibling implementation candidate, all runtime gates FALSE

The reviewed direction is TWO SIBLING jails, not unprivileged nesting.
`sibling_supervisor.py` is the fixed trusted root owner. It launches one runtime
and one control wrapper, takes an immutable public APK/CA/build snapshot, binds
run+provisioning+runtime-closure+source identities in its own ExpectedContext,
consumes one typed commit, enforces its own monotonic phase deadlines, checks
runtime namespace/member/handle absence, then publishes fixed collected originals
read-only to control. Failure returns attributed failure diagnostics where the
control process can still persist them, never reconstructed capture/cleanup.

`namespace_supervisor.py` now has two closed roles and fixed closure roots:
only runtime gets KVM; control rejects Android-toolchain closure destinations.
Both inherit only stdio and see a root-owned read-only /control inbox plus their
own mutable /work. Root lifecycle records are outside both writable work trees.
After the PID namespace exits, the wrapper verifies members and namespace FDs
before fixed-path private-material sanitation and jail deletion. No generic
privileged request server, runtime-selected path/command or source activation is
implemented. Staged source and complete runtime/control closure locks are still
required inputs and do not exist as reviewed executable locks.

`contained_driver.py` supplies offline provisioning, original zero-state readback,
actual-source build/boot prerequisites, commit wait, observed app process/socket
release, captured-request replay wait and scoped teardown. It makes no stdlib
request to satisfy app capture. `control_driver.py` is an unprivileged product
API journey with fixture-only setup, fresh execute/readback/report and a one-shot
fixed relay host, no KVM/ADB/namespace privileges. `owned_collect.py` is the
post-runtime bounded allowlist/hash/absence collector. `handoff_io.py` rejects
links/oversize/overwrites and snapshots bytes, never shares runtime-writable
approved inputs. The state machine terminal-fails deadline/traffic/order errors;
61then60 and trafficthenzero cannot progress. Pure tests verify run reuse,
substitution and failure retention. No Android/native positive is fabricated.

Remaining before any activation review: exact transitive executable/loader/
library closures and safe staging/license decision; reviewed source activation
hashes; pinned binary option/listener/proc behavior; complete no-native fault
simulation for each privileged setup/relay/cleanup phase; runtime signal/cancel/
forced-timeout evidence; isolated app TLS negative controls; and independent
review of this entire source candidate. Source syntax/pure tests do not prove
any namespace, KVM, Java/APK build, TLS app action or runtime absence occurred.

## Consolidated61c5323 source review corrections

Root input acquisition/publication/removal now uses directory descriptors and
openat traversal, with O_DIRECTORY|O_NOFOLLOW on every ancestor and bounded
regular-file reads. Live payload directory renames cannot retarget root reads.
Tests swap an ancestor to an unrelated tree after its descriptor is opened and
verify only original bytes are read. Immutable public snapshot remains a second,
separate protection, not a substitute for safe source acquisition.

The outer workflow entrypoint is now held outer_owner.py. It writes an exact
external locator and root/relay launch intent before effects, records relay and
role identities, arms race-checked PDEATHSIG on outer->relay->wrapper->unshare,
and attempts exact identity/pidfd recovery. Role launch intent/count is durable
before Popen and updated after identity capture; missing expected identities
remain unverified. The independent outer recovery never overwrites missing
original wrapper cleanup with a fake success record. A trusted root-jail intent
exists before closure copy or namespace launch. Namespace/member/handle absence
precedes anchored private-material/jail recovery. Real kill/cancel proofs remain
held, not inferred from these source paths.

Collector output is staged in a private root-only directory. It cannot be seen
by control until commandRC, runtime absence, original validation, and the root's
remaining10s collection budget have been accepted. One atomic directory publish
exposes the already-staged terminal result only after those gates. An overrun
leaves the passed candidate private; later failure cannot race an already-passed
product row. Tests cover expired collection publication without native execution.

Root observed stage authorization is explicit before emulator boot and before
app commit. The independent inspector accepts only a closed root-owned expected
stage, marks truly unreached app/emulator obligations as not_reached, and leaves
missing expected records unverified. It never makes launch/ADB records to pass
a positive validator. A pre-emulator failure and an app-expected missing record
have distinct pure regression cases. Control final absence remains separate
outer completion after product persistence, not part of runtime proof.

## Read-only mounted public subtree permissions

Public inbox/snapshot/failure-result directories use anchored public_directory:
create0700 then explicit descriptor fchmod0755, retaining publisher ownership
and no payload write access under umask077. Public snapshot files stay0444.
Outer run root and private collector staging remain0700. Regression creates the
actual paths under real umask077 and checks resulting mode/traversal/read bits,
not only mkdir arguments. UID65534 jail execution itself remains untested.

Outer relay logging now uses the same bounded pipe pump64KiB ceiling as other
supervisors. outer_owner has a held --recover-only entrypoint using only the
external exact locator and identity-bound recovery. This is NOT an always-run
recovery service: no workflow/always-run invocation is registered, and an
outer-owner SIGKILL has no living code to invoke recovery by itself. External
workflow ownership and actual fault evidence remain required before activation.

## Always-run invocation preparation, still unregistered

Repeated recover calls now create unique per-attempt intent/result and per-role
absence records. A reused attempt ID refuses before effects; normal-owner
recovery and later unconditional recovery preserve every earlier record. Pure
regression invokes two attempts against the same synthetic already-absent
identities and verifies original cleanup bytes unchanged. No native/device work.

owned-siblings.yml is unregistered workflow SOURCE with manual-only event,
exact-SHA+FALSE gate before effects, fixed outer invocation and bounded always()
recover-only step. This is not an operational workflow: archive acquisition,
reviewed source/closure staging locks and allowlisted final artifact exporter
remain missing and the source explicitly refuses without them. No ambient SDK
fallback, runner-wide KVM permission changes or broad runtime-work upload.

stage_archives.py is held exact-member streaming materialization source for a
reviewed manifest, not dependency resolution or SDK license approval. It rejects
archive links/duplicate members, requires all materialized regular file hashes,
uses bounded streaming for the3GB system image and immutable root-owned outputs.
Its transitive runtime/control stage lock does not exist yet. No archive was
extracted, SDK installed, license accepted or downloaded binary executed here.

## Held source follow-up: real effect ordering and app-negative preparation

The recover-only attempt intent precedes the relay signal as well as role
cleanup. Missing launch identity remains unverified failure and does not prevent
independent cleanup of the other role. Mock-only tests cover this distinction;
no real SIGKILL, cancel or timeout experiment has been run.

Offline builder source accepts closed positive/untrusted-ca/wrong-hostname APK
scenarios. Positive remains the sole contained-driver/default-product case.
Untrusted-ca embeds a distinct canonical disposable public CA, never a user key.
Wrong-hostname retains fixed TCP/CONNECT loopback scope and HTTPS verification,
changes only the layered TLS peer name, and explicitly suppresses client SNI so
the interception proxy cannot simply issue a matching leaf for that peer name.
Actual pinned Android/proxy behavior remains untested. Build metadata identifies
the scenario, embedded CA and compiled Java; negative cases are rejected before
positive fixture API setup creates any objects, and by positive output checks.
App logs now delimit handshake begin/established with nonce/UID/PID. Those logs
alone cannot establish the reason for a TLS failure or verify zero backend traffic.
A separately reviewed negative runtime driver, presented certificate evidence,
independent raw native/receipt ledgers and teardown remain missing. No negative
scenario is added to an existing workflow or product execution path. No build or
app execution has occurred. Upstream untrusted-origin negative remains separate
unimplemented preparation, not silently covered by the app trust negative.

Archive staging now rehashes the same open root-owned nonwritable single-link
archive descriptor used to retrieve each member, not a later path-open assumed
to match a prior hash. This is deliberately conservative and may reread archives;
no speed claim or staging completion is made. Public intermediate directories use
explicit fchmod0755 under private umask077; incomplete role roots remain private.

## Scope-bound workflow and bounded staging session correction

The unregistered candidate's recovery step runs only after a trusted per-workflow
context step succeeds, following the held source/lock gates. That root-owned
one-shot context binds GitHub run ID, attempt, exact reviewed/source SHA and a
fresh context ID, before owner invocation. The outer locator carries that exact
context. Recover-only compares all of it before signaling/cleanup or root attempt
records. A stale/other-run locator refuses; existence alone triggers nothing.
A missing locator/launch identity stays unverified failure, not clean absence.
Mock-only main-entry regression confirms mismatched context has no effects.

Archive leaves open O_NONBLOCK|O_NOFOLLOW then refuse nonregular descriptors.
Actual synthetic FIFO tests exercise both source inspection and session paths,
with metadata ownership policy shimmed solely to reach the FIFO type checks.
Production staging retains one verified immutable container FD and archive
reader/index for the entire bounded session. Hash occurs once per container;
materialization checks descriptor identity again and streams exact reviewed
members. Per-role members process in archive-offset order and duplicate aliases
share one decompression stream, bounded to16 outputs. Whole session ceilings:
900 seconds,100000 materialized files,24GiB materialized bytes, independently of
bounded archive/member declarations. A synthetic three-alias test materializes
ONLY tiny unit bytes and checks actual0555/0755 modes underumask077 and byte
accounting. No Google/JDK/SDK archive is extracted or installed by these tests.

Static ELF metadata leads are now recorded for12 pinned archive members using
ELF headers as data, never ldd or loading/executing the object. Concrete leads:
d8/apksigner require/bin/bash and invoke shell utilities; emulator ELF requires
X11 and Qt/pulse-related libraries even though the launch intends no-window and
no-audio. Flags do not remove DT_NEEDED dependencies. These leads do not resolve
the transitive host/library/Python/JDK/plugin closure or binary compatibility.

## Remaining staging-limit qualification, held before use

ZIP metadata now has a classic-EOCD/central-directory preflight BEFORE ZipFile
allocation: at most50000 entries/32MiB directory per archive, fixed bounded name/
extra/comment lengths, exact counts/extents, no ZIP64/multidisk/encryption or
non-deflate variants. Aggregate session metadata caps100000 entries/64MiB are
reserved before constructor allocation. Synthetic oversized declarations refuse
before the ZipFile constructor is called. Read-only metadata preflight passed
for the five downloaded Google ZIPs; this does not extract/install SDK content.

The900s checks remain COOPERATIVE, not a hard timeout while Python indexing,
decompression, filesystem reads/writes or fsync is blocked. Metadata byte caps
are not a Python allocator/RSS guarantee; TAR/PAX reader allocation also needs
outer constraints. Actual staging still requires a trusted outer watchdog and
hard process/memory/CPU/file limits with independently attributable partial-stage
cleanup. HARD_WATCHDOG_AND_RESOURCE_LIMITS_REVIEWED remains FALSE and is a
separate main/workflow source gate. Those mechanisms are not implemented here;
no staging readiness or hard-ceiling claim is made. Retained session readers fix
repeated per-member hashing, not all sources of stalled/unbounded runtime.

## Staging watchdog (held, source only)
`staging_watchdog.py` supervises `stage_archives.py`. One-shot pre-effect gates: the lock bytes must hash to the
reviewed lock identity, and every role root and the report path must NOT preexist (never adopted, never
quarantined). A durable private intent record is written before any effect, then a progress record with the
child's (pid, start-ticks, sid). The child gets its own session, CPU/file-size/NOFILE/address-space/core rlimits and
a checked PDEATHSIG SIGKILL. All post-Popen setup is inside the cleanup guard. Processes are stopped by signalling
each live member of the recorded session through its own pidfd after identity re-verification (no numeric kill),
verifying absence with a /proc scan, and reaping the leader with a bounded wait. Root mutation (rename to a private
`.failed-<attempt>`, never delete) happens only after absence is verified; otherwise the record says
`UNVERIFIED_ABSENCE_NO_ROOT_MUTATION`. Every ancestor in every traversal, record write and quarantine is opened
component by component with O_NOFOLLOW. After ANY exit, including exit 0, a deadline-bounded final validation
checks the report content, each role's closure-lock content, the exact reviewed file set (no extras) and every
file's size, mode and SHA-256 against the reviewed lock; a regular but invalid lock is quarantined too.
`recover()` is the independent attributable recovery for a dead watchdog with a unique record.

Honest limits: size scans are polling, not a disk quota; containment is the session plus pidfd signalling, so a
process that calls setsid escapes it and production still needs a PID namespace or cgroup; RLIMIT_NPROC is per-UID
and not claimed; tests use benign stager stand-ins and tmp directories as source evidence only, not real SDK
staging, a root-owned run, kernel limit enforcement or the real fault chain. `APPROVED_FOR_EXECUTION` is FALSE.

## Exporter status trust
Export obligations come from the root-published `control-in/result/result.json` status, never from the payload's
own control-result before absence. The staged control, execute and DB statuses must agree with it; unknown or
disagreeing status is an error. `complete_diagnostic_export` and `complete_product_evidence` are distinct.
