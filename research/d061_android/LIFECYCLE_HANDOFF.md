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
