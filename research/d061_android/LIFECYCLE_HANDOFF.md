# HELD lifecycle correction: separate control and runtime boundaries

Status: proposed source design, not implemented or authorized execution.
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
A real reviewed closure still cannot be produced honestly because that driver
and complete transitive runtime staging are missing. Emulator option/listener
compatibility, guest proc access, independent collector/recovery/fault tests,
app TLS negatives and outer boundary closure also remain unresolved.

This document is a design correction, not a way around the runtime hold.

Source ceiling accounting: provisioning240s, fixed approval handoff wait30s and
approved operation+teardown+collection130s total400s. The proposed inner driver
wall timeout420s and trusted outer reaping/sanitation wall timeout480s are global
infrastructure ceilings, not extensions to the approved60s action. These values
are source proposals only; no timing/compatibility experiment has occurred.
