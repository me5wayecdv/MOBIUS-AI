# D-061 capture preparation checkpoint

Status: draft research and preparation only. No namespace, firewall ruleset,
emulator, proxy or fixture has been launched by this preparation. No capture,
replay or TLS-gate capability has been verified. PR #112 must not be merged
or used for execution until technical review.

## Scope and authorship

The October 15 proposal describes mitmproxy interception and inspection of
app traffic. It is assistant-authored proposed content, not evidence that
the owner accepted every detail. Earlier task-board entries T104/T105 name
capture/replay and TLS/auth gates; the November 15 demo replan later adds a
controlled-backend restriction. Repository text does not establish owner
acceptance or authorize narrowing the deliverable.

A controlled fixture can prove named machinery using real mitmproxy capture,
safe GET replay and TLS trust checks. That evidence must be labeled fixture
or substitute-target evidence. It cannot establish Allsafe compatibility,
arbitrary-app interception, pinning bypass or broad detection coverage.
Conversely, the proposal alone cannot create a mandatory third-party-egress,
system-CA or Allsafe requirement. Final acceptance remains to be reconciled
against the owner's authenticated project instructions.

## Earlier assessment withdrawn

D061_CONTAINED_LAB_ASSESSMENT.md records capability probes, not containment
proof. Its cgroup-filtering design is superseded and must not be executed:

- A global output drop would break unrelated runner connectivity.
- Socket-cgroup matching can miss unclassifiable packets. Policy accept then
  fails open. Upstream kernel source is not a runner-kernel proof.
- Classifier-scoped counters show internal consistency only, not missed egress.
- QEMU-only networking was not established. Helpers and inherited sockets
  matter. Broad established/related allowances were not justified.

Probe runs 44875785657, 44876090990 and 44876211141 establish only observed
runner properties and nft check-mode acceptance. No target was launched in
those probes. Neither socket metadata nor rule acceptance proves isolation.

## Candidate topology

Research direction: a fresh no-uplink network namespace with loopback only,
containing a fresh emulator, all networking helpers, internal adb, proxy and
mock origin. No veth/uplink, host proxy or cross-namespace control connection.
Artifact files can be collected separately.

Threat model: trusted-lab accidental-egress containment, not hostile host-code
isolation. Membership and runtime hygiene are safety-relevant. A network
namespace does not close inherited sockets or block filesystem broker sockets.
The full harness therefore needs reviewed FD closure, private runtime/HOME/AVD,
proxy-environment removal, broker-path isolation and unprivileged execution.
All links, addresses, all route tables, policy rules, namespace memberships,
processes/helpers and sockets need checked inventories before app launch.
Versions and hashes must be pinned and recorded. Cleanup must stop helpers
before final inventory and removal. No universal-byte assurance is claimed.

## Exact infrastructure-only candidate

`scripts/d061/infra_netns_check.py` is a standalone candidate for exact-script
review. It is separate from the draft emulator scripts and requires an explicit
review-authorized flag. No one has executed it.

It proposes: root orchestration of one fresh named network namespace, loopback
only, JSON topology inventories, route lookups for documentation addresses
without sending packets, then a fresh isolated Python process as `nobody` with
no capabilities and no-new-privileges, no inherited environment/network FDs,
and a bounded loopback-only roundtrip. It proposes bounded cleanup and strict
host-topology-before/after comparison. No emulator/proxy/app or package install.

A pass would establish only that small infrastructure test. It would not
clear the full harness or establish broker-path isolation for emulator tooling.
Review must settle the exact candidate before even this check is run.

## Full fixture harness: incomplete draft, disabled

The shell entry points are disabled. The workflow is stored as a `.disabled`
draft outside `.github/workflows`, so no dispatch or automatic execution exists.
The proposed adapter is under scripts/d061/draft, NOT wired into product code.

Prepared draft parts: dependency-manifest candidate, staging script, emulator
launcher sketch, mock TLS backend/receipt ledger, fixture APK source with trust
flavors, product-API journey sketch and adapter sketch. They are NOT runnable
or accepted merely because the files exist. Known unresolved defects include:

- Shell inventory functions mostly record instead of enforcing complete expected
  state; inherited-FD closure and broker-path isolation are not implemented.
- Exact pinned emulator helper inventory is absent. Actual component versions
  are printed, not yet asserted against an approved runtime manifest.
- Working-directory/Python-environment propagation, SDK archive layout and
  mitmproxy hostname routing need source-backed correction.
- Unprivileged tcpdump has no reviewed capture privilege design. Evidence must
  be stopped/flushed before hashing and verified, not counted while live.
- Wrong-hostname control currently conflates chain rejection with hostname
  rejection. It needs a chain trusted for that control but wrong SAN, with
  independently verified rejection reason. Positive response JSON parsing
  must replace a brittle whitespace-sensitive string check.
- Replay currently reissues a known URL, not a captured request. Use the actual
  captured safe GET and prove a second backend receipt of its fresh run nonce.
- The second fixture package is not covered by the current primary-APK plan.
  Give each target its own correct product authorization and execution record.
- Product schema/allowlist/action integration and approval rejection tests are
  not implemented. No bypass or expanded read-only classification is allowed.
- New toolchain dependencies are proposed, not installed or approved. Gradle,
  AGP, Android build-tools/platform, mitmproxy and tcpdump need disposition.
  Transitive downloads are not fully locked; a freeze after resolution is not
  a reproducible dependency lock. No dependency license is accepted here.
- Runtime bounds and cleanup error propagation need review; a comment is not
  a timeout or an enforced safety gate.

Fixture trust must preserve normal hostname validation, reject an untrusted CA
and wrong hostname for the intended reasons, and keep upstream TLS verification
on. Safe GET request replay means a second origin receipt, not response replay.
A purpose-built fixture trusting a test CA needs no system-CA change or arbitrary
pinning bypass. Containment can change app behavior; results must say so.

## Verification performed

Only static syntax checks and the unchanged baseline Python suite were run.
Baseline: 968 passed, 20 skipped. This does not verify the new drafts, emulator
build, namespace capability, APK build or capture path. No model call or retry.

## Continuation

1. Review the standalone infrastructure candidate exactly as committed.
2. Fix the full-harness defects above without launching it or adding dependencies.
3. Submit the corrected exact harness for safety and scope review.
4. Only after disposition, run the authorized bounded slice and preserve real
   evidence. Until then D-061 remains unverified, neither optional nor complete.

### Infrastructure candidate correction after exact-script review

The infrastructure-only Python candidate now has controlled SIGTERM/SIGHUP/
SIGINT failure handling, protected finite cleanup, separate guarded process
inventory/kill/poll/delete/absence/snapshot/report steps and retained original
plus cleanup errors. A failed process cleanup remains failure after name removal.
It uses a UUID namespace, refuses existing names and journals successful creation
plus the namespace inode; cleanup requires matching identity and never adopts a
pre-existing or journal-less name. Optimization is rejected before safety checks.
Raw host evidence is kept; comparison removes only declared address/route expiry
metadata and firewall packet/byte counts, leaving unknown differences as failures.
IPv4 loopback is the proposed exercised path; IPv6 is inspection only.

An independent always-run CI cleanup candidate is stored at
scripts/d061/draft/infra-only-ci.yml.disabled, outside active workflows. It uses
only the successful-create journal from that job, bounded timeouts, identity
checks and no prefix-based deletion. SIGKILL or runner loss may prevent cleanup;
the create-to-journal SIGKILL window cannot be safely auto-adopted and must fail
with evidence missing rather than delete an unverified namespace. No cleanup
claim can survive absent/incomplete process and final-name evidence.

Only parsing and a local normalization unit check have run on this correction.
No namespace, socket roundtrip, host snapshot or cleanup operation has run.
