# D-061 second infrastructure preflight, evidence and offline comparison

Run: https://github.com/me5wayecdv/MOBIUS-AI/actions/runs/44880833440
Artifact: https://github.com/me5wayecdv/MOBIUS-AI/actions/runs/44880833440/artifacts/14698240485
SHA: f19c11533509bd0d6596a4b6e794c73218006dc3, reviewed PR114.

The run remains FAILED. It was one separately reviewed attempt, not an
unbounded retry. Unlike the first attempt, the actual evidence archive exists
and was downloaded and inspected. No third infrastructure run was made.

## What the retained evidence establishes

- Workload log contains the IPv4 loopback success marker. Original errors are
  empty. The small unprivileged Python workload's namespace identity,
  capability and no-new-privileges checks completed.
- Phase/ownership evidence identifies a fresh created/journaled namespace.
  Before/after inventories show only loopback, IPv4 loopback and ::1, local
  routes and standard policy rules. Both documentation-address route lookups
  are unreachable. IPv6 roundtrip was NOT tested.
- Final PID list is empty, namespace delete exits zero, and the executed
  final name check reported no error. A separate persisted name-absence field
  did not exist in this run; the candidate fix adds it for future evidence,
  not retroactively to this archive.
- Collector summary has no errors, and upload succeeded. This actually
  establishes root-created evidence collection for this run, not merely a
  permissions theory. No original traceback file exists because no original
  workload exception occurred.

## Why the run failed

The retained raw and normalized host snapshots show one differing field:
iptables security OUTPUT chain packet/byte counters increased. The comparator
normalized nft-style counters but missed iptables-save bracket counters. Both
main and independent cleanup therefore returned failure on host comparison.
All other normalized snapshot fields compare equal.

The narrow fix normalizes bracket counters only on complete iptables chain
header lines, preserving chain name, policy and all rule contents. Offline
comparison of the actual retained raw before/after snapshots now yields equal
configuration. A deliberate policy mutation remains detected. Regressions also
check chain, table, destination, action, added-rule and opaque-bracket changes.
This is offline comparator validation, NOT a new runtime pass and never a
rewrite of the failed run result.

## Next useful bounded preparation, not launch

Use offline unit tests and recorded protocol structures to define the smallest
real capture/replay/TLS fixture contract before acquiring tools or launching an
emulator: a unique investigation nonce; one GET captured by a real proxy;
replay built from that captured flow; exactly one additional backend receipt;
distinct positive trust, untrusted CA, wrong hostname and upstream TLS checks;
separate target authorizations for distinct APKs; digest-bound investigation
evidence for flow/receipt/CA-fingerprint metadata and report references. Tests
must reject forged receipt-only evidence and distinguish request replay from
response replay. These tests can define acceptance and fail-closed behavior
without claiming an implemented proxy or requiring new dependencies.

The full target/helper/FD/broker boundary still needs an exact reviewed design.
Toolchain dependencies remain held. No emulator, APK, proxy, capture, model call
or external target contact occurred in this infrastructure work. The held draft
full harness does not become safe merely because a loopback infrastructure
workload ran. No Allsafe/arbitrary-app claim or whole-project completion.

SIGKILL/runner-loss and the creation-to-journal window remain limits; never adopt
or delete an unverified namespace by prefix. Runtime work stays held pending
technical disposition. No third preflight is needed solely for a green badge.
