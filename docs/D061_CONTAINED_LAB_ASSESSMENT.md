# D-061 Contained-Lab Traffic Capture: Capability Assessment

Status: assessment and design only. The original D-061 objective (verified traffic
capture against a controlled backend) remains NOT established. No capture was
executed. This document records what a bounded, read-mostly probe established
about runner capability, the design it supports, its remaining limits, and the
exact unresolved decision.

## Prior containment critiques (why earlier attempts stopped)

1. One failed public ping (ICMP) is not proof of all-protocol containment.
2. IPv4 iptables rules do not cover IPv6, which is present and enabled on the
   runners (verified: `disable_ipv6=0`, link-local on eth0).
3. Host-alias allowance may reach host services and proxies.
4. `/proc/net/tcp` socket metadata is evidence of attempts, not proof that zero
   bytes left the target.
5. Applying firewall rules does not itself establish containment; established
   flows, DNS and host aliases can leave routes.

## Probe evidence (read-only plus minimal capability checks, no target launch, no applied firewall rules)

Branch `d061-capability-probe`, workflow `d061-capability-probe.yml`:

- Run 44875785657 (green): kernel 7.0.0-1020-azure, Ubuntu 26.04.1, nftables
  v1.1.6, iptables 1.8.11 (nf_tables), cgroup2fs mounted, passwordless sudo,
  IPv6 present and enabled, `nft_socket.ko` and `xt_cgroup.ko` present in the
  running kernel's module tree.
- Run 44876090990 (green): `nft --check` on an inet-family ruleset failed only
  because the referenced cgroup path did not exist yet ("cgroupv2 path fails:
  No such file or directory"); `modprobe nft_socket` succeeded. An unsupported
  match would have failed at match parsing, not at path resolution.
- Run 44876211141 (green): after `mkdir /sys/fs/cgroup/probe.slice` (created
  and removed in the same job, no persistent change), `nft --check` validated
  the full ruleset: inet family, output hook, `policy drop`, and
  `socket cgroupv2 level 1 "probe.slice"` rules permitting only
  `127.0.0.1:9999` and `[::1]:9999`. Result: NFT_CHECK3_OK.

Conclusion: the runner supports cgroup-v2-scoped nftables matching in the inet
family. The capability the earlier critiques said was unproven (one ruleset
covering both address families, bound to the target process, fail-closed) is
available on the free route.

## Design: structural containment via cgroup-scoped default-drop

1. Create a dedicated cgroup (for example `mobius-lab.slice`).
2. Start the Android emulator process inside that cgroup from the beginning.
   The kernel does not reclassify existing sockets when a task moves cgroups
   (documented behaviour; see references), so the process must be launched in
   the cgroup, never moved later. Verify `/proc/<pid>/cgroup` before any app
   install or launch; fail closed on mismatch.
3. Install one inet-family nftables table: output hook, `policy drop`, scoped
   to the cgroup, with a single accept for the controlled lab backend on host
   loopback (127.0.0.1:<port>, [::1]:<port>). Every rule carries counters.
4. The Android emulator uses user-mode (slirp) networking by default: all guest
   egress goes through the QEMU process's host sockets, which the cgroup-scoped
   ruleset binds. The guest has no other network path.
5. Run the lab backend on the runner's loopback. No external endpoint exists in
   this design; DNS or any other egress attempt is dropped structurally.
6. Capture at the backend. At teardown: `nft list ruleset` (record the active
   ruleset), reconcile counters so every packet on the chain is accounted for
   by an accept or the drop counter, then remove the table and cgroup.

How each prior critique is addressed:

- All-protocol: the output hook sees every protocol, not just ICMP.
- IPv6: the inet family covers IPv4 and IPv6 in one verified ruleset; IPv6
  presence on the runner was confirmed, so the ruleset was checked against it.
- Host-alias: guest-to-host traffic leaves via the QEMU process; the
  default-drop cgroup ruleset permits only the lab loopback port, so other host
  services and proxies are unreachable structurally rather than by test.
- Byte accounting: teardown counter reconciliation replaces socket-metadata
  inference; every packet on the cgroup's output path matches an accept rule or
  the drop policy counter.

## Remaining limits (stated plainly)

- `nft --check` proves the kernel accepts the ruleset; it is not proof that a
  live ruleset bound every byte in a real run. That proof exists only at
  execution time via ruleset listing, `/proc/<pid>/cgroup` verification before
  app launch, and counter reconciliation at teardown.
- The emulator's boot-time egress attempts (NTP, DNS, Play services checks)
  will be dropped; whether boot completes reliably under a full default-drop
  has not been tested and is part of what the execution run would answer.
- This assessment does not establish D-061. It establishes that a supported
  route plausibly exists on the free runners, within free-only constraints,
  with no owner-host access, no production activation, and no third-party
  endpoints.

## Unresolved decision

Execute or decline one bounded contained-lab run: emulator launched inside a
dedicated cgroup, inet-family default-drop output ruleset permitting only the
loopback lab backend, capture at the backend, teardown counter reconciliation,
results recorded against D-061. Until that decision is made, D-061 stays NOT
established and the capture path stays stopped.

## References

- Probe runs: 44875785657, 44876090990, 44876211141 (branch
  d061-capability-probe).
- Oracle Linux blog, "When cgroup v2 meets nftables": kernel does not migrate
  sockets with a task moved to a new cgroup; ruleset examples using
  `socket cgroupv2 level N`.
- QEMU documentation, network emulation: user-mode (slirp) networking routes
  guest traffic through the QEMU process.
- nftables wiki: inet family matches both IPv4 and IPv6; `socket cgroupv2`
  expression.
