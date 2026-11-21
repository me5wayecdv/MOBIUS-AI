# D-061 Contained Capture: Design Research (rev3, for review, no execution)

Status: research for technical review. No launch, no applied firewall rules,
no network-namespace creation has happened or will happen before review
disposition. This revision withdraws premises an independent review found
unsound; the earlier ruleset sketches (rev1 in D061_CONTAINED_LAB_ASSESSMENT.md,
rev2 circulated in draft) are superseded and must not be implemented.

## 1. Scope trace: original objective vs later narrowing

- Original proposal (2026-10-15, v2 PDF, verbatim from its generated source
  transcript, stronger than repo history): mitmproxy is named for
  "Interception and inspection of app network traffic in the test
  environment", inside the dynamic analysis module (emulator/ADB, Frida).
  Intake scope control blocks dynamic tests outside the declared app and
  environment.
- Earlier task board (commit d3277c4b): T104 mitmproxy adapter with request
  replay, T105 VECTOR auth/TLS gates. No controlled-backend-only restriction.
- Narrowing: "controlled lab backend only" first appears in the demo replan
  (commit b1c89df4, 2026-11-15). No owner-sanctioned narrowing is
  established; repo history alone is not owner acceptance, so the proposal
  text above is the grounding.

Consequence: lab-backend success cannot close original scope. Original
capability still requires capture/replay against real target network
behavior, with TLS/auth boundaries resolved and the CA route verified.

## 2. Withdrawn premises (independent review findings, accepted)

1. Socket-cgroup classification is not universal isolation: nft_socket can
   fail to classify packets without a full associated socket, and with a
   policy-accept base chain such packets fail open. A target classifier plus
   policy accept is therefore not proof of containment.
2. Counter equality (total == permit + drop) proves only internal
   consistency of classified packets; packets the classifier missed are
   never counted. Counters cannot prove absence of egress.
3. The QEMU-only process assumption is unestablished: emulator networking
   helpers (for example netsim) may be separate or pre-existing processes
   with inherited sockets outside any fresh cgroup.
4. Broad `ct state established,related` permits are not endorsed: any
   control exception needs narrow loopback, known-listener,
   reply-direction semantics, and no `related` without justification.
5. (rev1 error) A global output policy-drop would sever non-target runner
   connectivity.

Safety must therefore come from topology (no route exists), not from
packet classification or counters. Counters and pcap remain evidence
accounting, never safety claims.

## 3. Research direction: no-uplink network namespace

Design under study (research only, not approved execution):

- One dedicated network namespace containing EVERYTHING the run needs:
  the emulator process and every helper it spawns (netsim included if
  present), the adb server, mitmproxy, the lab backend/mock origin, and
  tcpdump. Inside the namespace only loopback is brought up. No veth, no
  default route, no external interface of any kind.
- Structural containment: with no route to any non-local address, the
  namespace's own stack refuses egress ("network unreachable") regardless
  of socket type, protocol, address family, or process identity. Nothing
  depends on classifier correctness or counter completeness.
- Verification by inspection, not inference: `ip netns exec mobius ip route`
  and `ip -6 route` showing only loopback/link-local scope; host-side
  forwarding sysctls confirmed unchanged; no NAT rules added anywhere.
  These are complete, enumerable conditions.
- No cross-namespace control plane: the driver script orchestrates inside
  the namespace via `ip netns exec`; artifacts (pcap, logs, reports) leave
  through the shared filesystem, which a network namespace does not
  isolate.
- Process inventory still required, for evidence completeness rather than
  safety: pin the exact emulator build, enumerate all spawned helpers and
  their namespace membership before app launch and at capture end, and
  confirm no helper was pre-existing with inherited sockets (start every
  component fresh inside the namespace).

Open research items before any execution proposal:

1. Runner capability: probe showed passwordless sudo and cgroup2fs, but
   netns creation (CAP_NET_ADMIN under sudo) is NOT yet probed on the free
   runners. Listed as unprobed; would be a read-mostly capability check.
2. Emulator inventory: which helpers the pinned emulator build spawns
   (netsimd or successors), which can be disabled by flag, and which must
   be included. Source: AOSP netsim development guide and the pinned
   emulator version's own docs.
3. Emulator boot with zero upstream: whether boot completes with slirp
   unable to reach any resolver or host service (expected: yes, with
   guest networking degraded; to be demonstrated, not assumed).
4. adb-in-namespace flow: adb server and emulator co-located in the
   namespace; confirm no component expects a host-side adb server.

## 4. Traffic source and behavior caveats (unchanged, still binding)

- The pinned Allsafe APK hardcodes external endpoints (httpbin.io,
  infosecadventures.io, firebaseappcheck.googleapis.com; static evidence in
  PHANTOM_FEASIBILITY.md). Under any no-uplink containment it produces only
  denied-attempt evidence, never successful sessions or content.
- Containment changes target behavior (DNS failure, refusal, TLS fallback,
  pinning aborts); all capture under containment is contained-behavior
  evidence and must be reported as such.
- A purpose-built lab target is a substitute target and can never close the
  original objective for real targets.

## 5. Honest substitute-target route (exercises real capability)

Reviewer-endorsed framing: a controlled lab app built to explicitly trust a
Mobius test CA can honestly exercise the REAL mitmproxy capture, request
replay, and TLS/auth gate machinery (proxy configuration, certificate
presentation, capture format, replay) without system-CA modification and
without unconstrained external traffic. Inside the no-uplink namespace the
proxy's upstream is a loopback mock origin. All results remain labeled
substitute-target evidence; they demonstrate the T104/T105 machinery, not
real-target coverage.

## 6. Original capability: explicit decisions, none assumed

1. Third-party endpoint scope: original-scope capture of Allsafe's real
   traffic requires real egress to its hardcoded third-party endpoints.
   That is an owner/authority question (standing constraint: no unapproved
   third-party communication), not engineering.
2. CA route for real targets: user/system CA install changes the emulator
   image; Allsafe bundles okhttp CertificatePinner and its runtime pinning
   posture is unverified.
3. Pinning bypass conflicts with the standing constraint disabling
   state-changing PoC adapters; lifting it is a separate decision.
4. Request replay (T104) against real endpoints needs decision 1.

## 7. Honest D-061 state

- Original capability (mitmproxy interception/inspection of real target
  traffic, replay, TLS/auth gates against real targets): OPEN, gated on the
  decisions in section 6.
- Contained-lab mechanism: PREPARED at research level. cgroup-based
  filtering withdrawn; no-uplink namespace is the grounded direction,
  pending the open items in section 3.3 and technical review.
- Substitute-target machinery demonstration (mitmproxy capture/replay/TLS
  gates against a lab app trusting a test CA): available once the namespace
  design clears review; closes nothing original.
- Real-target deliverable available today: denied-attempt evidence only.

## 8. Evidence references

- Capability probe runs: 44875785657, 44876090990, 44876211141 (branch
  d061-capability-probe; read-only plus nft --check and transient cgroup
  creation; no applied ruleset, no target, no namespace).
- Proposal text: 2026-10-15 generation transcript (section 1).
- Task board commits: d3277c4b (T104/T105, unrestricted), b1c89df4
  (2026-11-15 narrowing).
- Reviewer sources (via main): Linux net/netfilter/nft_socket.c upstream
  (not runner-kernel matched), AOSP netsim development guide, nftables
  conntrack documentation, mitmproxy Android certificate documentation.
- Related: docs/D061_CONTAINED_LAB_ASSESSMENT.md (rev1, superseded),
  docs/PROJECT_CHECKPOINT.md.
