# Mobius project checkpoint, 2026-11-21 10:11 EET

This checkpoint supersedes the earlier 20627843 snapshot. It records evidence
limits, not whole-project completion. Merged main inspected at
`9f8ede5c6e08efae4c94d76becdaec2de9181558`. PR117 merged after all5 normal
checks green at exactaa5f7ae. One separately reviewed local positive experiment
passed. It is not product integration or fullD061 acceptance.

## Landed work versus demonstrated work

| Work | Merged state | Demonstration boundary |
| --- | --- | --- |
| Observation-only PHANTOM/Frida (#106), lifecycle (#107) | 93aa0b7, e4bc956 | Prior target-scoped class observation/lifecycle evidence, not capture/TLS or general app coverage |
| D061 not-established docs (#109) | 043aff6 | Explicit gap, not optional completion |
| Connected journey plus hypothesis-ID serializer fix (#110) | 20627843 | Model-positive run reached report but failed projection; serializer fix unit-tested, no positive-model E2E re-verification |
| Infrastructure-only diagnostic/evidence corrections (#113,#114) | 4d7d2f60, f19c1153 | Two failed infrastructure runs, partial evidence described below |
| Narrow chain-counter comparator and evidence persistence correction (#115) | d712b86a | Approved source branch had five normal checks green; offline actual snapshots compare equal; original run still FAILED |
| PROPOSED offline evidence contract (#116) | 4f3f8576 | Six synthetic unit tests/25 subtests define structural consistency only, no capture/replay/TLS runtime proof |

The42-wheel native proxy closure plus hashed pip bootstrap and separately
reviewed activation merged in https://github.com/me5wayecdv/MOBIUS-AI/pull/117 .
One positive local experiment at9f8ede5 passed, with original source gates FALSE
and runtime copies activated through the exact orchestrator. See
`docs/D061_NATIVE_POSITIVE_RESULT.md` for provenance, actual evidence and limits.

## Connected journey, still incomplete at the original acceptance bar

- Model-positive round1:
  https://github.com/me5wayecdv/MOBIUS-AI/actions/runs/44865900582 . GitHub result
  remains failure. Five hypotheses reached approval, dynamic observation and
  report stages, but run-to-model-hypothesis projection failed because the
  serializer omitted hypothesis IDs. The later fix does not retroactively pass
  that run.
- Subsequent model samples returned zero hypotheses twice at unchanged route
  and inputs, alongside the earlier five. Empty answers are legitimate model
  outputs. The harness fails honestly, no retries into a pass:
  https://github.com/me5wayecdv/MOBIUS-AI/actions/runs/44868837467 .
- Unit/baseline success is not evidence that the corrected model-positive
  connected journey has run end to end. No invented approvals, expected-verdict
  tuning or seeded hypotheses have been added.

## D061 infrastructure evidence, not universal containment

1. First infrastructure-only run:
   https://github.com/me5wayecdv/MOBIUS-AI/actions/runs/44879445681 . FAILED at
   4d7d2f60; incomplete diagnostic location and root0700 artifact collection
   failure. Missing journal/artifacts do not prove no namespace existed.
2. Second infrastructure-only run:
   https://github.com/me5wayecdv/MOBIUS-AI/actions/runs/44880833440 . FAILED at
   f19c1153 because original comparator treated whole-chain iptables numeric
   counters as semantic changes. The 61-file archive provides narrow evidence
   for a nonroot/no-capabilities/no-new-privileges IPv4 loopback workload,
   loopback-only namespace topology, normal tracked-process/name cleanup and
   working private-artifact collection. IPv6 was inspected, not exercised.
3. Actual raw before and initial-after0039 as well as fallback-after0048 compare
   equal offline under the narrowly corrected chain-counter normalization.
   Fallback overwrote named host-after files; raw command records preserve both.
   Rule removal/order, ports/protocol/owner/verdict and topology changes remain
   meaningful. Ten diagnostics tests/32 subtests passed at merged4f3f857.
4. No third infrastructure run was needed or launched. The original failure
   remains failure. Offline comparator repair is not new runtime evidence.

Socket-cgroup classification and host-counter equality do not prove all-traffic
containment. Earlier assessment wording suggesting that they do is superseded.
Inherited descriptors, helper/broker paths, exact process cleanup and complete
network boundary still need source-specific review. PR112 full harness remains
held and incomplete: https://github.com/me5wayecdv/MOBIUS-AI/pull/112 .

## Native capture/replay/TLS frontier

- One real native local capture/request-replay experiment succeeded:
  https://github.com/me5wayecdv/MOBIUS-AI/actions/runs/44883271361 . Native3201byte
  flow plus two independent TLSv1.3 backend receipts, matched fingerprints,
  native replay lifecycle, normal cleanup and all31 copied hashes reviewed.
- FullD061 remains NOT ESTABLISHED. Product authorization/run/evidence/report
  wiring, APK traffic and TLS rejection controls were not exercised. Positive
  stdlib-client loopback traffic is not Android/Allsafe or cert-pinning evidence.
- Namespace snapshot is root supervisor pre-drop, not per-child privilege proof.
  Driver guard passed; separate child privilege/FD snapshots were not retained.
  Normal cleanup succeeded, signal/timeout/emergency kill paths unexercised.
- No repeated local run is planned merely for another pass. Next smallest slice
  is explicit product provenance/persistence wiring with the same fixed fixture,
  preserving existing authorization gates and investigation-anchor versus actual
  traffic-source identity. Its execution awaits focused exact scope review.

## Unchanged limits and unfinished decisions

- Free-only. No production activation, new image publication or GHCR republish.
- Paid spend, old-data deletion and key changes remain gated.
- No state-changing PoC adapters or model retries into a desired result.
- Byte-accounting units are conservative budget units, not provider usage;
  provider-reported usage stays separately labelled `provider_reported_*`.
- Owner-host capabilities are outside current execution; do not ask again as a
  workaround. Held PR66/68 stay held, PR69 stays untouched.
- D062 PDF export, D063 broader app catalogue and action-managed AVD convenience
  are later-scope decisions, not replacements for unfinished original work.
- Allsafe certificate-pinning posture and broader APK capability remain unknown.
- Routine free technical dependency selection is not a blanket prohibition.
  Exact installation/toolchain/harness review is still an operational gate.

No whole-project completion claim is supported by these partial results.
