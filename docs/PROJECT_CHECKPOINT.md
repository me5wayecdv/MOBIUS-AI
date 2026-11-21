# Mobius project checkpoint, 2026-11-21 09:48 EET

This checkpoint supersedes the earlier 20627843 snapshot. It records evidence
limits, not whole-project completion. Merged main inspected at
`4f3f85762ff8364137116b8d2e2c6a00b4454ea3`; latest baseline CI was still pending
when written. Research PR117 is separate, disabled preparation.

## Landed work versus demonstrated work

| Work | Merged state | Demonstration boundary |
| --- | --- | --- |
| Observation-only PHANTOM/Frida (#106), lifecycle (#107) | 93aa0b7, e4bc956 | Prior target-scoped class observation/lifecycle evidence, not capture/TLS or general app coverage |
| D061 not-established docs (#109) | 043aff6 | Explicit gap, not optional completion |
| Connected journey plus hypothesis-ID serializer fix (#110) | 20627843 | Model-positive run reached report but failed projection; serializer fix unit-tested, no positive-model E2E re-verification |
| Infrastructure-only diagnostic/evidence corrections (#113,#114) | 4d7d2f60, f19c1153 | Two failed infrastructure runs, partial evidence described below |
| Narrow chain-counter comparator and evidence persistence correction (#115) | d712b86a | Approved source branch had five normal checks green; offline actual snapshots compare equal; original run still FAILED |
| PROPOSED offline evidence contract (#116) | 4f3f8576 | Six synthetic unit tests/25 subtests define structural consistency only, no capture/replay/TLS runtime proof |

The 42-wheel native proxy closure and disabled standalone code are proposed at
https://github.com/me5wayecdv/MOBIUS-AI/pull/117 . No installation/import/launch
has been performed for that slice. See `research/d061_native/README.md` in that
PR for exact source and remaining technical review, not an activation plan.

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

- D061 remains NOT ESTABLISHED. Actual native request-flow capture and replay,
  independently received request, and appropriate positive/negative TLS tests
  have not been demonstrated by the proposed contract or dependency lock.
- A digest binds bytes, not occurrence, authorship or authorization. Synthetic
  fixture consistency is not evidence of actual capture or TLS capability.
- PR117's concrete local-only native proposal uses trusted harness profile
  attribution and pinned actual FlowWriter/FlowReader/client replay API, not a
  flow-selected profile or hardcoded request reconstruction. It is still
  disabled and unexecuted, with operational installation/execution hold.
- Its dependency lock is wheel-only/hash-closed for CPython3.12, Linuxx86_64,
  glibc>=2.28. Exact runner image/runtime remains unpinned. Dependency resolution
  and download are not imports, runtime validation or a safety certificate.

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
