# D061 product local integration, actual result

One bounded disposable CI experiment succeeded, not whole D061 or project completion.

- Reviewed main SHA: `45d0b31b4e71dbb0c62fb65d4e04f2c10633f076`, exact Git tree of
  reviewed activation head407c9ca. PR118 merged after all8 ordinary checks green.
- Actual run: https://github.com/me5wayecdv/MOBIUS-AI/actions/runs/44886198628
- Original sanitized artifact14699684180,97093bytes, ZIP SHA
  `967c08e52d7d3e7db038e2b668a0115eeda27434718b4f7367e7cd3734118d20`.
- Original logs37467bytes, ZIP SHA
  `af02abbf2b5b69cdb10dc803ab497480af350e3555cd7a67d8e187539786a595`.
- Product run `pcr_01M7YMDP125682ZDAGC295KC54`, PASSED2350ms; approved60s
  operation+60s teardown+10s collection reserve,130s total,1MiB output cap.

## What actually ran

A new explicitly disposable actor `ci-native-local-fixture` used the real
product API for authorization/case/exact-plan approval. New case
`scn_01M7YMDJV32TD2SAD1EYR88TRT`, authorization
`ath_01M7YMDJR572F291Y3BVV1VHDS`, approval
`apr_01M7YMDJVVGNC6F19C0A92Z9P1`. These are integration-test records, not owner
permission. No expired emulator grant or authority was transferred.

Five genuine historical model hypotheses were copied through explicitly
fixture-only DB setup, not a product import API or a current model call. The
source is artifact14691009604 from
https://github.com/me5wayecdv/MOBIUS-AI/actions/runs/44865900582 , ZIP SHA
`2e123119845bf6da37067dd9b8eed9eb6d92335716e4e477c4941abf3f3ccb76`.
Original case `scn_01M7Y5NADSTR1GK2CN0E05YBPV` and decision
`dec_01M7Y5PNXPKD48F27WTKG7WX5X` remain historical. Original hypothesis IDs,
claim hashes, row hashes, decision hash and copied IDs are in retained
fixture-provenance.json. Executor independently compared all5 claims/row hashes
and decision hash to the original source DB. The independent result reviewer
verified the retained mapping; that reviewer did not repeat the original-archive
crosscomparison. Claims remain open, not validated vulnerabilities.

Actual product execute, distinct-request immutable readback and report
write/read were exercised.75 recovery-file hashes and21 product-store object
hashes match retained originals. The19 linked run evidences total19028bytes,
with exact per-name evidenceID/digest/size mapping. Executor readback using
retained readonly DB/original objects exactly equals the actual API readback.
The independent reviewer separately checked DB/link/hash/plan relationships.

Native capture3201bytes SHA
`33871cd5e4fc6c1e4c94429f45928a62df438a1637cd60a9558e8ef2537fdaae` contains
one actual HTTPS flow, fixed GET/three headers/empty body/response200. Initial
and request-replay flow ID `1f3a0b76-2f33-40c2-9eb2-10da58ef813f` matches native
bytes, native-proof and events. Two distinct independent origin receipts have
sequence1/2 and TLSv1.3; all4 canonical requests match. Independent reviewer
decoded original native bytes without importing mitmproxy/product candidate code.

Stored report `ev_01M7YMDP38ER3PPJXG36YT1YJC`, SHA
`5944f15112ccab4ac1fec6da5634ae8945b595f495bb47f1b5109fc26b289949`, matches
retained report and original DB object, includes run/plan/all evidence refs and
explicit local-only limitations. No new model decision/token event exists in
the disposable case. No model retry was performed.

## Separate TLS control and lifecycle evidence

A separate isolated origin/proxy/nonce/initialized ledger exercised client
rejection of an untrusted proxy certificate chain, verification enabled. Actual
SSLCertVerificationError20, ledger before0/after0/delta0 after both producers
stopped. This is one rejection control, not hostname-mismatch, untrusted-origin,
pinning or general TLS coverage. Product positive profile still says its own
TLS rejection controls are untested; separate control is not silently attached
to that profile.

Independent always-run sanitation and stage-required final absence succeeded
for product and TLS roots: required launch records present, errors[], no live
recorded processes/private namespace members, keys/home/recorded jail absent.
Normal path only. This does not exercise failure, cancellation, timeout or
supervisor-kill paths. Collector is bounded partial recovery, not a promise of
full original archives after every failure. No private keys/homes/raw recursive
artifact upload. Recovery missing entries are mainly failure-only files and
inapplicable positive/TLS counterparts, not assertions that those ran.

## Preserved audit gap and non-results

The original experimental approval row has decided_by NULL due to an existing
PoCApprovalService metadata omission. Its append-only approval_resolved event
correctly attributes the actual test actor; requested_by and authorization
actor also match. Original DB/event/ZIP are not retrospectively rewritten.
A forward-only metadata regression/fix is separate work, no rerun needed.

An earlier activation attempt failed GitHub workflow validation at7aeb78f
because runner.temp was unavailable in jobenv. Run44885790634 had0jobs and is
still failed, not an actual native experiment. Source/context correction407c9ca
was reviewed before the single actual dispatch.

No APK, emulator, Android, Allsafe runtime, certificate pinning, third-party or
production target was exercised. Actual traffic was the controlled stdlib
loopback client. Product plumbing/native local replay and one separate TLS
control are demonstrated; real app-originated capture/replay remains original
scope work. Do not repeat this fixture merely to accumulate passes.
