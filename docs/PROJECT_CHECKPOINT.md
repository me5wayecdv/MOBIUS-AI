# Mobius Project Checkpoint (2026-11-21)

Durable checkpoint of verification state, evidence, limits and open decisions.
Written at task expiry; reflects main at squash SHA 20627843.

## Consent state

- Upstream model-provider consent: verified against the owner's original
  messages (Nov 20, 22:20:59 and 22:21:02 EET, owner number +201140495914),
  with agent scope confirmation at 22:21:09: free DeepSeek via opencode for
  Mobius trials only, no account secrets, no unrelated data.
- Distinct gates kept separate: upstream-data consent, synthetic-CI test
  approval, and any real-plan or production approval. Production activation,
  paid spend, data deletion and key changes remain owner-approval-gated.
- Owner instruction (Nov 21, 00:09): no user-facing messages until the whole
  project completes.

## Merged and verified (SHA-matched CI evidence)

| Item | Merge SHA | Evidence |
| --- | --- | --- |
| PHANTOM approval-gated observation-only Frida instrumentation (#106) | 93aa0b7 | post-merge run 44857880298 green; 11361 classes observed on Allsafe |
| Mobius-managed boot + pinned frida-server lifecycle (#107) | e4bc956 | post-merge runs 44862803510 / 44862803373 / 44862803427 green |
| D-061 documented as not established (#109) | 043aff6 | docs only |
| Connected-journey advisory workflow + hypothesis_ids serializer fix (#110) | 20627843 | round-1 run 44865900582 full chain; MOBIUS CI and worker smoke green post-merge on 20627843 |

## Verification status and gaps

- Connected journey (consent -> model hypotheses -> dynamic evidence ->
  ARCHIVIST report): run as one connected chain in CI, round 1 run
  44865900582. Mode model_gateway, provenance opencode/deepseek-v4.1-flash-free,
  5 model hypotheses, approval leg, frida actual=11361, report carrying
  model_consent_updated and hypotheses_generated events plus poc-result and
  report evidence.
- Gap, explicit: the run-bound-to-model-hypothesis projection failed in round
  1 (serializer omitted hypothesis_ids). The fix (126e0da) is unit-verified
  (968 tests passed) but NOT re-verified end to end on a model-positive run.
  No model retries into a pass were or will be performed.
- Model non-determinism on the free route is an established property: three
  samples of identical code, route and inputs returned 5, 0, 0 hypotheses
  (runs 44865900582, 44868837467 attempt 1, 44868837467 attempt 2). Empty
  output is a legitimate model answer; the harness fails honestly.
- D-061 traffic capture: NOT established. Earlier strictly-controlled capture
  could not be proven contained on free runners (see docs merged in #109 and
  the PR #108 record). A follow-up capability assessment found a plausible
  contained-lab route (docs/D061_CONTAINED_LAB_ASSESSMENT.md, probe runs
  44875785657 / 44876090990 / 44876211141); executing it is an unresolved
  decision. D-061 is blocked pending that decision, not optional and not
  complete.

## Held by the owner (not engineering-blocked)

- D-003 owner-host capabilities.
- Production activation beyond approved experiments.
- Paid spend, data deletion, key changes.

## Genuinely optional (later demo plan, not the original proposal)

- D-062 PDF export: no insufficiency evidence for the current report.
- D-063 broader app catalogue: scope decision, parked.
- Action-managed AVD creation/snapshotting: convenience.
- Allsafe runtime certificate-pinning posture: unverified, remains unknown.

## Standing limits in force

- Free-only route; no bypass of the opencode client gating; no paid keys.
- No production activation, no new image publication, no GHCR tag or
  republish, no new repo dependencies.
- Runtime findings are scoped to the tested target and version.
- State-changing PoC adapters stay disabled.
- No expected-verdict tuning, no seeded hypotheses, no invented approvals.
- Mobius byte-accounting units are conservative budget units, never reported
  as actual provider usage; provider-reported usage persists separately as
  provider_reported_*.
