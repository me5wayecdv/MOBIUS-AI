# Proposed offline capture evidence contract

Research only. `research/d061_capture_contract.py` and its synthetic unit tests
specify a candidate normalized evidence structure. They are not wired into
product execution and do not implement mitmproxy, Android capture, TLS testing
or real replay. No dependency install, socket or target launch is needed.

## Candidate acceptance

- Investigation-scoped nonce, granted plan hash and separate active target
  authorization for each distinct package/APK identity.
- Digest-bound captured safe GET, bounded headers and body hash, exact approved
  fixture URL, and capture artifact bound to replay.
- One initial and exactly one additional origin receipt with distinct IDs,
  sequence, same investigation/nonce and captured-request digest.
- Request replay is distinguished from response replay and from reissuing an
  unrelated hardcoded URL.
- Separate positive trusted-chain/hostname, untrusted-chain rejection,
  trusted-chain wrong-hostname rejection, upstream positive verification and
  upstream untrusted-chain rejection. Wrong-hostname evidence cannot be a
  generic TLS exception caused by an untrusted chain.
- Output explicitly says structural acceptance only, runtime capability and
  authenticity NOT established. Scope is substitute fixture, never Allsafe
  or arbitrary-target coverage.

## Limits and required actual verification

SHA256 binds evidence bytes. It does not authenticate who produced them or prove
any event occurred. A fabricated internally consistent bundle can satisfy this
contract. The tests reject inconsistent, substituted or missing records, NOT a
malicious producer fabricating all records. A future reviewed runtime must
independently gather original proxy flows, backend receipts, TLS outcomes and
product authorization/run records. It must preserve source provenance, capture
artifacts, extraction versions and evidence storage integrity, not accept an
arbitrary client's asserted outcomes. The proposed JSON is not mitmproxy's
native flow format. The extractor and replay-from-actual-flow implementation do
not yet exist. Active/expiry/approval assertions require live product checks,
not client-provided booleans.

Current gate tests concern TLS trust, not application authentication. No claim
of complete T105 authentication coverage is made. Replay safety, cancellation,
bounds, cleanup and namespace/helper/FD/broker hygiene remain separately held.
Toolchain additions remain held. Model paths and verdicts were not exercised.

## Local evidence

Five tests with 17 negative subtests exercise missing capture, response-replay
substitution, cross-investigation approvals, wrong target authorization,
changed bytes, duplicate/extra/missing/stale receipts, mismatched replay digest,
wrong TLS rejection reason, chain-confounded hostname test and disabled upstream
verification. Synthetic positive acceptance explicitly returns NOT_ESTABLISHED
for runtime capability and authenticity. These tests cannot replace eventual
actual machinery/runtime verification or whole-project acceptance.

## One bounded correction after review

The proposed validator now requires an independently supplied fixture policy
with nonempty required package/APK set, TLS-profile-to-package map and exact
allowed URLs. Empty targets and duplicate authorization IDs fail. Flow, replay,
receipts and TLS profiles carry target/APK/plan binding; digest recomputation
does not excuse cross-target records. Headers are bounded and limited to x-test
and accept, credential/cookie headers and nonempty GET bodies are rejected,
and redirect count must be zero. A self-asserted scope string is insufficient.
These are proposed narrow fixture constraints, not general GET safety or
application authentication policy. The independent policy still needs trusted
runtime provenance. Six tests/25subtests pass; no further synthetic layering.

The concrete next frontier is D061_NATIVE_PROXY_SLICE_DESIGN.md and its actual
pinned metadata inventory. Transitive lock, dependency disposition and runtime
boundary remain unresolved; no installs or launches have occurred.
