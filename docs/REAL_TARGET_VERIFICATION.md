# Real-target verification: Allsafe (2026-11-21)

Verification record for the pinned public lab APK against current `main`
(`81483d1`). Target: Allsafe v.1.6 (`infosecadventures.allsafe`), public
intentionally vulnerable training app, sha256
`d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9` (matches
the upstream release asset). Authorization row scope: static analysis of the
supplied artefact only. Model route: free OpenCode CLI provider
(`deepseek-v4.1-flash-free`), per-investigation consent.

## Static pipeline (journey, local process)

Upload -> authorize -> scan -> recon -> spectre -> provider-analysis ->
model-backed hypothesis -> VERITAS review, all through the product HTTP API.

- Multi-DEX ledger disclosed: 6 entries parsed (47093/383/22/196/29/15
  methods), `classes7.dex` `truncated-budget` at 2262 methods,
  `dex_complete=false`. Findings state bounded package coverage; no
  whole-APK completeness is claimed.
- Two findings on `infosecadventures.allsafe.challenges.DataProvider`
  (read and write operations): `exported=true`, no permission,
  `caller_check_absent=true` with per-class provenance (entry, runtime-order
  position, duplicated flag) and an explicit scope bound (analyzed operation
  methods + resolved helpers only). Sink flows recorded in the finding
  evidence: caller-controlled values into `SQLiteDatabase.update`/`delete`.
- VERITAS (model, advisory-only) challenged the write finding; one review
  cited evidence outside the finding's persisted refs and was captured as
  `needs_review` (verbatim raw reply preserved, untrusted, no verdict change,
  no foreign ref promoted). Deterministic gates remain the sole verdict
  authority; findings rest at `manual_review_required` /
  `insufficient_evidence` by policy.

## Safe PoC on the real target (read-only, manifest preconditions)

Read-only PoC plan (lab_apk target, no approval required) against the live
investigation:

- Positive control: persisted manifest component fact for the exported
  DataProvider found (expected true, actual true).
- Negative control: a nonexistent guarding permission is not declared
  (expected false, actual false).
- Run `pcr_01M7XK6E5TP5ZFT0349HYJKDPA` (plan
  `poc_01M7XK6E5H4QQJ157D5W39NNBS`) status `passed`; plan/result/log evidence
  persisted with input/output SHA-256.

This verifies preconditions and evidence capture on the real target. It is
not runtime exploitation.

## Dynamic smoke (runtime, CI emulator)

`.github/workflows/dynamic-provider-smoke.yml` +
`scripts/dynamic_provider_smoke.sh`: a hardware-accelerated emulator
(KVM on `ubuntu-latest`) installs the sha256-verified APK and exercises the
provider over `content`:

- `content query` against the exported provider returned the 4 seeded notes
  with no permission (`rows_before=4`).
- `content delete --where "1=1"` removed every row (`rows_after=0`):
  caller-controlled WHERE reaches `SQLiteDatabase.delete` at runtime.
- Negative control: the non-exported FileProvider authority is refused.
- First run: success (run 44834324180, artifact `dynamic-provider-smoke`).

This runtime-confirms the static finding on the lab target, in an ephemeral
emulator, with no credentials and no external target. It is a verified
slice, not the full PHANTOM adapter.

## Remaining boundaries (unchanged by the above)

- PHANTOM adapter: first read-only slice implemented inside Mobius
  (`services/phantom.py`): env-gated adb probes (package presence,
  provider row counts) wired into the D-041 runner for `emulator` plans,
  with qemu-only device verification and same-package target binding.
  End-to-end execution of a `read_only` emulator plan through the API is
  CI-verified (`phantom-api-smoke` workflow, first run 44842949369 on a
  hardware-accelerated emulator: upload -> authorization -> scan ->
  RECON -> `poc/execute` -> persisted poc-plan/poc-result/poc-log
  evidence, provider rows actual=4, PHANTOM_API_SMOKE: ALL_PASS).
  Limitation of that slice: the plan's referenced hypothesis is seeded
  directly in sqlite as documented test setup, because hypothesis
  creation through the API is model-gated (NEXUS consent) and the
  journey is intentionally no-model; every step under test goes through
  the API. Mobius-managed emulator orchestration and Frida
  instrumentation remain unimplemented.
- JADX OCI image: unpublished by design; the queue returns 503 until an
  approved immutable digest is configured. RECON/DEX/provider OCI worker
  transport is CI-verified (worker pipeline smoke, provider runtime
  validation against a job-local registry).
- Deployed worker host: unverified (demo-first deferral).
- Detection breadth: catalogue-bounded (provider operations, hardcoded keys,
  secrets); the broader catalogue (D-063) is deferred.
- Dynamic analysis: standalone smoke plus API-integrated read-only
  Mobius probes; no mitmproxy, no Frida hooks, no persistent emulator
  infrastructure.
