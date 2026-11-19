# Demonstration scenarios (D-002)

Three functional demonstration scenarios (component review, persisted
source capture, and the soundness boundary). These are functional
demonstrations of the pipeline on pinned targets; they are not a proof that
the system detects specific vulnerability classes. Every target is a public artefact pinned by
SHA-256 in `corpus/corpus.json` (nothing is redistributed; hashes are
verified before use). Expected evidence below is stated from measured runs on
main, not from aspiration.

## Scenario A - Exported-component review on a vulnerable training app

- **Target:** InsecureBankv2, SHA-256
  `b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b91f902d194a4`
  (corpus sample `insecurebankv2`, label: vulnerable training app).
- **Source location:** exported components declared in the binary
  `AndroidManifest.xml` (RECON), code indexed from the multi-DEX entries.
- **Expected evidence:** 5 components close at manual review with persisted
  review evidence records (measured on clean-tree main, 2026-11-19).
- **Positive control:** the InsecureBankv2 run produces those 5 review hits.
- **Negative control:** the named pinned benign samples
  `androguard-test-debug`, `androguard-testactivity` and `a2dp-volume`
  produced zero findings in the clean-tree benchmark (aggregate precision
  1.0, specificity 1.0 across all 7 samples).

## Scenario B - Source-backed investigation with persisted code evidence

- **Target:** OWASP Uncrackable L1, SHA-256
  `1da8bf57d266109f9a07c01bf7111a1975ce01f190b9d914bcd3ae3dbef96f21`
  (corpus sample `uncrack1`).
- **Source location:** `sg.vantagepoint.uncrackable1.MainActivity` from the
  verified JADX 1.5.6 cache (decompiled output, keyed by APK SHA-256 + tool
  version).
- **Expected evidence:** immutable SOURCE evidence bound to the APK SHA-256,
  tool version, path and line range, served inside the investigation's
  evidence package with full provenance. Measured 2026-11-19: scan
  `scn_01M7RXEK5WQE1J2HHM6JT9FARH`, evidence
  `ev_01M7RXF6CNJ1RVTZR5KA1JEBEJ` (method `a`, lines 15-54).
- **Positive control:** `POST /scans/{id}/code/source/evidence` returns 201
  with the hash-bound evidence record.
- **Negative controls (measured 2026-11-19):** an unknown class returns 404
  `JADX_CLASS_NOT_FOUND`; an unknown method returns 404
  `JADX_METHOD_NOT_FOUND`; no snippet is persisted in either case. The
  capture route never fabricates source.

## Scenario C - Soundness boundary on insufficient evidence

- **Target:** the Allsafe training APK (Apache-2.0, security education),
  SHA-256 `d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9`; live journey scan
  `scn_01M7RW55B200GZ5KGC8HKSR5Z7` on main `c6f0b82`, 2026-11-19.
- **Source location:** 7 DEX entries, 92,817 methods indexed; 5 components
  investigated end to end (upload to report).
- **Expected evidence:** every component closes at `insufficient_evidence` /
  `manual_review_required`, never at "refuted" (merged PR #61 policy); the
  coverage manifest discloses the analysis bounds.
- **Positive control:** the recorded live journey outcome above.
- **Negative control:** none matched per-scenario; the aggregate
  clean-tree benchmark (precision 1.0, specificity 1.0 over 7 samples) is
  the supporting evidence that confirmations are not fabricated.

## Out of the demo path

- Model-backed hypotheses are not part of the demo: no model output has
  passed the integrity guards yet (measured 2026-11-19 with three small
  local models); the deterministic fallback is shown and labelled instead.
- Runtime PoC reproduction needs a device/emulator host (D-003/D-060); the
  PoC lab demonstrates local harnesses only.
