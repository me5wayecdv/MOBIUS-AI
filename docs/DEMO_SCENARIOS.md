# Demonstration scenarios (D-002)

Three functional demonstration scenarios (component review, persisted
source capture, and the soundness boundary). These are functional
demonstrations of the pipeline on pinned targets; they are not a proof that
the system detects specific vulnerability classes. Every target is a public artefact pinned by
SHA-256 in `corpus/corpus.json` (nothing is redistributed; hashes are
verified before use). Expected evidence below is stated from measured runs on
main, not from aspiration. Live main at last measurement: `40bf0b8`
(2026-11-19). Each measurement names its scan or harness run and revision;
figures from ancestor revisions are marked historical.

## Scenario A - Exported-component review on a vulnerable training app

- **Target:** InsecureBankv2, SHA-256
  `b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b91f902d194a4`
  (corpus sample `insecurebankv2`, label: vulnerable training app).
- **Source location:** exported components declared in the binary
  `AndroidManifest.xml` (RECON), code indexed from the multi-DEX entries.
- **Expected evidence:** 6 findings on the exported-component-no-permission
  gate: 1 confirmed by the gate (`ViewStatement`, confidence 0.9, gate
  clauses exported/permission/caller_check_absent/sink_reachable all
  established; a gate pass is not an exploited weakness) and 5 closed at
  `manual_review_required` with persisted review evidence records.
  Measured on live main `40bf0b8`, 2026-11-19: scan
  `scn_01M7T16D7G1CCWCSFKGR2YN0PM` (upload to ARCHIVIST report) and the
  repo benchmark harness (confirmed=1, manual_review=5, flagged=true).
  Here and below, "flagged" is the benchmark's term for confirmed > 0;
  manual-review hits alone do not flag a sample.
  The earlier "5 components close at manual review" figure was measured on
  ancestor revisions earlier the same day and is historical.
- **Positive control:** the InsecureBankv2 run produces the confirmed
  `ViewStatement` finding plus the 5 review hits above.
- **Negative control:** the named pinned benign samples produced no
  confirmed findings and were not flagged. Measured on live main
  `40bf0b8`, 2026-11-19: `a2dp-volume` 0 confirmed / 2 manual review,
  flagged=false (benchmark harness). `androguard-test-debug` and
  `androguard-testactivity`: 0 confirmed in the historical 7-sample
  clean-tree run (morning 2026-11-19, ancestor revision). Historical
  7-sample aggregate from that run, with exact denominators: precision 1.0
  (CI95 0.21-1.0, 1 flagged), recall 0.25 (CI95 0.05-0.70, 4 vulnerable),
  specificity 1.0 (CI95 0.44-1.0, 3 benign); TP 1, FP 0, FN 3, TN 3. Seven
  samples are too few to establish reliability; these figures are historical
  provenance from an ancestor revision, not a current-main recall or
  accuracy measurement.

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
  `scn_01M7RW55B200GZ5KGC8HKSR5Z7` recorded on main `c6f0b82`, 2026-11-19
  (historical: `c6f0b82` is an ancestor of the current live main
  `40bf0b8`; not re-run on the current head).
- **Source location:** 7 DEX entries; the historical run's recorded index
  count was 92,817 methods (reported figure from that run's record, not
  re-derived for this document); 5 components investigated end to end
  (upload to report).
- **Expected evidence:** every component closes at `insufficient_evidence` /
  `manual_review_required`, never at "refuted" (merged PR #61 policy); the
  coverage manifest discloses the analysis bounds.
- **Positive control:** the recorded live journey outcome above.
- **Negative control:** none matched per-scenario. The historical
  7-sample clean-tree benchmark (morning 2026-11-19, ancestor revision;
  precision 1.0 CI95 0.21-1.0 on 1 flagged sample, specificity 1.0
  CI95 0.44-1.0 on 3 benign) is too small to establish reliability and is
  cited for provenance only, not as evidence of accuracy.

## Out of the demo path

- Model-backed hypotheses are not part of the demo: no model output has
  passed the integrity guards yet (measured 2026-11-19 with three small
  local models); the deterministic fallback is shown and labelled instead.
- Runtime PoC reproduction needs a device/emulator host (D-003/D-060); the
  PoC lab demonstrates local harnesses only.
