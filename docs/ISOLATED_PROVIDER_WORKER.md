# Isolated provider-analysis worker

Static provider-exposure analysis parses attacker-supplied APK bytes
(Androguard DEX adaptation plus the manifest model), so like DEX indexing it
runs outside the API process: in a separately deployed, networkless OCI
container that sees only the staged APK and the durable `worker_jobs` queue.

## Flow

1. `POST /api/v1/scans/{scan_id}/provider-analysis/jobs` enqueues a
   `provider_analysis` row. Same gates as DEX indexing: SURFACE_READY state,
   live authorization bound to the artifact, no duplicate unapplied job.
2. The worker claims it, stages the APK, and runs `mobius-provider-analysis`
   in a digest-pinned image (`MOBIUS_PROVIDER_IMAGE`, immutable
   `repo@sha256:...` reference only).
3. The container entrypoint parses the manifest surface, adapts each
   root-level `classes*.dex` (sizes checked before decompression, per-entry
   and aggregate budgets, per-entry coverage ledger), runs the deterministic
   `core.providers` detector, and emits a versioned JSON payload on stdout.
4. The API applies it exactly once via
   `POST /api/v1/scans/{scan_id}/provider-analysis/jobs/{job_id}/apply`:
   strict schema validation, per-field bounds, closed enum sets (protection
   status, operation kind, guard outcomes), digest binding to the authorized
   APK SHA-256, methods-adapted count cross-checked against the ledger, and
   the authorization target-package check repeated against the payload's
   package name.
5. The service then applies the SAME downgrade rules as the in-process path:
   DEX completeness is recomputed API-side from the ledger alone (a partial
   ledger downgrades `caller_check_absent=True` to unknown), field-carried
   sink flows never satisfy provider proofs, and every finding is decided by
   the exported-component-no-permission gate, never by the worker.

The in-process route (`POST /scans/{id}/provider-analysis`) remains for local
development only: it answers 503 unless the environment is `test` or
`MOBIUS_PROVIDER_INLINE=1`.

## Trust contract

- Worker output is evidence transport, never a verdict. A payload that
  smuggles extra fields (for example a `verdict`) is schema-invalid.
- Distinct failure classes: exit 2 staged-input contract violation, 3
  analysis failure, 4 output budget exceeded. A DEX entry that cannot be
  parsed is NOT a failure; it is ledger evidence that downgrades the claims
  depending on it.
- Output budget: 4 MiB (`MAX_PROVIDER_JSON_BYTES`), enforced in the
  entrypoint and again at apply time.

## Publication

`.github/workflows/publish-provider-worker-image.yml` is
`workflow_dispatch`-only and requires `owner_approval=APPROVED` plus an
approval reference. Do not publish a provider image, and do not set
`MOBIUS_PROVIDER_IMAGE` to a mutable tag, without an explicit project-owner
decision. Until a digest is published and a dedicated worker deployment is
smoke-tested, do not claim provider analysis is operationally isolated in a
deployed environment.
