# VERITAS independent finding review

**Status:** implemented as an opt-in service on PR #39; manually invoked via `POST /scans/{id}/findings/{finding_id}/veritas-review` (PR #64). As of 2026-11-20, an optional post-pipeline auto-review pass wires it into the NEXUS route behind a default-off per-investigation flag (`auto_veritas` on `PUT /scans/{id}/model-consent`). Advisory-only in both modes; deterministic gates remain the sole verdict authority. Real-model review quality remains unverified (see the 2026-11-19 measurement rows in TASK_BOARD/IMPLEMENTATION_STATUS: small local models failed the integrity guards or timed out).

## Purpose

VERITAS is a separate model-backed reviewer that challenges an existing persisted finding against the evidence already attached to that finding. Its output is advisory. It cannot create, update, confirm, reject, or downgrade a finding. The deterministic predicates in `ValidationService` remain the only verdict authority.

## Independence and consent

- The caller must supply the finding producer's actual model ID.
- The requested VERITAS model must differ from the producer model before any provider request.
- The provider-resolved model ID is checked again after the response; aliases that resolve to the producer model are refused and are not persisted as an independent review.
- The investigation must have explicit `llm_data_sharing.enabled=true` and provider consent matching the configured local provider.
- Calls use `InvestigationModelGateway`, which enforces the investigation's live consent and cumulative token budget.
- The reviewer runs at temperature 0 and uses the reasoning role.
- No hosted provider, paid service, SDK, or new package is introduced.

## Evidence boundary

The service loads the persisted finding and resolves every evidence reference against `evidence` rows belonging to the same investigation. Only bounded summaries and metadata are sent; raw APK contents, prompts, and hidden reasoning are not persisted. Each challenge must cite only evidence IDs supplied in that review. Unknown or cross-investigation references fail closed.

## Output and audit

The structured reply is one of:

- `challenge`: at least one concrete challenge with cited evidence and requested proof.
- `no_material_challenge`: no challenge was identified; this is not confirmation.
- `insufficient_evidence`: the supplied evidence cannot support a meaningful review.

A `DecisionRow` stores the validated structured result and D-025 provenance (provider, requested/actual model, prompt version, hashes, schema, token usage, latency, and generation parameters). A `veritas_review_completed` event records the disposition and provenance without raw prompt text. No schema change or migration is required.

## Invocation

The service is available to application code as `VeritasReviewService(session, gateway=..., session_factory=...).review(finding_id, producer_model_id=...)`. The manual route requires the caller to supply a trustworthy producer model ID from the discovery provenance; the service does not infer one.

## Optional auto-review pass (added 2026-11-20)

When an investigation opts in (`auto_veritas: true` on the consent endpoint, which requires `enabled: true`), `POST /scans/{id}/nexus` runs a bounded review pass AFTER the deterministic pipeline transaction commits, and adds a `veritas_auto_review` summary block to the response. Without the flag the response is unchanged.

Design constraints, all test-pinned:

- **Post-commit only.** The pipeline session holds the investigation row write lock (event_seq allocator) until commit; an in-pipeline review would self-block because the review's budget reserve/settle run on independent sessions. The route commits first, then the pass runs per-finding on fresh sessions.
- **Fail-closed provenance.** Only confirmed findings from a known deterministic producer with persisted evidence references are eligible; they are sent with the explicit `deterministic-pipeline` sentinel producer ID. Anything else is skipped with a fixed reason token, and a sentinel review always reports `producer_model_verified: false` / `independence_assured: false`.
- **Per-finding rechecks.** Consent, provider match, and the auto flag are re-read immediately before each review, not once per pass.
- **Concurrency-safe.** A PostgreSQL advisory transaction lock per (investigation, finding) is held on the review's own session until the commit/rollback AFTER the provider call and persistence complete; simultaneous runs cannot double-review or double-reserve, and contention is reported as the fixed skip token `review-in-progress`. This guarantee is PostgreSQL-only: on SQLite (single-process development) the lock is skipped by design and the `already-reviewed` idempotency check alone applies.
- **Fail-isolated.** Per-finding failures persist a `veritas_review_failed` diagnostic event with a fixed reason token (`consent-missing`, `provider-error`, `output-invalid`, `budget-exhausted`, `review-pass-error`) on its own transaction; raw errors, prompts, and exception chains never leave the server. A pass-level failure is reported as `status: review-pass-error` in the response block and never changes the scan's HTTP result.
- **Bounded and idempotent.** At most 10 reviews per run; a finding with a persisted review is skipped (`already-reviewed`). In the summary block, `completed` counts only reviews that were actually persisted; `skipped` and `failed` entries (including `review-in-progress` and any `review-pass-error`) are never counted as completed reviews.

## Verification boundaries

Unit, HTTP, and PostgreSQL tests cover different-model enforcement (including provider aliases), consent, evidence-reference confinement, persisted audit provenance, the invariant that a VERITAS challenge cannot alter the stored deterministic verdict, the auto-pass skip/failure tokens, idempotency, and concurrent-pass single-review semantics under PostgreSQL. A real Ollama review and model-quality benchmark remain unverified; the auto pass has only ever run against scripted mock providers. No migration is included.

## Report presentation (preview branch, not on main)

On the preview branch `feat/archivist-veritas-advisory`, ARCHIVIST renders one advisory line per finding from persisted rows only: a completed review shows its disposition, summary, challenges, reviewer model, and an explicit independence statement (`producer independence was **not verified**` whenever the producer is not bound to a persisted model decision), always marked advisory-only with "a lack of challenge is not confirmation"; a failed or skipped attempt renders as **not completed** with its fixed reason token and is never presented as a review result. Findings with no recorded advisory activity show no line. The change is held for owner preview with real renders; it is not merged.
