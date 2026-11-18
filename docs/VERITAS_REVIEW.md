# VERITAS independent finding review

**Status:** implemented as an opt-in service on PR #39; not yet wired into the default investigation pipeline or War Room.

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

The service is available to application code as `VeritasReviewService(session, gateway=..., session_factory=...).review(finding_id, producer_model_id=...)`. It is not automatically invoked by validation or the scan pipeline in this slice. The caller must supply a trustworthy producer model ID from the discovery provenance; the service does not infer one.

## Verification boundaries

Unit tests cover different-model enforcement (including provider aliases), consent, evidence-reference confinement, persisted audit provenance, and the invariant that a VERITAS challenge cannot alter the stored deterministic verdict. A real Ollama review and model-quality benchmark remain unverified. No migration is included.
