# Investigation model-token budget and NEXUS hypotheses

## Default behavior

The investigation pipeline remains deterministic by default. The local Ollama provider is disabled at process configuration by default, and every investigation starts with `llm_data_sharing.enabled=false`. NEXUS hypothesis generation therefore uses the explicitly labelled `deterministic_fallback` unless:
1. An operator explicitly enables the local Ollama provider in process configuration.
2. The investigation owner explicitly grants provider-specific consent through `PUT /api/v1/scans/{scan_id}/model-consent` with `{"enabled":true,"provider":"ollama"}`.

Consent can be revoked with `{"enabled":false,"provider":null}`. A create-scan request cannot implicitly grant consent; the legacy boolean field is rejected when true because it does not identify a provider.

## Cumulative budget invariant

All model calls associated with one investigation share `budget_json.max_model_tokens` and `used_json.model_tokens`. The budget is not copied into a per-call gateway snapshot.

Before a provider request, `InvestigationTokenBudget`:
- Acquires a database write/row lock on the investigation row.
- Reads cumulative actual usage plus outstanding reservations.
- Reserves a conservative upper bound: UTF-8 byte lengths of system prompt, user payload and JSON Schema, protocol overhead, plus requested maximum output tokens.
- Commits the reservation before contacting the provider.

After the call:
- Provider-reported input and output tokens are checked against the pre-call upper bound.
- The reservation is atomically replaced by actual usage.
- Missing usage, transport failure after request start, or an upper-bound violation consumes the full reservation conservatively and fails closed.
- Every accepted usage settlement is recorded as a durable investigation event.

The invariant enforced by every reservation is:

`actual_model_tokens + reserved_model_tokens + requested_reservation <= max_model_tokens`

PostgreSQL row locks serialize reservations across processes. SQLite write locks serialize the CI/development path. The concurrency tests use independent sessions and simultaneous reservations; they assert that two requests cannot reserve the same remaining budget. Multi-call tests prove that sequential calls accumulate actual usage rather than reusing an initial snapshot.

A crashed process may leave a reservation outstanding. This intentionally fails closed (budget capacity is unavailable) rather than assuming a possibly completed provider request was free. Reservation recovery/expiry is a future operational feature and must never release an uncertain reservation automatically.

## NEXUS D-022

`POST /api/v1/scans/{scan_id}/nexus/hypotheses` builds a bounded evidence package and generates testable hypotheses. Model output:
- Must cite observation IDs present in that package.
- Must select required evidence types from a closed allowlist.
- Cannot dispatch tools, select arbitrary targets, run tests, or change finding verdicts.
- Is persisted as `HypothesisRow` plus an auditable `DecisionRow` and `hypotheses_generated` event.

The deterministic fallback is the default and is reported as `mode=deterministic_fallback`; it creates only rule-derived hypotheses from persisted reachable-path observations. It is not described as AI or model reasoning. A configured and consented model call is reported as `mode=model_gateway` with model ID and measured usage. Provider errors are not silently converted into a fallback result.

No hosted provider, paid service, vendor SDK, or new dependency is introduced. The only live adapter remains local Ollama over the standard-library HTTP client.
