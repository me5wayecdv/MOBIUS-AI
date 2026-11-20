# Local structured model provider

**Status:** local provider adapter and core port are implemented. NEXUS hypothesis generation uses the investigation-bound gateway with explicit consent; PR #39 adds an opt-in VERITAS reviewer. Neither model path is part of the default scan flow.

## Scope and dependencies

- No hosted model provider, paid API, vendor SDK, or new Python package is introduced.
- The only real adapter is local Ollama over its HTTP API, using Python's standard library.
- A deterministic mock provider implements the same adapter contract for tests and reproducible fixtures.
- Provider selection defaults to `disabled`. The API does not launch Ollama automatically.

## Configuration

Environment variables:

```sh
MOBIUS_MODEL_PROVIDER=ollama
MOBIUS_MODEL_BASE_URL=http://127.0.0.1:11434
MOBIUS_MODEL_NAME=qwen3:8b
MOBIUS_MODEL_TIMEOUT_SECONDS=120
```

The Ollama endpoint must use plain HTTP and an approved local hostname (`localhost`, `127.0.0.1`, `::1`, `ollama`, or `host.docker.internal`). Public hosted endpoints are rejected. The model must already be installed in Ollama; model downloads are an operator action and are not part of API startup.

To disable model calls:

```sh
MOBIUS_MODEL_PROVIDER=disabled
```

## Consent and budget

The process-wide gateway is only a provider configuration. Before an investigation can use it, the caller must derive a per-investigation gateway with:

- `enabled=True` from that investigation's `llm_data_sharing.enabled`
- `provider="ollama"` matching the explicit per-investigation provider consent
- The remaining model-token budget for that investigation

No consent or a mismatched provider raises `ModelConsentRequired` before any HTTP request. A zero/exhausted budget fails before the request. If the provider does not report input and output token usage, the result is rejected because the investigation budget cannot be enforced.

The returned structured completion includes the validated Pydantic object, actual model ID, input/output token counts, latency, and schema-valid flag. The caller must persist the measured token usage against the investigation budget.

## Output contract

The adapter sends the Pydantic-generated JSON Schema to Ollama's constrained `format` field and validates the returned JSON again locally with `extra="forbid"` schemas. The provider does not receive a tool registry and cannot execute tools. It returns structured data only.

APK-derived text is untrusted input. Prompts must explicitly tell the model not to follow instructions embedded in APK strings, comments, resources, or decompiled code. Model output is a proposal, never evidence or authorization.

## Verified / not yet verified

- Unit tests cover request shape, schema forwarding, local endpoint restrictions, explicit consent, provider identity, malformed output, token-budget exhaustion, missing usage metrics, and deterministic mock compatibility with `core.ports.ModelGateway`.
- CI does not require an Ollama daemon and does not claim model-quality measurements.
- Real Ollama calls were measured on 2026-11-19 (recorded in `TASK_BOARD.md` and `IMPLEMENTATION_STATUS.md`): `qwen2.5:0.5b`, `qwen2.5:1.5b` and `qwen2.5-coder:1.5b` each returned schema-valid JSON, and all three were rejected by the citation/evidence integrity guards. The guards functioned as designed (fail-closed); the models failed the guards. No accepted model-backed hypothesis has ever been produced, and whether a larger local model passes the guards is unknown.
- NEXUS hypothesis generation and VERITAS review persist prompt/model provenance. A bounded repair loop (initial call plus at most two repair attempts carrying fixed reason tokens, fail-closed on exhaustion with committed `planner_rejected` diagnostics) is implemented for NEXUS hypothesis generation; a NEXUS planner and a response cache are not implemented.
- Model calls remain opt-in and require explicit per-investigation consent; deterministic fallback remains the default.


## Investigation integration update

All investigation-scoped model calls must use `InvestigationModelGateway` with the investigation ID and session factory. It reads live consent on every call and reserves a conservative token ceiling against the investigation's cumulative budget under a database row/write lock before contacting the provider. Measured usage is reconciled to `used_json.model_tokens`; ambiguous provider failures and missing usage consume the full reservation and fail closed. Do not use `with_consent(... remaining_tokens=...)` as an investigation integration because that API represents a per-instance snapshot and is retained only for isolated adapter tests/compatibility. See `INVESTIGATION_MODEL_BUDGET.md`.
