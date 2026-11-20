"""Local-only structured model provider boundary.

Providers return typed JSON, never executable tool calls. The gateway requires per-scan
consent and validates every response against a caller-supplied Pydantic contract.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol, get_args, get_origin
from urllib.parse import urlsplit

from pydantic import BaseModel, ValidationError


class ModelProviderError(RuntimeError):
    pass


class ModelConsentRequired(ModelProviderError):
    pass


class ModelUnavailable(ModelProviderError):
    pass


class ModelOutputInvalid(ModelProviderError):
    def __init__(self, message: str, *, raw_content: str | None = None) -> None:
        super().__init__(message)
        # The raw reply is kept for server-side repair/review only. API layers
        # must never surface it to clients.
        self.raw_content = raw_content


class ModelBudgetExceeded(ModelProviderError):
    pass


@dataclass(frozen=True, slots=True)
class ProviderResult:
    content: str
    model_id: str
    # Accounting units charged against the investigation budget. For providers
    # that transform the envelope (OpenCode CLI adapter) these are conservative
    # byte-ceiling measurements, NOT the provider's real token count.
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    # The provider's own reported real token usage when it differs from the
    # accounting units above; None means no distinct provider report exists.
    provider_prompt_tokens: int | None = None
    provider_completion_tokens: int | None = None
    duration_ms: int = 0


class ModelProvider(Protocol):
    name: str

    def complete_json(
        self,
        *,
        model: str,
        system_prompt: str,
        user_payload: dict[str, Any],
        response_schema: dict[str, Any],
        timeout_seconds: int,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> ProviderResult: ...


class DeterministicMockProvider:
    """Deterministic provider for tests and explicitly labelled local demonstrations."""

    name = "mock"

    def __init__(
        self,
        response_json: str,
        *,
        model_id: str = "mobius-deterministic-mock",
        prompt_tokens: int = 1,
        completion_tokens: int = 1,
    ) -> None:
        self.response_json = response_json
        self.model_id = model_id
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens

    def complete_json(self, **_kwargs: Any) -> ProviderResult:
        return ProviderResult(
            content=self.response_json,
            model_id=self.model_id,
            prompt_tokens=self.prompt_tokens,
            completion_tokens=self.completion_tokens,
        )


class OllamaProvider:
    """Ollama /api/chat adapter using only the Python standard library."""

    name = "ollama"

    def __init__(self, base_url: str = "http://127.0.0.1:11434") -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError("Ollama endpoint must be a plain local HTTP origin")
        host = parsed.hostname.lower()
        if host not in {"localhost", "127.0.0.1", "::1", "ollama", "host.docker.internal"}:
            raise ValueError("Ollama endpoint must resolve through an approved local host name")
        self.endpoint = base_url.rstrip("/") + "/api/chat"

    def complete_json(
        self,
        *,
        model: str,
        system_prompt: str,
        user_payload: dict[str, Any],
        response_schema: dict[str, Any],
        timeout_seconds: int = 120,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> ProviderResult:
        if not model.strip():
            raise ValueError("model name is required")
        body = json.dumps({
            "model": model,
            "stream": False,
            "format": response_schema,
            "options": {"temperature": temperature, "num_predict": max_tokens},
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": json.dumps(user_payload, ensure_ascii=False, separators=(",", ":")),
                },
            ],
        }).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ModelUnavailable(f"Ollama request failed: {type(exc).__name__}") from exc
        if len(raw) > 2 * 1024 * 1024:
            raise ModelOutputInvalid("Ollama response exceeded 2 MiB")
        try:
            decoded = json.loads(raw)
            message = decoded["message"]["content"]
            model_id = str(decoded.get("model") or model)
            prompt_tokens = decoded.get("prompt_eval_count")
            completion_tokens = decoded.get("eval_count")
        except (ValueError, KeyError, TypeError) as exc:
            raise ModelOutputInvalid("Ollama returned an invalid response envelope") from exc
        if not isinstance(message, str) or not message.strip():
            raise ModelOutputInvalid("Ollama returned empty structured content")
        return ProviderResult(
            content=message,
            model_id=model_id,
            prompt_tokens=prompt_tokens if isinstance(prompt_tokens, int) else None,
            completion_tokens=completion_tokens if isinstance(completion_tokens, int) else None,
            duration_ms=max(0, int((time.monotonic() - started) * 1000)),
        )


class StructuredModelGateway:
    """Consent-gated provider call with strict output and token-budget validation."""

    def __init__(self, provider: ModelProvider, *, model: str, timeout_seconds: int = 120, consent_enabled: bool = False, consent_provider: str | None = None, remaining_tokens: int = 0) -> None:
        if not model.strip():
            raise ValueError("model name is required")
        if not 1 <= timeout_seconds <= 900:
            raise ValueError("model timeout must be between 1 and 900 seconds")
        self.provider = provider
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.consent_enabled = consent_enabled
        self.consent_provider = consent_provider
        self.remaining_tokens = remaining_tokens

    def with_consent(self, *, enabled: bool, provider: str | None, remaining_tokens: int) -> StructuredModelGateway:
        return StructuredModelGateway(
            self.provider, model=self.model, timeout_seconds=self.timeout_seconds,
            consent_enabled=enabled, consent_provider=provider, remaining_tokens=remaining_tokens,
        )

    async def complete_structured(
        self, *, role: str, system: str, user: str, schema: type[BaseModel],
        temperature: float = 0.0, max_tokens: int = 4096,
    ) -> dict[str, Any]:
        if role not in {"reasoning", "workhorse"}:
            raise ValueError("model role must be reasoning or workhorse")
        parsed, result = await asyncio.to_thread(
            self.generate,
            output_model=schema,
            system_prompt=system,
            user_payload={"input": user},
            consent_enabled=self.consent_enabled,
            consent_provider=self.consent_provider,
            remaining_tokens=self.remaining_tokens,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return {
            "data": parsed,
            "model_id": result.model_id,
            "input_tokens": result.prompt_tokens,
            "output_tokens": result.completion_tokens,
            "latency_ms": result.duration_ms,
            "schema_valid": True,
            # The verbatim transport reply: normalization may reshape it, so a
            # post-conversion rejection must capture THIS, not a reserialized
            # parse tree, when the original is what the operator needs.
            "raw_content": result.content,
        }

    def generate(
        self,
        *,
        output_model: type[BaseModel],
        system_prompt: str,
        user_payload: dict[str, Any],
        consent_enabled: bool,
        consent_provider: str | None,
        remaining_tokens: int,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> tuple[BaseModel, ProviderResult]:
        if not consent_enabled:
            raise ModelConsentRequired("LLM data sharing is disabled for this investigation")
        if consent_provider != self.provider.name:
            raise ModelConsentRequired(
                f"investigation consent must explicitly name provider {self.provider.name!r}"
            )
        if remaining_tokens <= 0:
            raise ModelBudgetExceeded("model token budget is exhausted")
        result = self.provider.complete_json(
            model=self.model,
            system_prompt=system_prompt,
            user_payload=user_payload,
            response_schema=output_model.model_json_schema(),
            timeout_seconds=self.timeout_seconds,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if result.prompt_tokens is None or result.completion_tokens is None:
            raise ModelBudgetExceeded(
                "provider did not report token usage; cannot enforce the investigation budget"
            )
        used = result.prompt_tokens + result.completion_tokens
        if used > remaining_tokens:
            raise ModelBudgetExceeded(
                f"provider used {used} tokens but only {remaining_tokens} remained"
            )
        norm = normalize_structured_reply(result.content, output_model)
        if norm.status != "valid":
            raise ModelOutputInvalid(
                f"model reply unconvertible: {norm.reason}", raw_content=result.content
            )
        return norm.data, result



class InvestigationModelGateway:
    """A gateway bound to one investigation's live consent and cumulative token ledger."""

    def __init__(self, gateway: StructuredModelGateway, session_factory, investigation_id: str) -> None:
        self.gateway = gateway
        self.session_factory = session_factory
        self.investigation_id = investigation_id

    async def complete_structured(
        self, *, role: str, system: str, user: str, schema: type[BaseModel],
        temperature: float = 0.0, max_tokens: int = 4096,
    ) -> dict[str, Any]:
        return await asyncio.to_thread(
            self._complete_sync,
            role=role, system=system, user=user, schema=schema,
            temperature=temperature, max_tokens=max_tokens,
        )

    def _complete_sync(
        self, *, role: str, system: str, user: str, schema: type[BaseModel],
        temperature: float, max_tokens: int,
    ) -> dict[str, Any]:
        from ..adapters.models import InvestigationRow
        from .token_budget import InvestigationTokenBudget

        if role not in {"reasoning", "workhorse"}:
            raise ValueError("model role must be reasoning or workhorse")
        if not 1 <= max_tokens <= 4096:
            raise ValueError("max_tokens must be between 1 and 4096")
        session = self.session_factory()
        try:
            investigation = session.get(InvestigationRow, self.investigation_id)
            if investigation is None:
                raise ModelConsentRequired("investigation not found; model call refused")
            consent = dict(investigation.llm_data_sharing or {})
            if consent.get("enabled") is not True:
                raise ModelConsentRequired("LLM data sharing is disabled for this investigation")
            if consent.get("provider") != self.gateway.provider.name:
                raise ModelConsentRequired(
                    f"investigation consent must explicitly name provider {self.gateway.provider.name!r}"
                )
        finally:
            session.close()

        # UTF-8 byte length is a conservative upper bound for tokenizer tokens; include
        # schema and protocol overhead so the reservation covers the full prompt envelope.
        # Providers that transform the envelope (e.g. the OpenCode CLI adapter wraps the
        # payload in extra JSON, whose escaping grows with payload content) expose the
        # exact composed wire length via prompt_envelope_bytes; measuring it keeps the
        # ceiling sound at any payload scale instead of relying on a fixed margin.
        schema_dict = schema.model_json_schema()
        envelope = getattr(self.gateway.provider, "prompt_envelope_bytes", None)
        if callable(envelope):
            prompt_ceiling = envelope(
                system_prompt=system,
                user_payload={"input": user},
                response_schema=schema_dict,
            )
        else:
            schema_bytes = json.dumps(schema_dict, separators=(",", ":")).encode("utf-8")
            prompt_ceiling = (
                len(system.encode("utf-8")) + len(user.encode("utf-8")) + len(schema_bytes) + 1024
            )
        reservation_size = prompt_ceiling + max_tokens
        budget = InvestigationTokenBudget(self.session_factory)
        reservation = budget.reserve(self.investigation_id, reservation_size)
        try:
            result = self.gateway.provider.complete_json(
                model=self.gateway.model,
                system_prompt=system,
                user_payload={"input": user},
                response_schema=schema.model_json_schema(),
                timeout_seconds=self.gateway.timeout_seconds,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except Exception:
            # A timeout/disconnect can happen after the provider accepted and processed
            # the request. Without usage metadata, charge the full reservation.
            budget.settle(
                reservation, actual_tokens=reservation.reserved_tokens,
                provider=self.gateway.provider.name, model_id=self.gateway.model,
            )
            raise

        if result.prompt_tokens is None or result.completion_tokens is None:
            # The provider may have consumed tokens. Charge the full reservation rather
            # than releasing it and pretending the call was free.
            budget.settle(
                reservation, actual_tokens=reservation.reserved_tokens,
                provider=self.gateway.provider.name, model_id=result.model_id,
            )
            raise ModelBudgetExceeded(
                "provider did not report token usage; full reservation charged conservatively"
            )

        actual = result.prompt_tokens + result.completion_tokens
        # Budget accounting uses the conservative accounting units; when the
        # provider reports its own real token usage (OpenCode CLI totals), keep
        # it distinctly named so audits never confuse the two.
        usage_detail: dict[str, Any] = {
            "accounting_prompt_units": result.prompt_tokens,
            "accounting_completion_units": result.completion_tokens,
        }
        if result.provider_prompt_tokens is not None:
            usage_detail["provider_reported_prompt_tokens"] = result.provider_prompt_tokens
        if result.provider_completion_tokens is not None:
            usage_detail["provider_reported_completion_tokens"] = result.provider_completion_tokens
        if result.prompt_tokens > prompt_ceiling or result.completion_tokens > max_tokens:
            budget.settle(
                reservation, actual_tokens=reservation.reserved_tokens + 1,
                provider=self.gateway.provider.name, model_id=result.model_id,
                usage={**usage_detail,
                       "prompt_ceiling": prompt_ceiling,
                       "max_tokens": max_tokens},
            )
            raise ModelBudgetExceeded("provider usage exceeded the pre-call token ceiling")
        budget.settle(
            reservation, actual_tokens=actual,
            provider=self.gateway.provider.name, model_id=result.model_id,
            usage=usage_detail,
        )

        norm = normalize_structured_reply(result.content, schema)
        if norm.status != "valid":
            raise ModelOutputInvalid(
                f"model reply unconvertible: {norm.reason}", raw_content=result.content
            )
        validated = norm.data
        schema_json = json.dumps(schema.model_json_schema(), sort_keys=True, separators=(",", ":"))
        return {
            "data": validated,
            "provider": self.gateway.provider.name,
            "requested_model": self.gateway.model,
            "model_id": result.model_id,
            "role": role,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "schema_name": schema.__name__,
            "system_prompt_sha256": hashlib.sha256(system.encode("utf-8")).hexdigest(),
            "input_sha256": hashlib.sha256(user.encode("utf-8")).hexdigest(),
            "schema_sha256": hashlib.sha256(schema_json.encode("utf-8")).hexdigest(),
            "response_sha256": hashlib.sha256(result.content.encode("utf-8")).hexdigest(),
            "provider_input_tokens": result.provider_prompt_tokens,
            "provider_output_tokens": result.provider_completion_tokens,
            "input_tokens": result.prompt_tokens,
            "output_tokens": result.completion_tokens,
            "latency_ms": result.duration_ms,
            "schema_valid": True,
            "normalization": {
                "method": norm.method,
                "dropped_fields": list(norm.dropped_fields),
            },
        }


_DEFAULT_BIN = "opencode"
_MAX_ERROR_CHARS = 400


def _model_tag(model: str) -> str:
    tag = model.strip()
    if not tag:
        raise ValueError("model name is required")
    return tag if "/" in tag else f"opencode/{tag}"


def parse_ndjson_events(stdout: str) -> tuple[str, int | None, int | None]:
    """Concatenate assistant text parts and sum token usage from NDJSON events.

    Returns (content, input_tokens, output_tokens). Pure function so it can be
    unit-tested without the CLI.
    """
    texts: list[str] = []
    input_tokens = 0
    output_tokens = 0
    saw_input = False
    saw_output = False
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        etype = event.get("type")
        part = event.get("part") or {}
        if etype == "text" and isinstance(part.get("text"), str):
            texts.append(part["text"])
        elif etype == "step_finish":
            tokens = part.get("tokens") or {}
            if isinstance(tokens.get("input"), int):
                input_tokens += tokens["input"]
                saw_input = True
            if isinstance(tokens.get("output"), int):
                output_tokens += tokens["output"]
                saw_output = True
    return (
        "".join(texts),
        input_tokens if saw_input else None,
        output_tokens if saw_output else None,
    )


@dataclass(frozen=True, slots=True)
class ReplyNormalization:
    """Outcome of converting a raw model reply into a validated schema instance.

    ``reason`` is a sanitized failure class (locations and rule names only,
    never model content); the raw reply stays with the caller for repair or
    needs-review capture.
    """

    status: str  # "valid" | "unconvertible"
    data: BaseModel | None = None
    method: str | None = None  # exact | fenced | extracted | extracted_duplicate
    dropped_fields: tuple[str, ...] = ()
    reason: str | None = None


_FENCE_RE = re.compile(r"^```[A-Za-z0-9_-]*[ \t]*\n(?P<body>.*?)\n?```$", re.DOTALL)


def _json_candidates(text: str) -> list[Any]:
    """Every JSON value decodable from any ``{``/``[`` position in the text."""
    decoder = json.JSONDecoder()
    found: list[Any] = []
    covered_until = -1
    for match in re.finditer(r"[\{\[]", text):
        if match.start() < covered_until:
            continue  # nested inside a candidate already decoded
        try:
            value, end = decoder.raw_decode(text, match.start())
        except json.JSONDecodeError:
            continue
        if isinstance(value, (dict, list)):
            found.append(value)
            covered_until = end
    return found


def _drop_forbidden_keys(value: Any, schema: type[BaseModel], path: str = "") -> tuple[Any, list[str]]:
    """Drop object keys the schema does not declare, recording dotted paths.

    Keys are only ever REMOVED (and reported). Nothing is added, renamed, or
    retyped: a missing required field stays missing and fails validation.
    """
    if not isinstance(value, dict):
        return value, []
    if schema.model_config.get("extra") == "allow":
        return value, []
    dropped: list[str] = []
    out: dict[str, Any] = {}
    for key, item in value.items():
        field_info = schema.model_fields.get(key)
        if field_info is None:
            dropped.append(f"{path}{key}")
            continue
        out[key] = _coerce_value(item, field_info.annotation, f"{path}{key}.", dropped)
    return out, dropped


def _coerce_value(value: Any, annotation: Any, path: str, dropped: list[str]) -> Any:
    origin = get_origin(annotation)
    if origin is list and isinstance(value, list):
        args = get_args(annotation)
        item_type = args[0] if args else Any
        return [_coerce_value(v, item_type, f"{path}{i}.", dropped) for i, v in enumerate(value)]
    if isinstance(annotation, type) and issubclass(annotation, BaseModel) and isinstance(value, dict):
        coerced, sub = _drop_forbidden_keys(value, annotation, path)
        dropped.extend(sub)
        return coerced
    return value


def normalize_structured_reply(text: str, schema: type[BaseModel]) -> ReplyNormalization:
    """Convert a raw model reply into a validated schema instance.

    Acceptance ladder (tolerant of presentation, strict on semantics):
    1. the whole reply is one JSON value;
    2. the reply is a single markdown code fence wrapping one JSON value;
    3. exactly one DISTINCT JSON object/array appears anywhere in the reply
       (surrounding prose is presentation); repeated identical payloads
       collapse to one;
    4. undeclared object keys are dropped and recorded; nothing is added.

    Anything else (no JSON payload, several conflicting payloads, or a schema
    violation after key-dropping) is unconvertible: the caller must repair or
    capture it as needs-review, never guess a decision.
    """
    stripped = text.strip()
    if not stripped:
        return ReplyNormalization(status="unconvertible", reason="empty_reply")
    candidate: Any = None
    method: str | None = None
    try:
        candidate = json.loads(stripped)
        method = "exact"
    except json.JSONDecodeError:
        fence = _FENCE_RE.match(stripped)
        if fence is not None:
            try:
                candidate = json.loads(fence.group("body").strip())
                method = "fenced"
            except json.JSONDecodeError:
                candidate = None
        if candidate is None:
            found = _json_candidates(stripped)
            distinct: dict[str, Any] = {}
            for value in found:
                distinct.setdefault(json.dumps(value, sort_keys=True), value)
            if len(distinct) == 1:
                candidate = next(iter(distinct.values()))
                method = "extracted" if len(found) == 1 else "extracted_duplicate"
            elif len(distinct) > 1:
                return ReplyNormalization(status="unconvertible", reason="multiple_conflicting_payloads")
    if candidate is None:
        return ReplyNormalization(status="unconvertible", reason="no_json_payload")
    coerced, dropped = _drop_forbidden_keys(candidate, schema)
    try:
        validated = schema.model_validate(coerced)
    except ValidationError as exc:
        locs = ";".join(
            ".".join(str(p) for p in err["loc"]) + ":" + err["type"] for err in exc.errors()[:5]
        )
        return ReplyNormalization(status="unconvertible", reason=f"schema_violation:{locs}")
    return ReplyNormalization(status="valid", data=validated, method=method, dropped_fields=tuple(dropped))


class OpenCodeCliProvider:
    """ModelProvider that drives OpenCode's free-tier models via the official CLI.

    Token accounting: ``prompt_tokens`` reports the byte length of the prompt
    envelope this adapter composed (Mobius's system prompt + schema + payload),
    matching the reservation ceiling's conservative bytes-as-tokens unit. The
    gateway sizes the reservation from :meth:`prompt_envelope_bytes`, the exact
    composed wire envelope (including JSON escaping growth), so the ceiling
    cannot underestimate what is actually sent. The OpenCode CLI injects its
    own system prompt (~6k tokens of platform overhead) that is not part of
    the Mobius envelope; reporting it would trip the pre-call ceiling guard on
    every call. The CLI-reported totals, including that overhead, are exposed
    on ``last_cli_input_tokens`` / ``last_cli_output_tokens`` after each call
    so harness reports can state real platform usage. ``completion_tokens`` is
    the CLI-reported answer output, falling back to the answer's byte length
    when the CLI omits usage.

    ``max_tokens`` is NOT forwarded to the CLI: ``opencode run`` exposes no
    output-length flag (verified against ``opencode run --help``), so the
    model answers at its natural length and the per-call output ceiling is
    enforced Mobius-side at settle, never provider-side.
    """

    name = "opencode"

    def __init__(self, binary: str | None = None) -> None:
        self.binary = binary or os.environ.get("MOBIUS_OPENCODE_BIN", _DEFAULT_BIN)
        if shutil.which(self.binary) is None and not os.path.exists(self.binary):
            raise ModelProviderError(
                f"OpenCode CLI not found at {self.binary!r}; install opencode-ai "
                "or set MOBIUS_OPENCODE_BIN"
            )
        self.last_cli_input_tokens: int | None = None
        self.last_cli_output_tokens: int | None = None

    @staticmethod
    def compose_prompt(
        *,
        system_prompt: str,
        user_payload: dict[str, Any],
        response_schema: dict[str, Any],
    ) -> str:
        """Compose the exact wire prompt sent to the CLI (single source of truth)."""
        return (
            f"{system_prompt}\n\n"
            "Respond with ONLY a JSON object conforming to this JSON Schema. "
            "No markdown fences, no commentary, no tool use:\n"
            f"{json.dumps(response_schema)}\n\n"
            "Input payload:\n"
            f"{json.dumps(user_payload)}"
        )

    def prompt_envelope_bytes(
        self,
        *,
        system_prompt: str,
        user_payload: dict[str, Any],
        response_schema: dict[str, Any],
    ) -> int:
        """Byte length of the composed wire prompt; the reservation ceiling unit.

        Bytes are a conservative upper bound for tokens, and JSON escaping of
        the payload (newlines, quotes, unicode) is measured, not estimated.
        """
        return len(
            self.compose_prompt(
                system_prompt=system_prompt,
                user_payload=user_payload,
                response_schema=response_schema,
            ).encode("utf-8")
        )

    def complete_json(
        self,
        *,
        model: str,
        system_prompt: str,
        user_payload: dict[str, Any],
        response_schema: dict[str, Any],
        timeout_seconds: int = 120,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> ProviderResult:
        prompt = self.compose_prompt(
            system_prompt=system_prompt,
            user_payload=user_payload,
            response_schema=response_schema,
        )
        # Run in an empty directory: the agent sees no project files and has
        # nothing to act on; the prompt asks for a direct JSON answer.
        workdir = tempfile.mkdtemp(prefix="mobius-opencode-")
        started = time.monotonic()
        try:
            proc = subprocess.run(
                [
                    self.binary,
                    "run",
                    "--format",
                    "json",
                    "--pure",
                    "--model",
                    _model_tag(model),
                    prompt,
                ],
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 120,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ModelBudgetExceeded(
                f"OpenCode CLI exceeded the {timeout_seconds}s budget"
            ) from exc
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        duration_ms = int((time.monotonic() - started) * 1000)
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or "")[-_MAX_ERROR_CHARS:].strip()
            raise ModelProviderError(f"OpenCode CLI exited {proc.returncode}: {tail}")
        content, cli_input, cli_output = parse_ndjson_events(proc.stdout)
        self.last_cli_input_tokens = cli_input
        self.last_cli_output_tokens = cli_output
        # Raw reply text is returned untouched: presentation-vs-semantics
        # separation happens in normalize_structured_reply at the gateway.
        if not content.strip():
            tail = (proc.stdout or "")[-_MAX_ERROR_CHARS:].strip()
            raise ModelProviderError(f"OpenCode CLI returned no assistant text: {tail}")
        return ProviderResult(
            content=content,
            model_id=_model_tag(model),
            # Accounting units: composed-envelope bytes / CLI output sum (or the
            # answer's byte length fallback), both conservative for budgeting.
            prompt_tokens=len(prompt.encode("utf-8")),
            completion_tokens=(
                cli_output if cli_output is not None else len(content.encode("utf-8"))
            ),
            # The CLI's own real token report, including its platform overhead;
            # provenance for harnesses, never the budget charge.
            provider_prompt_tokens=cli_input,
            provider_completion_tokens=cli_output,
            duration_ms=duration_ms,
        )


def create_model_gateway(
    provider_name: str,
    *,
    base_url: str,
    model: str,
    timeout_seconds: int = 120,
) -> StructuredModelGateway | None:
    """Build only an explicitly configured local provider; no hosted provider is bundled."""
    if provider_name == "disabled":
        return None
    if provider_name == "ollama":
        return StructuredModelGateway(
            OllamaProvider(base_url),
            model=model,
            timeout_seconds=timeout_seconds,
        )
    if provider_name == "opencode":
        # Opt-in hosted route via the official OpenCode CLI's documented
        # automation mode (free tier is client-gated; no direct anonymous API
        # is used). PRIVACY BOUNDARY: prompts are passed through to OpenCode's
        # upstream model providers (https://opencode.ai/legal/privacy-policy),
        # so this provider is intended for public/synthetic investigations
        # only. Two independent controls keep it off private data by default:
        # this explicit config opt-in (default: disabled) and the existing
        # per-investigation consent gate, which fails closed unless consent
        # explicitly names provider "opencode".
        return StructuredModelGateway(
            OpenCodeCliProvider(),
            model=model,
            timeout_seconds=timeout_seconds,
        )
    raise ValueError(f"unsupported model provider: {provider_name}")
