"""Local-only structured model provider boundary.

Providers return typed JSON, never executable tool calls. The gateway requires per-scan
consent and validates every response against a caller-supplied Pydantic contract.
"""
from __future__ import annotations

import asyncio
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Generic, Protocol, TypeVar
from urllib.parse import urlsplit

from pydantic import BaseModel, ValidationError


class ModelProviderError(RuntimeError):
    pass


class ModelConsentRequired(ModelProviderError):
    pass


class ModelUnavailable(ModelProviderError):
    pass


class ModelOutputInvalid(ModelProviderError):
    pass


class ModelBudgetExceeded(ModelProviderError):
    pass


@dataclass(frozen=True, slots=True)
class ProviderResult:
    content: str
    model_id: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
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
        try:
            parsed = json.loads(result.content)
            validated = output_model.model_validate(parsed)
        except (ValueError, ValidationError) as exc:
            raise ModelOutputInvalid("model output failed the requested JSON schema") from exc
        return validated, result


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
    raise ValueError(f"unsupported model provider: {provider_name}")
