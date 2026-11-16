"""Local-only structured model provider boundary.

Providers return typed JSON, never executable tool calls. The gateway requires per-scan
consent and validates every response against a caller-supplied Pydantic contract.
"""
from __future__ import annotations

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
    ) -> ProviderResult:
        if not model.strip():
            raise ValueError("model name is required")
        body = json.dumps({
            "model": model,
            "stream": False,
            "format": response_schema,
            "options": {"temperature": 0.1},
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


class ModelGateway:
    """Consent-gated provider call with strict output and token-budget validation."""

    def __init__(self, provider: ModelProvider, *, model: str, timeout_seconds: int = 120) -> None:
        if not model.strip():
            raise ValueError("model name is required")
        if not 1 <= timeout_seconds <= 900:
            raise ValueError("model timeout must be between 1 and 900 seconds")
        self.provider = provider
        self.model = model
        self.timeout_seconds = timeout_seconds

    def generate(
        self,
        *,
        output_model: type[BaseModel],
        system_prompt: str,
        user_payload: dict[str, Any],
        consent_enabled: bool,
        consent_provider: str | None,
        remaining_tokens: int,
    ) -> tuple[BaseModel, ProviderResult]:
        if not consent_enabled:
            raise ModelConsentRequired("LLM data sharing is disabled for this investigation")
        if consent_provider != self.provider.name:
            raise ModelConsentRequired(
                f"investigation consent must explicitly name provider {self.provider.name!r}"
            )
        if remaining_tokens < 0:
            raise ModelBudgetExceeded("model token budget is exhausted")
        result = self.provider.complete_json(
            model=self.model,
            system_prompt=system_prompt,
            user_payload=user_payload,
            response_schema=output_model.model_json_schema(),
            timeout_seconds=self.timeout_seconds,
        )
        used = (result.prompt_tokens or 0) + (result.completion_tokens or 0)
        if used and used > remaining_tokens:
            raise ModelBudgetExceeded(
                f"provider used {used} tokens but only {remaining_tokens} remained"
            )
        try:
            parsed = json.loads(result.content)
            validated = output_model.model_validate(parsed)
        except (ValueError, ValidationError) as exc:
            raise ModelOutputInvalid("model output failed the requested JSON schema") from exc
        return validated, result
