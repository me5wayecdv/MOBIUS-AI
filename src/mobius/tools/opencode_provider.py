"""OpenCode CLI provider adapter for acceptance-harness evaluation only.

This module is EVAL TOOLING: it lets the VERITAS/NEXUS acceptance harnesses
measure OpenCode's free-tier models against the exact same acceptance bar as
the local Ollama mode, without changing any product code, default model, or
deployment. It is not wired into the product gateway or any investigation path.

The adapter shells out to the official OpenCode CLI's documented automation
mode (``opencode run --format json``, https://opencode.ai/docs/cli/) instead of
calling any HTTP endpoint directly: OpenCode's free tier is intended for use
from within the OpenCode client, and anonymous direct API access is rate
limited. Using the CLI respects that intended use; no workaround is attempted.

Privacy boundary: prompts are passed through to the upstream model provider by
OpenCode (https://opencode.ai/legal/privacy-policy), so only the harnesses'
synthetic/public fixtures may ever be sent through this adapter.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any

from ..services.model_provider import (
    ModelBudgetExceeded,
    ModelProviderError,
    ProviderResult,
)

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


class OpenCodeCliProvider:
    """ModelProvider that drives OpenCode's free-tier models via the official CLI.

    Token accounting: ``prompt_tokens`` reports the byte length of the prompt
    envelope this adapter composed (Mobius's system prompt + schema + payload),
    matching the reservation ceiling's conservative bytes-as-tokens unit. The
    OpenCode CLI injects its own system prompt (~6k tokens of platform
    overhead) that is not part of the Mobius envelope; reporting it would trip
    the pre-call ceiling guard on every call. The CLI-reported totals,
    including that overhead, are exposed on ``last_cli_input_tokens`` /
    ``last_cli_output_tokens`` after each call so harness reports can state
    real platform usage. ``completion_tokens`` is the CLI-reported answer
    output, falling back to the answer's byte length when the CLI omits usage.
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
        prompt = (
            f"{system_prompt}\n\n"
            "Respond with ONLY a JSON object conforming to this JSON Schema. "
            "No markdown fences, no commentary, no tool use:\n"
            f"{json.dumps(response_schema)}\n\n"
            "Input payload:\n"
            f"{json.dumps(user_payload)}"
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
        if not content.strip():
            tail = (proc.stdout or "")[-_MAX_ERROR_CHARS:].strip()
            raise ModelProviderError(f"OpenCode CLI returned no assistant text: {tail}")
        return ProviderResult(
            content=content,
            model_id=_model_tag(model),
            prompt_tokens=len(prompt.encode("utf-8")),
            completion_tokens=(
                cli_output if cli_output is not None else len(content.encode("utf-8"))
            ),
            duration_ms=duration_ms,
        )
