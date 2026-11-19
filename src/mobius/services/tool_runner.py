"""Fail-closed tool execution boundary.

This module deliberately does not spawn processes. A deployment must inject a backend
that provides OS/container isolation and reports that isolation as ready. This prevents
an API-process subprocess wrapper from being mistaken for a sandbox.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

_SCAN_ID = re.compile(r"^scn_[0-9A-HJKMNP-TV-Z]{26}$")
_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")


class ToolRunnerError(RuntimeError):
    """Base class for a rejected or unavailable tool invocation."""


class ToolUnavailable(ToolRunnerError):
    """The requested tool or an isolation-capable backend is unavailable."""


class ToolRejected(ToolRunnerError):
    """The request violates the registered tool contract or execution policy."""


class ToolLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    timeout_seconds: int = Field(default=60, ge=1, le=900)
    memory_mb: int = Field(default=1024, ge=64, le=8192)
    cpu_seconds: int = Field(default=60, ge=1, le=900)
    max_output_bytes: int = Field(default=2_000_000, ge=1024, le=20_000_000)
    network_enabled: bool = False


class ToolSpec:
    """Trusted server-side registration; never construct from model/user input."""

    def __init__(
        self,
        *,
        name: str,
        binary: str,
        version: str,
        args_model: type[BaseModel],
        build_argv: Callable[[BaseModel], tuple[str, ...]],
        limits: ToolLimits | None = None,
    ) -> None:
        if not _TOOL_NAME.fullmatch(name):
            raise ValueError("invalid tool name")
        binary_path = Path(binary)
        if not binary_path.is_absolute():
            raise ValueError("tool binary must be an absolute server-configured path")
        if not version.strip():
            raise ValueError("tool version must be pinned or explicitly identified")
        self.name = name
        self.binary = str(binary_path)
        self.version = version
        self.args_model = args_model
        self.build_argv = build_argv
        self.limits = limits or ToolLimits()

    def argv_for(self, payload: dict[str, object]) -> tuple[str, ...]:
        try:
            validated = self.args_model.model_validate(payload)
        except ValidationError as exc:
            raise ToolRejected("tool arguments failed schema validation") from exc
        argv = self.build_argv(validated)
        if not isinstance(argv, tuple) or not argv:
            raise ToolRejected("registered argv builder must return a non-empty tuple")
        if any(not isinstance(part, str) or not part or "\x00" in part for part in argv):
            raise ToolRejected("argv contains an invalid argument")
        # The executable is always supplied by trusted registration, never by the caller.
        if argv[0] != self.binary:
            raise ToolRejected("argv builder attempted to replace the registered executable")
        return argv


@dataclass(frozen=True, slots=True)
class BackendResult:
    status: str
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    duration_ms: int


class IsolatedExecutionBackend(Protocol):
    """An implementation backed by a real isolation boundary (e.g. hardened container)."""

    @property
    def isolation_ready(self) -> bool: ...

    def execute(
        self,
        *,
        argv: tuple[str, ...],
        workspace: Path,
        limits: ToolLimits,
    ) -> BackendResult: ...


@dataclass(frozen=True, slots=True)
class ToolRun:
    tool: str
    version: str
    status: str
    exit_code: int | None
    stdout: bytes
    stderr_tail: str
    duration_ms: int
    truncated: bool


class ToolRunner:
    """Closed-registry dispatcher; refuses execution without verified isolation."""

    def __init__(
        self,
        *,
        workspace_root: Path,
        backend: IsolatedExecutionBackend | None,
        tools: tuple[ToolSpec, ...] = (),
    ) -> None:
        self.workspace_root = workspace_root.resolve()
        self.backend = backend
        self._tools: dict[str, ToolSpec] = {}
        for spec in tools:
            if spec.name in self._tools:
                raise ValueError(f"duplicate tool registration: {spec.name}")
            self._tools[spec.name] = spec

    def invoke(
        self,
        *,
        investigation_id: str,
        tool: str,
        args: dict[str, object],
    ) -> ToolRun:
        if not _SCAN_ID.fullmatch(investigation_id):
            raise ToolRejected("invalid investigation identifier")
        spec = self._tools.get(tool)
        if spec is None:
            raise ToolUnavailable(f"tool is not registered: {tool}")
        if self.backend is None or not self.backend.isolation_ready:
            raise ToolUnavailable("no verified isolated execution backend is configured")

        argv = spec.argv_for(args)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        root = self.workspace_root.resolve()
        workspace = root / investigation_id
        # Refuse symlink/path tricks and keep each investigation in its own directory.
        if workspace.exists() and workspace.is_symlink():
            raise ToolRejected("investigation workspace must not be a symlink")
        workspace.mkdir(mode=0o700, parents=False, exist_ok=True)
        resolved = workspace.resolve()
        if resolved.parent != root:
            raise ToolRejected("workspace escaped the configured root")
        # File-output tools (JADX) run their container as fixed uid 65532, which must be
        # able to write outputs/. A non-root worker cannot chown to that uid, so outputs/
        # is sticky world-writable (1777, the /tmp pattern) inside the owner-only
        # workspace: host-level privacy is enforced by the 0700 parent, and the sticky bit
        # stops cross-entry deletion. Created for every job so the backend can mount it
        # when the tool's contract needs it; stdout-only tools never see it mounted.
        outputs = resolved / "outputs"
        if outputs.is_symlink():
            raise ToolRejected("investigation outputs path must not be a symlink")
        outputs.mkdir(parents=False, exist_ok=True)
        outputs.chmod(0o1777)

        result = self.backend.execute(argv=argv, workspace=resolved, limits=spec.limits)
        if result.status not in {"ok", "error", "timeout", "killed", "unavailable"}:
            raise ToolRejected("isolation backend returned an unknown status")
        max_bytes = spec.limits.max_output_bytes
        stdout = result.stdout[:max_bytes]
        stderr = result.stderr[-16_384:]
        return ToolRun(
            tool=spec.name,
            version=spec.version,
            status=result.status,
            exit_code=result.exit_code,
            stdout=stdout,
            stderr_tail=stderr.decode("utf-8", errors="replace"),
            duration_ms=max(0, result.duration_ms),
            truncated=len(result.stdout) > max_bytes,
        )
