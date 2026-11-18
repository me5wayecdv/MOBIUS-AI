"""JADX decompilation adapter with digest/version-addressed, verified caching.

The adapter delegates execution to ToolRunner. It never starts a process itself; production
callers must register the binary with a verified, digest-pinned isolated backend.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..services.tool_runner import (
    ToolLimits,
    ToolRejected,
    ToolRunner,
    ToolUnavailable,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_SCAN_ID = re.compile(r"^scn_[0-9A-HJKMNP-TV-Z]{26}$")
_MAX_SOURCE_FILES = 10_000
_MAX_SOURCE_BYTES = 64 * 1024 * 1024
_MAX_SNIPPET_LINES = 40


class JadxError(RuntimeError):
    """Base class for an explicit JADX/cache failure."""

    def __init__(self, status: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class JadxUnavailable(JadxError):
    """JADX or its verified isolated execution backend is unavailable."""


class JadxExecutionFailed(JadxError):
    """JADX returned a non-success result or produced invalid output."""


class JadxCacheError(JadxError):
    """A cache entry failed integrity or path validation."""


class _JadxArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    input_file: str = Field(pattern=r"^input\.(?:apk|dex)$")
    output_dir: str = Field(pattern=r"^jadx-output-[0-9a-f]{12}$")


def build_jadx_tool_spec(
    *, binary: str = "/opt/jadx/bin/jadx", version: str = "1.5.6",
    name: str = "jadx.decompile",
):
    """Build the trusted server-side ToolSpec for the pinned JADX executable."""
    from ..services.tool_runner import ToolSpec

    return ToolSpec(
        name=name,
        binary=binary,
        version=version,
        args_model=_JadxArgs,
        build_argv=lambda args: (
            binary, "--no-res", "-d", f"/work/{args.output_dir}",
            f"/work/{args.input_file}",
        ),
        limits=ToolLimits(
            timeout_seconds=300,
            memory_mb=4096,
            cpu_seconds=300,
            max_output_bytes=1024 * 1024,
            network_enabled=False,
        ),
    )


@dataclass(frozen=True, slots=True)
class JadxResult:
    apk_sha256: str
    tool_version: str
    cache_dir: Path
    source_files: tuple[str, ...]
    cached: bool
    fidelity: str = "decompiled"


@dataclass(frozen=True, slots=True)
class SourceSnippet:
    path: str
    start_line: int
    end_line: int
    text: str
    fidelity: str = "decompiled"


class JadxAdapter:
    """Run JADX through ToolRunner and cache verified source output by APK SHA-256 + version."""

    def __init__(
        self, *, runner: ToolRunner, cache_root: Path, tool_version: str = "1.5.6",
        tool_name: str = "jadx.decompile",
    ) -> None:
        if not _VERSION.fullmatch(tool_version):
            raise ValueError("JADX version must be an explicit safe version identifier")
        self.runner = runner
        self.cache_root = Path(cache_root).absolute()
        self.tool_version = tool_version
        self.tool_name = tool_name

    def decompile(
        self, *, investigation_id: str, artifact: bytes,
        expected_sha256: str | None = None, artifact_name: str = "input.apk",
    ) -> JadxResult:
        if not _SCAN_ID.fullmatch(investigation_id):
            raise JadxError("invalid_input", "invalid investigation identifier")
        if not isinstance(artifact, bytes) or not artifact:
            raise JadxError("invalid_input", "APK/DEX artifact must be non-empty bytes")
        if artifact_name not in {"input.apk", "input.dex"}:
            raise JadxError("invalid_input", "artifact_name must be input.apk or input.dex")

        digest = hashlib.sha256(artifact).hexdigest()
        if expected_sha256 is not None:
            if not _SHA256.fullmatch(expected_sha256) or expected_sha256 != digest:
                raise JadxError("digest_mismatch", "artifact SHA-256 does not match the authorized digest")

        self.cache_root.mkdir(parents=True, exist_ok=True)
        if self.cache_root.is_symlink():
            raise JadxCacheError("unsafe_cache", "cache root must not be a symlink")
        cache_root = self.cache_root.resolve(strict=True)
        version_key = self.tool_version
        apk_root = cache_root / digest
        apk_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if apk_root.is_symlink() or apk_root.resolve().parent != cache_root:
            raise JadxCacheError("unsafe_cache", "APK cache path escaped the configured root")
        entry = apk_root / version_key
        lock_path = apk_root / f".{version_key}.lock"
        if lock_path.is_symlink():
            raise JadxCacheError("unsafe_cache", "cache lock must not be a symlink")

        try:
            with lock_path.open("a+b") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                cached = self._read_cache(entry, digest)
                if cached is not None:
                    return cached

                output_dir_name = "jadx-output-" + hashlib.sha256(
                    self.tool_version.encode("utf-8")
                ).hexdigest()[:12]
                workspace_root = self.runner.workspace_root
                workspace_root.mkdir(parents=True, exist_ok=True)
                workspace = workspace_root / investigation_id
                if workspace.exists() and workspace.is_symlink():
                    raise JadxExecutionFailed("unsafe_workspace", "investigation workspace must not be a symlink")
                workspace.mkdir(mode=0o700, parents=False, exist_ok=True)
                if workspace.resolve().parent != workspace_root.resolve():
                    raise JadxExecutionFailed("unsafe_workspace", "investigation workspace escaped its root")

                input_path = workspace / artifact_name
                if input_path.is_symlink():
                    raise JadxExecutionFailed("unsafe_workspace", "staged artifact must not be a symlink")
                if input_path.exists():
                    if not input_path.is_file() or hashlib.sha256(input_path.read_bytes()).hexdigest() != digest:
                        raise JadxExecutionFailed("workspace_conflict", "workspace already contains a different input artifact")
                else:
                    with input_path.open("xb") as stream:
                        stream.write(artifact)
                    input_path.chmod(0o444)

                output_path = workspace / output_dir_name
                if output_path.exists() or output_path.is_symlink():
                    raise JadxExecutionFailed("workspace_conflict", "JADX output path already exists; refusing to overwrite it")

                try:
                    run = self.runner.invoke(
                        investigation_id=investigation_id,
                        tool=self.tool_name,
                        args={"input_file": artifact_name, "output_dir": output_dir_name},
                    )
                except ToolUnavailable as exc:
                    raise JadxUnavailable("tool_unavailable", str(exc)) from exc
                except ToolRejected as exc:
                    raise JadxExecutionFailed("tool_rejected", str(exc)) from exc

                if run.version != self.tool_version:
                    raise JadxExecutionFailed("version_mismatch", "registered JADX version differs from the adapter cache version")
                if run.status != "ok" or run.exit_code != 0 or run.truncated:
                    raise JadxExecutionFailed(
                        run.status if run.status != "ok" else "nonzero_exit",
                        f"JADX failed (status={run.status}, exit_code={run.exit_code}, "
                        f"truncated={run.truncated}): {run.stderr_tail[-4096:]}",
                    )

                source_root = output_path / "sources"
                files = self._collect_sources(source_root)
                if not files:
                    raise JadxExecutionFailed("empty_output", "JADX completed without producing Java or smali source files")

                return self._write_cache(
                    entry=entry, digest=digest, source_root=source_root, files=files,
                )
        except OSError as exc:
            raise JadxExecutionFailed("io_error", f"JADX cache/workspace I/O failed: {exc}") from exc

    @staticmethod
    def _collect_sources(source_root: Path) -> list[Path]:
        if source_root.is_symlink() or not source_root.is_dir():
            raise JadxExecutionFailed("invalid_output", "JADX sources directory is missing or unsafe")
        root = source_root.resolve(strict=True)
        files: list[Path] = []
        total_bytes = 0
        for current, dirs, names in os.walk(root, followlinks=False):
            current_path = Path(current)
            for name in list(dirs):
                child = current_path / name
                if child.is_symlink():
                    raise JadxExecutionFailed("invalid_output", "JADX output contains a symlink directory")
            for name in names:
                path = current_path / name
                if path.is_symlink() or not path.is_file():
                    raise JadxExecutionFailed("invalid_output", "JADX output contains a non-regular file")
                if path.suffix not in {".java", ".smali"}:
                    continue
                size = path.stat().st_size
                total_bytes += size
                files.append(path)
                if len(files) > _MAX_SOURCE_FILES or total_bytes > _MAX_SOURCE_BYTES:
                    raise JadxExecutionFailed("output_limit", "JADX source output exceeded the file-count or byte budget")
        return sorted(files)

    def _write_cache(
        self, *, entry: Path, digest: str, source_root: Path, files: list[Path],
    ) -> JadxResult:
        entry.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temp = Path(tempfile.mkdtemp(prefix=".jadx-cache-", dir=entry.parent))
        try:
            cached_sources = temp / "sources"
            cached_sources.mkdir(mode=0o700)
            manifest_files: list[dict[str, Any]] = []
            relative_names: list[str] = []
            root = source_root.resolve(strict=True)
            for source in files:
                relative = source.resolve(strict=True).relative_to(root).as_posix()
                pure = PurePosixPath(relative)
                if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
                    raise JadxCacheError("unsafe_source_path", "JADX returned an unsafe source path")
                target = cached_sources.joinpath(*pure.parts)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                data = target.read_bytes()
                manifest_files.append({
                    "path": relative,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                })
                relative_names.append(relative)
            manifest = {
                "schema_version": 1,
                "apk_sha256": digest,
                "tool_version": self.tool_version,
                "source_files": manifest_files,
            }
            (temp / "manifest.json").write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            if entry.exists() or entry.is_symlink():
                raise JadxCacheError("cache_conflict", "cache entry appeared during locked write; refusing to replace it")
            os.replace(temp, entry)
            return JadxResult(digest, self.tool_version, entry / "sources", tuple(relative_names), False)
        finally:
            if temp.exists():
                shutil.rmtree(temp)

    def _read_cache(self, entry: Path, digest: str) -> JadxResult | None:
        if not entry.exists() and not entry.is_symlink():
            return None
        if entry.is_symlink() or not entry.is_dir():
            raise JadxCacheError("corrupt_cache", "cache entry is not a regular directory")
        manifest_path = entry / "manifest.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise JadxCacheError("corrupt_cache", "cache manifest is missing or unsafe")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise JadxCacheError("corrupt_cache", "cache manifest cannot be read") from exc
        if not isinstance(manifest, dict):
            raise JadxCacheError("corrupt_cache", "cache manifest root must be an object")
        if (
            manifest.get("schema_version") != 1
            or manifest.get("apk_sha256") != digest
            or manifest.get("tool_version") != self.tool_version
            or not isinstance(manifest.get("source_files"), list)
        ):
            raise JadxCacheError("corrupt_cache", "cache manifest identity/schema mismatch")

        source_root = entry / "sources"
        if source_root.is_symlink() or not source_root.is_dir():
            raise JadxCacheError("corrupt_cache", "cached source directory is missing or unsafe")
        root = source_root.resolve(strict=True)
        names: list[str] = []
        total_bytes = 0
        for item in manifest["source_files"]:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise JadxCacheError("corrupt_cache", "cache manifest contains an invalid source entry")
            pure = PurePosixPath(item["path"])
            if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
                raise JadxCacheError("corrupt_cache", "cache manifest contains an unsafe source path")
            path = source_root.joinpath(*pure.parts)
            parent = source_root
            for part in pure.parts[:-1]:
                parent = parent / part
                if parent.is_symlink():
                    raise JadxCacheError("corrupt_cache", "cached source parent is a symlink")
            if path.is_symlink() or not path.is_file() or not path.resolve(strict=True).is_relative_to(root):
                raise JadxCacheError("corrupt_cache", "cached source reference does not resolve safely")
            data = path.read_bytes()
            total_bytes += len(data)
            if (
                hashlib.sha256(data).hexdigest() != item.get("sha256")
                or len(data) != item.get("size")
                or path.suffix not in {".java", ".smali"}
            ):
                raise JadxCacheError("corrupt_cache", "cached source failed integrity validation")
            names.append(pure.as_posix())
        if not names or len(names) != len(set(names)) or len(names) > _MAX_SOURCE_FILES or total_bytes > _MAX_SOURCE_BYTES:
            raise JadxCacheError("corrupt_cache", "cache source inventory is empty or exceeds limits")
        return JadxResult(digest, self.tool_version, source_root, tuple(sorted(names)), True)

    @staticmethod
    def resolve_source(
        result: JadxResult, *, relative_path: str, start_line: int, end_line: int,
    ) -> SourceSnippet:
        pure = PurePosixPath(relative_path)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            raise JadxError("invalid_reference", "source reference path is unsafe")
        if start_line < 1 or end_line < start_line or end_line - start_line + 1 > _MAX_SNIPPET_LINES:
            raise JadxError("invalid_reference", "source line range must contain 1 to 40 lines")
        if pure.as_posix() not in result.source_files:
            raise JadxError("source_not_found", "source reference is not present in the verified cache manifest")
        source_root = result.cache_dir.resolve(strict=True)
        path = source_root.joinpath(*pure.parts)
        parent = source_root
        for part in pure.parts[:-1]:
            parent = parent / part
            if parent.is_symlink():
                raise JadxCacheError("corrupt_cache", "decompiled source parent is a symlink")
        if path.is_symlink() or not path.is_file() or not path.resolve(strict=True).is_relative_to(source_root):
            raise JadxError("source_not_found", "decompiled source reference does not resolve")
        try:
            data = path.read_bytes()
            manifest = json.loads((source_root.parent / "manifest.json").read_text(encoding="utf-8"))
            record = next((item for item in manifest["source_files"] if item.get("path") == pure.as_posix()), None)
            if record is None or len(data) != record.get("size") or hashlib.sha256(data).hexdigest() != record.get("sha256"):
                raise JadxCacheError("corrupt_cache", "source reference failed cache integrity validation")
            lines = data.decode("utf-8").splitlines()
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise JadxError("source_unreadable", "decompiled source or cache manifest could not be read") from exc
        if end_line > len(lines):
            raise JadxError("line_range_invalid", "source reference line range exceeds the file")
        return SourceSnippet(
            path=pure.as_posix(), start_line=start_line, end_line=end_line,
            text="\n".join(lines[start_line - 1:end_line]),
        )
