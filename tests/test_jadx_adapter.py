from __future__ import annotations

import hashlib
import os
import subprocess
import time
from pathlib import Path

import pytest

from mobius.adapters.jadx import (
    JadxAdapter,
    JadxCacheError,
    JadxError,
    JadxExecutionFailed,
    JadxUnavailable,
    build_jadx_tool_spec,
)
from mobius.services.tool_runner import BackendResult, ToolRunner

SCAN = "scn_01J8Z5K9WQ7R3T2M6N4P8V0ABC"


class FixtureBackend:
    """Test-only backend; writes deterministic source without executing a process."""

    isolation_ready = True

    def __init__(self, *, status: str = "ok", exit_code: int = 0, create_source: bool = True):
        self.calls = []
        self.status = status
        self.exit_code = exit_code
        self.create_source = create_source

    def execute(self, *, argv, workspace, limits):
        self.calls.append(argv)
        output_arg = next(part for part in argv if part.startswith("/work/outputs/jadx-output-"))
        output = workspace / output_arg.removeprefix("/work/")
        if self.create_source:
            source = output / "sources" / "com" / "example" / "Fixture.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package com.example;\n"
                "public final class Fixture {\n"
                "    public int answer() { return 42; }\n"
                "}\n",
                encoding="utf-8",
            )
        return BackendResult(self.status, self.exit_code, b"", b"fixture stderr", 4)


class LocalFixtureBackend:
    """Test-only real-process backend, used exclusively with the checked-in DEX fixture."""

    isolation_ready = True

    def execute(self, *, argv, workspace, limits):
        command = [
            str(workspace / part.removeprefix("/work/")) if part.startswith("/work/") else part
            for part in argv
        ]
        started = time.monotonic()
        try:
            result = subprocess.run(
                command, cwd=workspace, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=limits.timeout_seconds, check=False, shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            return BackendResult(
                "timeout", None, exc.stdout or b"", exc.stderr or b"",
                int((time.monotonic() - started) * 1000),
            )
        return BackendResult(
            "ok" if result.returncode == 0 else "error",
            result.returncode, result.stdout, result.stderr,
            int((time.monotonic() - started) * 1000),
        )


def make_adapter(tmp_path, backend, *, version="1.5.6", binary="/opt/jadx/bin/jadx"):
    spec = build_jadx_tool_spec(binary=binary, version=version)
    runner = ToolRunner(
        workspace_root=tmp_path / "workspaces",
        backend=backend,
        tools=(spec,),
    )
    return JadxAdapter(runner=runner, cache_root=tmp_path / "cache", tool_version=version)


def test_cache_is_reused_for_same_apk_digest_and_tool_version(tmp_path):
    backend = FixtureBackend()
    adapter = make_adapter(tmp_path, backend)
    artifact = b"fixture-apk-bytes"
    digest = hashlib.sha256(artifact).hexdigest()

    first = adapter.decompile(investigation_id=SCAN, artifact=artifact, expected_sha256=digest)
    second = adapter.decompile(investigation_id=SCAN, artifact=artifact, expected_sha256=digest)

    assert first.cached is False
    assert second.cached is True
    assert first.cache_dir == second.cache_dir
    assert first.apk_sha256 == digest
    assert first.tool_version == "1.5.6"
    assert len(backend.calls) == 1
    assert not list((tmp_path / "workspaces" / SCAN / "outputs").glob("jadx-output-*"))
    assert not (tmp_path / "workspaces" / SCAN / ".jadx-home").exists()


def test_cache_key_changes_when_jadx_version_changes(tmp_path):
    artifact = b"same-apk"
    first_backend = FixtureBackend()
    second_backend = FixtureBackend()
    first = make_adapter(tmp_path, first_backend, version="1.5.6")
    second = make_adapter(tmp_path, second_backend, version="1.5.7")

    old = first.decompile(investigation_id=SCAN, artifact=artifact)
    new = second.decompile(investigation_id=SCAN, artifact=artifact)

    assert old.cache_dir != new.cache_dir
    assert old.cached is False and new.cached is False
    assert len(first_backend.calls) == len(second_backend.calls) == 1


def test_source_reference_resolves_with_bounded_lines(tmp_path):
    adapter = make_adapter(tmp_path, FixtureBackend())
    result = adapter.decompile(investigation_id=SCAN, artifact=b"fixture")
    snippet = adapter.resolve_source(
        result, relative_path=result.source_files[0], start_line=1, end_line=3,
    )

    assert snippet.fidelity == "decompiled"
    assert snippet.start_line == 1
    assert "return 42" in snippet.text


def test_source_reference_rejects_traversal_and_oversized_ranges(tmp_path):
    adapter = make_adapter(tmp_path, FixtureBackend())
    result = adapter.decompile(investigation_id=SCAN, artifact=b"fixture")

    with pytest.raises(JadxError, match="unsafe"):
        adapter.resolve_source(result, relative_path="../outside.java", start_line=1, end_line=1)
    with pytest.raises(JadxError, match="1 to 40"):
        adapter.resolve_source(result, relative_path=result.source_files[0], start_line=1, end_line=41)


def test_authorized_digest_mismatch_is_explicit(tmp_path):
    adapter = make_adapter(tmp_path, FixtureBackend())
    with pytest.raises(JadxError) as error:
        adapter.decompile(investigation_id=SCAN, artifact=b"fixture", expected_sha256="0" * 64)
    assert error.value.status == "digest_mismatch"


def test_corrupt_cache_is_not_silently_reused(tmp_path):
    adapter = make_adapter(tmp_path, FixtureBackend())
    result = adapter.decompile(investigation_id=SCAN, artifact=b"fixture")
    (result.cache_dir / result.source_files[0]).write_text("tampered", encoding="utf-8")

    with pytest.raises(JadxCacheError, match="integrity"):
        adapter.decompile(investigation_id=SCAN, artifact=b"fixture")


def test_nonzero_jadx_exit_is_explicit_and_not_cached(tmp_path):
    adapter = make_adapter(tmp_path, FixtureBackend(status="error", exit_code=3))
    with pytest.raises(JadxExecutionFailed) as error:
        adapter.decompile(investigation_id=SCAN, artifact=b"fixture")
    assert error.value.status == "error"


def test_missing_isolation_backend_is_explicit(tmp_path):
    spec = build_jadx_tool_spec()
    runner = ToolRunner(workspace_root=tmp_path / "workspaces", backend=None, tools=(spec,))
    adapter = JadxAdapter(runner=runner, cache_root=tmp_path / "cache")
    with pytest.raises(JadxUnavailable) as error:
        adapter.decompile(investigation_id=SCAN, artifact=b"fixture")
    assert error.value.status == "tool_unavailable"


def test_jadx_decompiles_checked_in_dex_fixture_when_cli_is_installed(tmp_path):
    binary = os.environ.get("MOBIUS_JADX_BIN")
    if not binary:
        pytest.skip("JADX 1.5.6 is installed only in the CI tool-validation job")
    fixture = Path(__file__).parent / "fixtures" / "dex" / "AnalysisTest.dex"
    artifact = fixture.read_bytes()
    adapter = make_adapter(tmp_path, LocalFixtureBackend(), binary=binary)
    result = adapter.decompile(
        investigation_id=SCAN, artifact=artifact, artifact_name="input.dex",
        expected_sha256=hashlib.sha256(artifact).hexdigest(),
    )

    assert result.cached is False
    assert result.source_files
    snippet = adapter.resolve_source(
        result, relative_path=result.source_files[0], start_line=1, end_line=1,
    )
    assert snippet.text
