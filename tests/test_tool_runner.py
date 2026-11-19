from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict, Field

from mobius.services.tool_runner import (
    BackendResult,
    ToolLimits,
    ToolRejected,
    ToolRunner,
    ToolSpec,
    ToolUnavailable,
)


class Args(BaseModel):
    model_config = ConfigDict(extra="forbid")
    input_file: str = Field(pattern=r"^[a-zA-Z0-9_.-]+$")


class FakeBackend:
    isolation_ready = True

    def __init__(self):
        self.calls = []

    def execute(self, *, argv, workspace, limits):
        self.calls.append((argv, workspace, limits))
        return BackendResult("ok", 0, b"result", b"", 12)


def spec():
    return ToolSpec(
        name="jadx.decompile",
        binary="/opt/mobius/bin/jadx",
        version="1.5.1",
        args_model=Args,
        build_argv=lambda args: (
            "/opt/mobius/bin/jadx", "--single-class", args.input_file
        ),
        limits=ToolLimits(timeout_seconds=30, network_enabled=False),
    )


SCAN = "scn_01J8Z5K9WQ7R3T2M6N4P8V0ABC"


def test_runner_requires_verified_isolation(tmp_path):
    runner = ToolRunner(workspace_root=tmp_path, backend=None, tools=(spec(),))
    with pytest.raises(ToolUnavailable, match="isolated execution backend"):
        runner.invoke(investigation_id=SCAN, tool="jadx.decompile", args={"input_file": "A.smali"})


def test_unknown_tool_is_rejected(tmp_path):
    runner = ToolRunner(workspace_root=tmp_path, backend=FakeBackend(), tools=(spec(),))
    with pytest.raises(ToolUnavailable, match="not registered"):
        runner.invoke(investigation_id=SCAN, tool="shell", args={})


def test_schema_rejects_extra_or_malformed_args(tmp_path):
    runner = ToolRunner(workspace_root=tmp_path, backend=FakeBackend(), tools=(spec(),))
    with pytest.raises(ToolRejected, match="schema validation"):
        runner.invoke(
            investigation_id=SCAN,
            tool="jadx.decompile",
            args={"input_file": "../../etc/passwd", "command": "id"},
        )


def test_executable_cannot_be_overridden(tmp_path):
    bad = ToolSpec(
        name="jadx.bad",
        binary="/opt/mobius/bin/jadx",
        version="1.5.1",
        args_model=Args,
        build_argv=lambda args: ("/bin/sh", "-c", "echo unsafe"),
    )
    runner = ToolRunner(workspace_root=tmp_path, backend=FakeBackend(), tools=(bad,))
    with pytest.raises(ToolRejected, match="replace the registered executable"):
        runner.invoke(investigation_id=SCAN, tool="jadx.bad", args={"input_file": "A.smali"})


def test_valid_invocation_uses_private_per_scan_workspace(tmp_path):
    backend = FakeBackend()
    runner = ToolRunner(workspace_root=tmp_path, backend=backend, tools=(spec(),))
    result = runner.invoke(
        investigation_id=SCAN, tool="jadx.decompile", args={"input_file": "A.smali"}
    )
    assert result.status == "ok"
    assert result.stdout == b"result"
    assert backend.calls[0][0] == ("/opt/mobius/bin/jadx", "--single-class", "A.smali")
    workspace = backend.calls[0][1]
    assert workspace.parent == tmp_path.resolve()
    assert workspace.stat().st_mode & 0o777 == 0o700
    outputs = workspace / "outputs"
    assert outputs.is_dir()
    # Sticky world-writable inside the owner-only workspace: the container's fixed uid
    # 65532 must write it and a non-root worker cannot chown to that uid.
    assert outputs.stat().st_mode & 0o7777 == 0o1777


def test_unready_backend_fails_closed(tmp_path):
    class Unready:
        isolation_ready = False

    runner = ToolRunner(workspace_root=tmp_path, backend=Unready(), tools=(spec(),))
    with pytest.raises(ToolUnavailable):
        runner.invoke(investigation_id=SCAN, tool="jadx.decompile", args={"input_file": "A.smali"})
