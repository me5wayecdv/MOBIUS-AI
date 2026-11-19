import pytest
from mobius.services.oci_backend import OciBackend
from mobius.services.tool_runner import ToolLimits

IMAGE = "ghcr.io/example/mobius-jadx@sha256:" + "a" * 64
BINARY = "/opt/jadx/bin/jadx"


def make_backend(tmp_path, **kwargs):
    runtime = tmp_path / "podman"
    runtime.write_text("runtime")
    return OciBackend(runtime=str(runtime), binary_images={BINARY: IMAGE}, **kwargs)


def test_rejects_mutable_image_reference(tmp_path):
    runtime = tmp_path / "podman"
    runtime.write_text("runtime")
    with pytest.raises(ValueError, match="immutable sha256"):
        OciBackend(runtime=str(runtime), binary_images={BINARY: "latest"})


def test_runtime_path_must_be_absolute():
    with pytest.raises(ValueError, match="absolute"):
        OciBackend(runtime="podman", binary_images={})


def test_container_command_enforces_security_flags(tmp_path):
    backend = make_backend(tmp_path)
    workspace = tmp_path / "work"
    workspace.mkdir()
    command = backend._container_argv(
        argv=(BINARY, "--version"), workspace=workspace,
        limits=ToolLimits(timeout_seconds=30, memory_mb=512, cpu_seconds=20),
    )
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--user=65532:65532" in command
    assert "--pids-limit=128" in command
    assert "--memory=512m" in command
    assert IMAGE in command


def test_mount_flag_uses_only_valid_key_value_fields(tmp_path):
    """Regression: docker rejects bare fields in --mount (a `,rw` suffix shipped once and
    every job failed with 'invalid field rw must be a key=value pair')."""
    backend = make_backend(tmp_path)
    workspace = tmp_path / "work"
    workspace.mkdir()
    command = backend._container_argv(
        argv=(BINARY, "--version"), workspace=workspace,
        limits=ToolLimits(timeout_seconds=30, memory_mb=512, cpu_seconds=20),
    )
    mount = command[command.index("--mount") + 1]
    assert mount == f"type=bind,src={workspace.resolve()},dst=/work"
    for field in mount.split(","):
        assert "=" in field, field


def test_unregistered_binary_rejected(tmp_path):
    backend = make_backend(tmp_path)
    workspace = tmp_path / "work"
    workspace.mkdir()
    with pytest.raises(ValueError, match="no pinned OCI image"):
        backend._container_argv(argv=("/bin/sh", "-c", "id"),
                                workspace=workspace, limits=ToolLimits())


def test_symlink_workspace_rejected(tmp_path):
    backend = make_backend(tmp_path)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="non-symlink"):
        backend._container_argv(argv=(BINARY,), workspace=link, limits=ToolLimits())


def test_network_is_never_enabled(tmp_path):
    backend = make_backend(tmp_path)
    result = backend.execute(argv=(BINARY,), workspace=tmp_path,
                             limits=ToolLimits(network_enabled=True))
    assert result.status == "unavailable"


def test_readiness_checks_runtime_and_digest_image(tmp_path):
    calls = []

    class Result:
        returncode = 0

    def fake_run(command, **kwargs):
        calls.append(command)
        return Result()

    backend = make_backend(tmp_path, run=fake_run)
    assert backend.isolation_ready
    assert calls[0][-1] == "info"
    assert calls[1][-1] == IMAGE
