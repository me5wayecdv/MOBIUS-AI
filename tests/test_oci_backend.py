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


def make_workspace(tmp_path):
    workspace = tmp_path / "work"
    workspace.mkdir()
    (workspace / "input.apk").write_bytes(b"fixture-apk")
    (workspace / "outputs").mkdir()
    return workspace


def test_container_command_enforces_security_flags(tmp_path):
    backend = make_backend(tmp_path)
    workspace = make_workspace(tmp_path)
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


def _mount_assertions(command, root):
    mounts = [command[i + 1] for i, part in enumerate(command) if part == "--mount"]
    assert f"type=bind,src={root / 'input.apk'},dst=/work/input.apk,readonly" in mounts
    # The workspace root must not appear as a mount source at all.
    assert not any(f"src={root}," in m or m.endswith(f"src={root}") for m in mounts)
    # Bare fields are only valid for boolean flags (readonly); a bare `rw` is rejected
    # by the runtime ('invalid field rw must be a key=value pair').
    boolean_flags = {"readonly"}
    for mount in mounts:
        for field in mount.split(","):
            assert "=" in field or field in boolean_flags, field
    tmpfs = [part for part in command if part.startswith("--tmpfs=")]
    assert any(spec.startswith("--tmpfs=/work:") for spec in tmpfs)
    return mounts


def test_stdout_tools_get_a_read_only_mount_contract(tmp_path):
    """Split-mount contract, stdout tools (recon/dex): the workspace directory itself is
    never mounted; the container gets a tmpfs /work and the staged input as a single
    read-only file bind. No writable host path is exposed at all. Also regression-guards
    that every --mount field is key=value (a bare `rw` once failed every job at start)."""
    backend = make_backend(tmp_path)
    workspace = make_workspace(tmp_path)
    command = backend._container_argv(
        argv=(BINARY, "--version"), workspace=workspace,
        limits=ToolLimits(timeout_seconds=30, memory_mb=512, cpu_seconds=20),
    )
    mounts = _mount_assertions(command, workspace.resolve())
    assert not any("/work/outputs" in m for m in mounts)


def test_file_output_tools_get_the_writable_outputs_bind(tmp_path):
    """Split-mount contract, file-output tools (JADX): only the per-job outputs/ directory
    is additionally mounted writable (sticky 1777 inside the 0700 workspace, because the
    fixed container uid 65532 must write it and a non-root worker cannot chown)."""
    backend = make_backend(tmp_path, writable_output_binaries=frozenset({BINARY}))
    workspace = make_workspace(tmp_path)
    command = backend._container_argv(
        argv=(BINARY, "--version"), workspace=workspace,
        limits=ToolLimits(timeout_seconds=30, memory_mb=512, cpu_seconds=20),
    )
    mounts = _mount_assertions(command, workspace.resolve())
    root = workspace.resolve()
    assert f"type=bind,src={root / 'outputs'},dst=/work/outputs" in mounts


def test_writable_output_binaries_must_be_registered(tmp_path):
    with pytest.raises(ValueError, match="writable-output"):
        make_backend(tmp_path, writable_output_binaries=frozenset({"/bin/sh"}))


def test_container_command_requires_staged_input(tmp_path):
    backend = make_backend(tmp_path)
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="input.apk"):
        backend._container_argv(argv=(BINARY,), workspace=empty, limits=ToolLimits())


def test_file_output_tools_require_an_outputs_directory(tmp_path):
    backend = make_backend(tmp_path, writable_output_binaries=frozenset({BINARY}))
    no_outputs = tmp_path / "no-outputs"
    no_outputs.mkdir()
    (no_outputs / "input.apk").write_bytes(b"fixture-apk")
    with pytest.raises(ValueError, match="outputs"):
        backend._container_argv(argv=(BINARY,), workspace=no_outputs, limits=ToolLimits())


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
