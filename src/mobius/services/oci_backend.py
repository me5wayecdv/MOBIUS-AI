"""Hardened OCI execution backend for registered MOBIUS tools."""
from __future__ import annotations

import os
import re
import selectors
import signal
import subprocess
import time
from pathlib import Path
from typing import Callable

from mobius.services.tool_runner import BackendResult, ToolLimits

_IMAGE = re.compile(r"^[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}$")
_BINARY = re.compile(r"^/[A-Za-z0-9_./-]+$")


class OciBackend:
    """Run registered binaries in digest-pinned, networkless OCI containers."""

    def __init__(
        self, *, runtime: str, binary_images: dict[str, str],
        pids_limit: int = 128, tmpfs_mb: int = 128,
        popen: Callable = subprocess.Popen, run: Callable = subprocess.run,
    ) -> None:
        if not Path(runtime).is_absolute():
            raise ValueError("OCI runtime path must be absolute")
        if not 16 <= pids_limit <= 1024 or not 16 <= tmpfs_mb <= 1024:
            raise ValueError("OCI resource limits are outside the allowed range")
        for binary, image in binary_images.items():
            if not _BINARY.fullmatch(binary):
                raise ValueError("container binary path must be absolute")
            if not _IMAGE.fullmatch(image):
                raise ValueError("tool images must be immutable sha256 digest references")
        self.runtime = runtime
        self.binary_images = dict(binary_images)
        self.pids_limit = pids_limit
        self.tmpfs_mb = tmpfs_mb
        self._popen = popen
        self._run = run

    @property
    def isolation_ready(self) -> bool:
        if not self.binary_images or not Path(self.runtime).is_file():
            return False
        for command in ([self.runtime, "info"], *(
            [self.runtime, "image", "inspect", image]
            for image in sorted(set(self.binary_images.values()))
        )):
            try:
                result = self._run(
                    command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=10, check=False, shell=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                return False
            if result.returncode != 0:
                return False
        return True

    def _container_argv(self, *, argv: tuple[str, ...], workspace: Path,
                        limits: ToolLimits) -> tuple[str, ...]:
        if not argv or argv[0] not in self.binary_images:
            raise ValueError("tool executable has no pinned OCI image")
        if not workspace.is_absolute() or workspace.is_symlink():
            raise ValueError("workspace must be an absolute non-symlink directory")
        root = workspace.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("workspace must be a directory")
        # Mount contract: the container never sees the workspace directory itself. It
        # gets an in-container tmpfs at /work and the staged input as a single read-only
        # file bind; results come back on stdout. No writable host path is exposed at
        # all. File-output tools are deliberately NOT supported by this backend: the
        # writable outputs contract and the cleanup of container-uid-owned output trees
        # are unverified, so JADX output-writing is held (see the worker's jadx branch).
        input_file = root / "input.apk"
        if input_file.is_symlink() or not input_file.is_file():
            raise ValueError("staged input.apk must be a regular non-symlink file")
        image = self.binary_images[argv[0]]
        return (
            self.runtime, "run", "--rm", "--init", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            f"--pids-limit={self.pids_limit}", f"--memory={limits.memory_mb}m",
            "--memory-swap", f"{limits.memory_mb}m",
            f"--cpus={max(0.1, min(8.0, limits.cpu_seconds / max(1, limits.timeout_seconds))):.2f}",
            "--ulimit", f"cpu={limits.cpu_seconds}:{limits.cpu_seconds}",
            "--ulimit", f"fsize={limits.max_output_bytes}:{limits.max_output_bytes}",
            "--ulimit", "nofile=1024:1024", "--user=65532:65532",
            f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={self.tmpfs_mb}m",
            # In-container scratch root; discarded with the container. Parents-first order
            # matters: the two binds below land inside this tmpfs.
            f"--tmpfs=/work:rw,noexec,nosuid,nodev,size={self.tmpfs_mb}m",
            # --mount fields must be key=value; a bare `rw` is rejected by the runtime.
            # The input is a single-file read-only bind: the runtime enforces immutability
            # and no host directory traversal is needed to reach it.
            "--mount", f"type=bind,src={input_file},dst=/work/input.apk,readonly",
            "--workdir=/work", "--hostname=mobius-tool",
            "--env=HOME=/tmp", "--env=TMPDIR=/tmp", image, *argv,
        )

    def execute(self, *, argv: tuple[str, ...], workspace: Path,
                limits: ToolLimits) -> BackendResult:
        if limits.network_enabled:
            return BackendResult("unavailable", None, b"",
                                 b"network-enabled jobs are not supported", 0)
        try:
            command = self._container_argv(argv=argv, workspace=workspace, limits=limits)
        except (ValueError, OSError) as exc:
            return BackendResult("unavailable", None, b"", str(exc).encode(), 0)
        started = time.monotonic()
        try:
            proc = self._popen(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, shell=False, close_fds=True,
                start_new_session=True,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
            )
        except OSError as exc:
            return BackendResult("unavailable", None, b"", str(exc).encode(), 0)

        out, err = bytearray(), bytearray()
        buffers = {proc.stdout: out, proc.stderr: err}
        selector = selectors.DefaultSelector()
        for stream in buffers:
            selector.register(stream, selectors.EVENT_READ)
        deadline = started + limits.timeout_seconds
        status = "ok"
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.2)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    room = limits.max_output_bytes - len(out) - len(err)
                    if room <= 0 or len(chunk) > room:
                        if room > 0:
                            buffers[key.fileobj].extend(chunk[:room])
                        status = "killed"
                        break
                    buffers[key.fileobj].extend(chunk)
                if status != "ok":
                    break
        finally:
            selector.close()
        if status in {"timeout", "killed"} and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            code = proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait()
            status = "killed"
        if status == "ok" and code:
            status = "error"
        return BackendResult(status, code, bytes(out), bytes(err[-16384:]),
                             int((time.monotonic() - started) * 1000))
