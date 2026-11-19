"""Runtime assertions for the OCI mount contract, against the real container runtime.

Runs on CI runners with Docker (the free GitHub ubuntu runners provide it). Uses the
pinned, already-pulled RECON worker image as a permitted fixture: no JADX, no new
images, no paid services. The probe swaps the tool invocation for a Python snippet via
``--entrypoint`` so it can attempt exactly the writes the contract must forbid, then
checks the host-side effect.

What is asserted (the stdout-tool contract used by recon/dex):

* the workspace directory itself is never mounted;
* /work/input.apk is a read-only file bind (write attempts fail);
* no /work/outputs mount exists - there is no writable host path at all;
* anything the container writes into /work lands on the discarded tmpfs and never
  reaches the host;
* a neighbouring job's workspace is not mounted, not visible, and is byte-identical
  afterwards.

File-output tools (JADX) are deliberately out of scope: no writable host path exists
in this contract, the JADX image stays unpublished, and the worker's jadx branch is
held until a reviewed file-output mount contract and a verified output-tree cleanup
exist.

Exit code 0 = every assertion held; 1 = at least one failed (details on stderr).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from mobius.services.oci_backend import OciBackend
from mobius.services.tool_runner import ToolLimits

# The pinned fixture binary inside the recon image; mirrors worker/runner.py.
RECON_BINARY = "/usr/local/bin/mobius-recon-manifest"
PYTHON = "/usr/local/bin/python3"

LIMITS = ToolLimits(timeout_seconds=60, memory_mb=256, cpu_seconds=30)

PROBE = r"""
import json, os

def can_write_file(path):
    try:
        with open(path, "a") as fh:
            fh.write("x")
        return True
    except OSError:
        return False

def can_write_tree(path):
    try:
        os.makedirs(path + "/nested/deep", exist_ok=True)
        with open(path + "/nested/deep/probe.txt", "w") as fh:
            fh.write("probe")
        return True
    except OSError:
        return False

report = {}
report["input_read_ok"] = os.path.isfile("/work/input.apk")
report["input_write_blocked"] = not can_write_file("/work/input.apk")
mounts = [l.strip() for l in open("/proc/self/mountinfo") if " /work" in l]
report["work_mounts"] = mounts
report["outputs_is_mount"] = any(" /work/outputs " in l for l in mounts)
# Any in-container scratch write must land on the discarded tmpfs, never the host
# (asserted host-side by comparing workspace snapshots).
report["tmpfs_write_ok"] = can_write_tree("/work/tmpfs-scratch")
print("PROBE-JSON:" + json.dumps(report))
"""


def fail(msg: str) -> None:
    print(f"ASSERTION FAILED: {msg}", file=sys.stderr)
    raise SystemExit(1)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): sha256(p)
        for p in sorted(root.rglob("*"))
        if p.is_file() and not p.is_symlink()
    }


def stage_workspace(root: Path) -> Path:
    workspace = root
    workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
    staged = workspace / "input.apk"
    staged.write_bytes(b"oci-contract-probe fixture apk bytes")
    staged.chmod(0o444)
    return workspace


def build_probe_command(backend: OciBackend, image: str, workspace: Path) -> tuple[str, ...]:
    command = backend._container_argv(  # noqa: SLF001 - the probe tests this builder directly
        argv=(RECON_BINARY, "--input", "/work/input.apk"),
        workspace=workspace,
        limits=LIMITS,
    )
    index = command.index(image)
    # Keep every hardening flag and mount exactly as the backend emits them; only the
    # image entrypoint and tool argv are replaced by the probe.
    return (*command[:index], "--entrypoint", PYTHON, image, "-c", PROBE)


def run_probe(command: tuple[str, ...]) -> dict:
    result = subprocess.run(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=LIMITS.timeout_seconds + 30, check=False, shell=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    if result.returncode != 0:
        print(result.stdout.decode(errors="replace"), file=sys.stderr)
        print(result.stderr.decode(errors="replace")[-4096:], file=sys.stderr)
        fail(f"probe container exited {result.returncode}")
    marker = "PROBE-JSON:"
    for line in result.stdout.decode(errors="replace").splitlines():
        if line.startswith(marker):
            return json.loads(line[len(marker):])
    print(result.stdout.decode(errors="replace"), file=sys.stderr)
    fail("probe produced no report")


def check_mount_sources(report: dict, workspace: Path) -> None:
    sources = []
    for line in report["work_mounts"]:
        if " - " not in line:
            continue
        source = line.split(" - ", 1)[1].split(" ", 2)[1] if len(line.split(" - ", 1)[1].split(" ")) > 1 else ""
        sources.append(source)
    root = str(workspace)
    for source in sources:
        if source == root:
            fail("the workspace directory itself is mounted")
        if source.startswith(root + "/") and source != str(workspace / "input.apk"):
            fail(f"unexpected workspace path mounted: {source}")
    if report["outputs_is_mount"]:
        fail("a /work/outputs mount exists; the stdout-only contract has no writable host path")


def main() -> int:
    image = os.environ.get("MOBIUS_RECON_IMAGE")
    if not image:
        fail("MOBIUS_RECON_IMAGE is not set (expected the pinned digest reference)")
    runtime = os.environ.get("MOBIUS_OCI_RUNTIME") or shutil.which("docker")
    if not runtime or not Path(runtime).is_absolute():
        fail("no absolute OCI runtime path (MOBIUS_OCI_RUNTIME or docker on PATH)")

    base = Path(tempfile.mkdtemp(prefix="oci-contract-"))
    ws_a = stage_workspace(base / "job-a")
    ws_b = stage_workspace(base / "job-b")
    (ws_b / "marker.txt").write_text("neighbouring job must remain untouched")
    before_a = snapshot(ws_a)
    before_b = snapshot(ws_b)

    backend = OciBackend(runtime=runtime, binary_images={RECON_BINARY: image})

    print("== stdout-only contract (recon/dex; the only contract this backend exposes)")
    report = run_probe(build_probe_command(backend, image, ws_a))
    print(json.dumps(report, indent=2))
    if not report["input_read_ok"]:
        fail("container could not read the staged input")
    if not report["input_write_blocked"]:
        fail("READ-ONLY INPUT VIOLATED: container appended to /work/input.apk")
    check_mount_sources(report, ws_a)
    after_a = snapshot(ws_a)
    if after_a != before_a:
        fail(f"contract changed the workspace: {sorted(after_a)} != {sorted(before_a)}")
    if snapshot(ws_b) != before_b:
        fail("neighbouring job workspace changed during the probe")
    print("stdout-only contract: input immutable, no writable host path, tmpfs confined, jobs isolated")

    shutil.rmtree(base, ignore_errors=True)
    print("OCI mount contract runtime assertions: ALL PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
