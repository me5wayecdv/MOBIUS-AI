"""Runtime assertions for the OCI mount contract, against the real container runtime.

Runs on CI runners with Docker (the free GitHub ubuntu runners provide it). Uses the
pinned, already-pulled RECON worker image as a permitted fixture: no JADX, no new
images, no paid services. The probe swaps the tool invocation for a Python snippet via
``--entrypoint`` so it can attempt exactly the writes the contract must forbid, then
checks the host-side effect.

What is asserted, per contract mode:

* stdout-tool contract (recon/dex): the workspace directory itself is never mounted;
  /work/input.apk is a read-only file bind (write attempts fail); no /work/outputs
  mount exists; anything the container writes into /work lands on the discarded tmpfs
  and never reaches the host; a neighbouring job's workspace is not mounted, not
  visible, and is byte-identical afterwards.
* file-output contract (JADX-mode fixture): everything above, plus the outputs/
  directory IS writable from inside and the write is visible on the host — and only
  that subtree changes.

The JADX image stays unpublished and untested; the writable mode is exercised with the
recon image standing in as the pinned runtime fixture. Output-tree cleanup of
uid-65532-owned nested directories by an unprivileged host worker is expressly NOT
asserted here: it is an unresolved question and the JADX output-writing path stays
held until it is answered.

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
if report["outputs_is_mount"]:
    report["outputs_write_ok"] = can_write_tree("/work/outputs/probe-tree")
else:
    # No outputs mount: a same-named path can be created on the /work tmpfs, but it
    # must never propagate to the host (asserted host-side).
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
    outputs = workspace / "outputs"
    outputs.mkdir()
    outputs.chmod(0o1777)
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


def check_mount_sources(report: dict, workspace: Path, *, outputs_expected: bool) -> None:
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
        if source.startswith(root + "/") and source not in {
            str(workspace / "input.apk"),
            str(workspace / "outputs"),
        }:
            fail(f"unexpected workspace path mounted: {source}")
    if outputs_expected != report["outputs_is_mount"]:
        fail(f"outputs mount presence {report['outputs_is_mount']} != expected {outputs_expected}")


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

    backend_ro = OciBackend(runtime=runtime, binary_images={RECON_BINARY: image})
    backend_rw = OciBackend(
        runtime=runtime, binary_images={RECON_BINARY: image},
        writable_output_binaries=frozenset({RECON_BINARY}),
    )

    print("== read-only contract (stdout tools: recon/dex)")
    report = run_probe(build_probe_command(backend_ro, image, ws_a))
    print(json.dumps(report, indent=2))
    if not report["input_read_ok"]:
        fail("container could not read the staged input")
    if not report["input_write_blocked"]:
        fail("READ-ONLY INPUT VIOLATED: container appended to /work/input.apk")
    check_mount_sources(report, ws_a, outputs_expected=False)
    after_a = snapshot(ws_a)
    if after_a != before_a:
        fail(f"read-only contract changed the workspace: {sorted(after_a)} != {sorted(before_a)}")
    if snapshot(ws_b) != before_b:
        fail("neighbouring job workspace changed during the read-only probe")
    print("read-only contract: input immutable, no writable host path, tmpfs confined, jobs isolated")

    print("== writable contract (file-output fixture standing in for JADX mode)")
    report = run_probe(build_probe_command(backend_rw, image, ws_a))
    print(json.dumps(report, indent=2))
    if not report["input_write_blocked"]:
        fail("READ-ONLY INPUT VIOLATED in writable mode")
    if not report.get("outputs_write_ok"):
        fail("outputs/ bind was not writable in writable mode")
    check_mount_sources(report, ws_a, outputs_expected=True)
    written = ws_a / "outputs" / "probe-tree" / "nested" / "deep" / "probe.txt"
    if not written.is_file() or written.read_text() != "probe":
        fail("container write into outputs/ is not host-visible")
    after_a = snapshot(ws_a)
    unexpected = set(after_a) - set(before_a) - {str(written.relative_to(ws_a))}
    if unexpected:
        fail(f"writable mode wrote outside outputs/: {sorted(unexpected)}")
    changed = {k for k in before_a if before_a[k] != after_a.get(k)}
    if changed:
        fail(f"writable mode modified pre-existing files: {sorted(changed)}")
    if snapshot(ws_b) != before_b:
        fail("neighbouring job workspace changed during the writable probe")
    print("writable contract: writes confined to outputs/, input immutable, jobs isolated")

    shutil.rmtree(base, ignore_errors=True)
    print("OCI mount contract runtime assertions: ALL PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
