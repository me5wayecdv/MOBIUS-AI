"""Runtime assertions for the OCI mount contract, against the real container runtime.

Runs on CI runners with Docker (the free GitHub ubuntu runners provide it). Uses the
pinned, already-pulled RECON worker image as a permitted fixture: no JADX, no new
images, no paid services. The probe swaps the tool invocation for a Python snippet via
``--entrypoint`` so it can attempt exactly the writes the contract must forbid, then
checks the host-side effect.

What is asserted (the stdout-tool contract used by recon/dex):

* the EXACT permitted mount set under /work is present and nothing else is: one tmpfs
  at /work and one bind at /work/input.apk whose mount options include ``ro`` (parsed
  from /proc/self/mountinfo with the pre-separator root/mountpoint/options fields -
  the post-separator "source" field is the backing device, not the bind path);
* the staged input is immutable at the MOUNT level: the probe-only fixture is staged
  world-writable (0666), so a failed append cannot be explained by file permission
  bits - only the read-only bind can have blocked it (the real worker still stages
  its input 0444; this fixture is probe-only);
* no writable host path exists: no /work/outputs mount, no other bind; in-container
  scratch writes land on the discarded tmpfs and never reach the host;
* job isolation within the tested mount-namespace boundary: the neighbouring job's
  sentinel file is not mounted anywhere, cannot be read through any plausible
  in-container path, and the neighbour workspace is byte-identical afterwards.

The mount-set parser is self-tested first (``--self-test`` runs only these checks):
fabricated mountinfo records for an overbroad workspace bind, an unexpected extra
mount, and an rw input bind must all be rejected.

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
from dataclasses import dataclass
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

def can_read(path):
    try:
        with open(path, "rb") as fh:
            fh.read(1)
        return True
    except OSError:
        return False

report = {}
report["input_read_ok"] = os.path.isfile("/work/input.apk")
report["input_write_blocked"] = not can_write_file("/work/input.apk")
mounts = [l.strip() for l in open("/proc/self/mountinfo") if " /work" in l]
report["work_mounts"] = mounts
# Neighbour-job read attempts at every plausible in-container path. None of these
# may succeed: the neighbour workspace must not be mounted or otherwise exposed.
report["neighbour_reads"] = {
    path: can_read(path)
    for path in (
        "/work/../job-b/marker.txt",
        "/work/../../job-b/marker.txt",
        "/job-b/marker.txt",
        "/workspace/job-b/marker.txt",
        "/workspaces/job-b/marker.txt",
        "/tmp/job-b/marker.txt",
    )
}
# Any in-container scratch write must land on the discarded tmpfs, never the host
# (asserted host-side by comparing workspace snapshots).
report["tmpfs_write_ok"] = can_write_tree("/work/tmpfs-scratch")
print("PROBE-JSON:" + json.dumps(report))
"""


def fail(msg: str) -> None:
    print(f"ASSERTION FAILED: {msg}", file=sys.stderr)
    raise SystemExit(1)


@dataclass(frozen=True)
class MountEntry:
    """One /proc/self/mountinfo record, parsed field-correctly.

    Layout: id parent major:minor root mountpoint options [optional...] - fstype
    source super-options. For a bind mount the pre-separator ``root`` field carries
    the bound path (relative to the source filesystem); the post-separator ``source``
    is only the backing device name and MUST NOT be compared against host paths.
    """

    mountpoint: str
    root: str
    options: frozenset
    fstype: str


def parse_mountinfo(lines: list[str]) -> list[MountEntry]:
    entries = []
    for line in lines:
        pre, sep, post = line.partition(" - ")
        fields = pre.split()
        if sep == "" or len(fields) < 6:
            fail(f"unparsable mountinfo record: {line!r}")
        post_fields = post.split()
        if len(post_fields) < 2:
            fail(f"unparsable mountinfo record (post-separator): {line!r}")
        entries.append(
            MountEntry(
                mountpoint=fields[4],
                root=fields[3],
                options=frozenset(fields[5].split(",")),
                fstype=post_fields[0],
            )
        )
    return entries


def check_mount_contract(report: dict, workspace: Path, input_file: Path) -> None:
    """Assert the exact permitted mount set under /work and nothing else."""
    entries = parse_mountinfo(report["work_mounts"])
    under_work = [
        e for e in entries
        if e.mountpoint == "/work" or e.mountpoint.startswith("/work/")
    ]
    permitted = {"/work", "/work/input.apk"}
    actual = {e.mountpoint for e in under_work}
    if actual != permitted:
        fail(f"mount set under /work is {sorted(actual)}, expected exactly {sorted(permitted)}")
    by_point = {e.mountpoint: e for e in under_work}
    if by_point["/work"].fstype != "tmpfs":
        fail(f"/work is {by_point['/work'].fstype}, expected tmpfs")
    input_mount = by_point["/work/input.apk"]
    if "ro" not in input_mount.options:
        fail(f"/work/input.apk mount options {sorted(input_mount.options)} lack 'ro'")
    # The bind root must be the staged input path, not a directory and not the
    # workspace itself. (Relative to the source filesystem; on the runner's root fs
    # this equals the absolute host path.)
    if input_mount.root == "/":
        fail("/work/input.apk is bound to a filesystem root, not the staged file")
    if not input_mount.root.endswith("/input.apk"):
        fail(f"/work/input.apk bind root is {input_mount.root!r}, expected the staged input.apk")
    workspace_str = str(workspace)
    if input_mount.root == workspace_str:
        fail("the workspace directory itself is mounted")
    expected = str(input_file)
    if input_mount.root != expected and not expected.endswith(input_mount.root):
        fail(f"bind root {input_mount.root!r} does not resolve to the staged input {expected!r}")


def self_test() -> None:
    """The checker must reject fabricated contract violations."""
    workspace = Path("/tmp/selftest/job-a")
    input_file = workspace / "input.apk"
    valid = {"work_mounts": [
        "461 450 0:80 / /work rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=131072k,mode=755,inode64",
        f"462 461 259:1 {input_file} /work/input.apk ro,relatime - ext4 /dev/root rw,discard",
    ]}
    check_mount_contract(valid, workspace, input_file)  # must not raise

    violations = {
        "overbroad workspace bind": [
            f"462 461 259:1 {workspace} /work rw,relatime - ext4 /dev/root rw,discard",
        ],
        "unexpected extra mount": [
            "461 450 0:80 / /work rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=131072k",
            f"462 461 259:1 {input_file} /work/input.apk ro,relatime - ext4 /dev/root rw,discard",
            f"463 461 259:1 {workspace}/outputs /work/outputs rw,relatime - ext4 /dev/root rw,discard",
        ],
        "input mounted read-write": [
            "461 450 0:80 / /work rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=131072k",
            f"462 461 259:1 {input_file} /work/input.apk rw,relatime - ext4 /dev/root rw,discard",
        ],
        "workspace mounted at a nested point": [
            "461 450 0:80 / /work rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=131072k",
            f"462 461 259:1 {input_file} /work/input.apk ro,relatime - ext4 /dev/root rw,discard",
            f"463 461 259:1 {workspace} /work/host rw,relatime - ext4 /dev/root rw,discard",
        ],
        "unparsable record": ["not a mountinfo line"],
    }
    for name, lines in violations.items():
        try:
            check_mount_contract({"work_mounts": lines}, workspace, input_file)
        except SystemExit:
            continue
        print(f"SELF-TEST FAILED: checker accepted {name}", file=sys.stderr)
        raise SystemExit(1)
    print(f"mount-contract checker self-test: {1 + len(violations)} cases OK")


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
    # Probe-only fixture: world-writable on purpose. If a container append then fails,
    # only the read-only mount can have blocked it - file permission bits allow anyone.
    # (The real worker stages its own input 0444; this probe does not touch it.)
    staged.chmod(0o666)
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


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0

    self_test()  # a checker that cannot reject violations must never vouch for them

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

    backend = OciBackend(runtime=runtime, binary_images={RECON_BINARY: image},
                         run_label=os.environ.get("MOBIUS_CANARY_RUN_ID") or None)

    print("== stdout-only contract (recon/dex; the only contract this backend exposes)")
    report = run_probe(build_probe_command(backend, image, ws_a))
    print(json.dumps(report, indent=2))
    if not report["input_read_ok"]:
        fail("container could not read the staged input")
    if not report["input_write_blocked"]:
        fail("READ-ONLY INPUT VIOLATED: container appended to /work/input.apk "
             "despite a world-writable fixture file - the mount is not enforcing ro")
    check_mount_contract(report, ws_a, ws_a / "input.apk")
    readable = [p for p, ok in report["neighbour_reads"].items() if ok]
    if readable:
        fail(f"neighbour job sentinel READABLE at: {readable}")
    after_a = snapshot(ws_a)
    if after_a != before_a:
        fail(f"contract changed the workspace: {sorted(after_a)} != {sorted(before_a)}")
    if snapshot(ws_b) != before_b:
        fail("neighbouring job workspace changed during the probe")
    print("stdout-only contract: input ro-mount enforced, no writable host path, "
          "tmpfs confined, neighbour unreadable+unchanged (tested namespace boundary)")

    shutil.rmtree(base, ignore_errors=True)
    print("OCI mount contract runtime assertions: ALL PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
