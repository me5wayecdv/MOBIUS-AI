"""PHANTOM emulator adapter (D-060): bounded runtime probes and lifecycle.

A closed set of adb probes against a verified emulator only - physical devices
are refused before any probe runs. Every invocation is an argv list (never a
shell string) with a bounded timeout and capped output. adb probes are
read-only: no install, no delete, no proxy. The optional Frida probe is
observation-only instrumentation (a fixed enumeration script embedded in this
module - callers cannot supply scripts), gated upstream by the PoC approval
flow.

Target-side lifecycle operations (not probes): bounded boot verification and
the pinned frida-server lifecycle. start_instrumentation only ever pushes a
local server binary whose sha256 matches the caller-pinned digest - a
mismatch fails closed before any device traffic - and only onto the verified
emulator. stop_instrumentation is the matching idempotent cleanup.

An unconfigured environment fails closed with PoCAdapterUnavailable,
preserving the pre-adapter behavior.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from .poc_runner import PoCAdapterUnavailable

MAX_OUTPUT_BYTES = 262_144
PROBE_TIMEOUT_SECONDS = 30
FRIDA_TIMEOUT_SECONDS = 90
BOOT_BUDGET_SECONDS = 120
BOOT_POLL_SECONDS = 5
_DETAIL_OUTPUT_BYTES = 4_000

# Fixed on-device path for the pinned frida-server binary. The name is fixed
# so the matching pkill cleanup and pidof verification are unambiguous.
_SERVER_DEVICE_PATH = "/data/local/tmp/mobius-frida-server"

# Fixed observation-only Frida script: count classes loaded in the target
# process. Synchronous enumeration (enumerateLoadedClassesSync) so the count
# prints during initial script evaluation - the CLI's post-evaluation exit
# cannot race an async onComplete callback. No user-controlled script ever
# reaches Frida through this adapter.
_FRIDA_ENUMERATE_SCRIPT = (
    "Java.perform(function () {"
    "console.log('MOBIUS_CLASSES:' + Java.enumerateLoadedClassesSync().length);"
    "});"
)

# (argv, timeout_seconds) -> (returncode, stdout_bytes, stderr_bytes)
Runner = Callable[[Sequence[str], int], "tuple[int, bytes, bytes]"]


def _subprocess_runner(argv: Sequence[str], timeout: int) -> "tuple[int, bytes, bytes]":
    proc = subprocess.run(list(argv), capture_output=True, timeout=timeout, check=False)
    return proc.returncode, proc.stdout, proc.stderr


@dataclass(frozen=True, slots=True)
class EmulatorProbeResult:
    probe: str
    target: str
    actual: Any
    detail: str
    raw_output: str  # capped


class PhantomEmulatorAdapter:
    """adb-backed probes; the command runner and emulator check are injectable."""

    VERSION = "mobius-phantom/0.1.0"

    def __init__(
        self,
        *,
        adb_path: str,
        serial: str | None = None,
        frida_path: str | None = None,
        runner: Runner | None = None,
        emulator_check: Callable[[], bool] | None = None,
    ) -> None:
        self._adb = adb_path
        self._serial = serial
        self._frida = frida_path
        self._runner = runner or _subprocess_runner
        self._emulator_check = emulator_check

    def _argv(self, *args: str) -> list[str]:
        argv = [self._adb]
        if self._serial:
            argv += ["-s", self._serial]
        argv += list(args)
        return argv

    def _run(self, argv: Sequence[str]) -> "tuple[int, str]":
        rc, out, err = self._runner(argv, PROBE_TIMEOUT_SECONDS)
        text = (out + err)[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
        return rc, text

    def _require_emulator(self) -> None:
        if self._emulator_check is not None:
            ok = self._emulator_check()
        else:
            rc, text = self._run(self._argv("shell", "getprop", "ro.kernel.qemu"))
            ok = rc == 0 and text.strip() == "1"
        if not ok:
            raise PoCAdapterUnavailable(
                "PHANTOM probes run against a verified emulator only; "
                "the connected target is not an emulator"
            )

    def probe_package_present(self, package: str) -> EmulatorProbeResult:
        self._require_emulator()
        rc, text = self._run(self._argv("shell", "pm", "list", "packages", package))
        present = rc == 0 and any(
            line.strip() == f"package:{package}" for line in text.splitlines()
        )
        return EmulatorProbeResult(
            "package_present", package, present, "pm list packages", text[:_DETAIL_OUTPUT_BYTES]
        )

    def probe_provider_query_rows(self, authority: str, path: str) -> EmulatorProbeResult:
        """Read-only content query; actual is the row count, or None when the
        provider refused the query (permission denial, security error)."""
        self._require_emulator()
        uri = f"content://{authority}/{path}"
        rc, text = self._run(self._argv("shell", "content", "query", "--uri", uri))
        refused = (
            rc != 0
            or "Permission Denial" in text
            or "SecurityException" in text
            or "requires" in text and "permission" in text.lower()
        )
        if refused:
            return EmulatorProbeResult(
                "provider_query_rows", uri, None,
                f"query refused or failed (rc={rc})", text[:_DETAIL_OUTPUT_BYTES],
            )
        return EmulatorProbeResult(
            "provider_query_rows", uri, text.count("Row:"),
            "content query row count", text[:_DETAIL_OUTPUT_BYTES],
        )

    def _pids_of(self, package: str) -> list[str]:
        rc, text = self._run(self._argv("shell", "pidof", package))
        if rc != 0:
            return []
        return text.split()

    def _ensure_app_running(self, package: str) -> tuple[str | None, bool]:
        """Target-side setup (not instrumentation): launch the lab app on the
        verified emulator if its process is not running, waiting bounded.
        Returns (pid, ambiguous): pid is the single observed process id, or
        None when no process is running after the bounded wait or when more
        than one pid is listed (ambiguous, and the caller must fail closed
        rather than guess which process is the target)."""
        pids = self._pids_of(package)
        if len(pids) == 1:
            return pids[0], False
        if len(pids) > 1:
            return None, True
        self._run(self._argv(
            "shell", "monkey", "-p", package,
            "-c", "android.intent.category.LAUNCHER", "1",
        ))
        for _ in range(6):
            pids = self._pids_of(package)
            if len(pids) == 1:
                return pids[0], False
            if len(pids) > 1:
                return None, True
            time.sleep(5)
        return None, False

    def probe_frida_enumerate_classes(self, package: str) -> EmulatorProbeResult:
        """Observation-only instrumentation: ensure exactly one target
        process is running (launching the lab app on the verified emulator
        if needed), attach by its observed pid, and count loaded classes with
        the fixed embedded script. Fails closed without attaching when the
        target process is absent or ambiguous. actual is
        the class count, or None when attach/enumeration failed. Requires
        frida tooling configured and a frida-server already running on the
        verified emulator (the CI job owns the server lifecycle); the
        upstream PoC approval flow gates this probe."""
        self._require_emulator()
        if not self._frida:
            raise PoCAdapterUnavailable(
                "frida tooling is not configured on this host"
            )
        pid, ambiguous = self._ensure_app_running(package)
        if ambiguous:
            return EmulatorProbeResult(
                "frida_enumerate_classes", package, None,
                "frida attach refused: multiple pids listed for the target "
                "(frida-ambiguous-process); failing closed rather than "
                "attaching to an unverified process",
                b"",
            )
        if pid is None:
            return EmulatorProbeResult(
                "frida_enumerate_classes", package, None,
                "frida attach refused: no target process running after the "
                "bounded relaunch wait (frida-process-not-running)",
                b"",
            )
        device = ["-D", self._serial] if self._serial else ["-U"]
        # Attach by the observed pid only. On the prior CI run, attach by
        # package name reported process-not-found while the same run's
        # checks listed a running pid; pid attachment targets exactly the
        # verified process, never a name match on another process.
        argv = [self._frida, *device, "-q", "-p", pid, "-e", _FRIDA_ENUMERATE_SCRIPT]
        rc, out, err = self._runner(argv, FRIDA_TIMEOUT_SECONDS)
        text = (out + err)[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
        count = None
        for line in text.splitlines():
            if line.startswith("MOBIUS_CLASSES:"):
                try:
                    count = int(line.split(":", 1)[1].strip())
                except ValueError:
                    count = None
        if rc != 0 or count is None:
            return EmulatorProbeResult(
                "frida_enumerate_classes", package, None,
                f"frida attach/enumeration failed (rc={rc}): {_frida_error_class(text)}",
                text[:_DETAIL_OUTPUT_BYTES],
            )
        return EmulatorProbeResult(
            "frida_enumerate_classes", package, count,
            "observation-only frida class enumeration", text[:_DETAIL_OUTPUT_BYTES],
        )

    def wait_for_boot(
        self,
        budget_seconds: int = BOOT_BUDGET_SECONDS,
        poll_seconds: int = BOOT_POLL_SECONDS,
    ) -> bool:
        """Bounded boot verification: wait for the device, then poll
        sys.boot_completed until the budget is exhausted. Returns False on
        timeout - callers fail closed, never proceed against a device whose
        boot state is unverified."""
        self._require_emulator()
        rc, _ = self._run(self._argv("wait-for-device"))
        if rc != 0:
            return False
        polls = max(1, budget_seconds // poll_seconds)
        for _ in range(polls):
            rc, text = self._run(self._argv(
                "shell", "getprop", "sys.boot_completed"))
            if rc == 0 and text.strip() == "1":
                return True
            time.sleep(poll_seconds)
        return False

    def start_instrumentation(
        self, server_path: str, expected_sha256: str
    ) -> str:
        """Pinned frida-server lifecycle on the verified emulator: verify the
        local binary's sha256 against the caller-pinned digest (fail closed
        before any device traffic on mismatch), push it, and start it.
        Returns a fixed detail string; raises PoCAdapterUnavailable on any
        verification or push failure. Target-side setup, not a probe."""
        self._require_emulator()
        digest = hashlib.sha256()
        with open(server_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected_sha256.lower():
            raise PoCAdapterUnavailable(
                "refusing to push an unverified binary: local server digest "
                "does not match the pinned sha256"
            )
        # adb root is best-effort: expected on userdebug emulator images,
        # tolerated when already running as root.
        self._run(self._argv("root"))
        rc, _ = self._run(self._argv("wait-for-device"))
        if rc != 0:
            raise PoCAdapterUnavailable(
                "device did not return after adb root (bounded wait)"
            )
        rc, text = self._run(self._argv(
            "push", server_path, _SERVER_DEVICE_PATH))
        if rc != 0:
            raise PoCAdapterUnavailable(
                "frida-server push failed (rc=%d)" % rc
            )
        self._run(self._argv("shell", "chmod", "755", _SERVER_DEVICE_PATH))
        self._run(self._argv(
            "shell", "nohup", _SERVER_DEVICE_PATH,
            ">/dev/null", "2>&1", "&"))
        time.sleep(2)
        rc, text = self._run(self._argv(
            "shell", "pidof", "mobius-frida-server"))
        if rc != 0 or not text.strip():
            raise PoCAdapterUnavailable(
                "frida-server did not stay up after start (bounded check)"
            )
        return "frida-server started on the verified emulator (pinned digest)"

    def stop_instrumentation(self) -> str:
        """Best-effort cleanup: stop any frida-server on the verified
        emulator. Idempotent; a missing server is not an error."""
        self._require_emulator()
        rc, text = self._run(self._argv("shell", "pkill", "-f", "frida-server"))
        if rc == 0:
            return "frida-server stopped on the emulator"
        return f"no running frida-server found (rc={rc}) or stop refused"


# Fixed failure classifications for the frida probe. Persisted step detail
# must never carry target-derived strings (process names, paths, class names,
# secrets), so raw tool output is mapped onto this closed set of labels and
# the raw text stays in-memory only.
_FRIDA_ERROR_CLASSES = (
    (("unable to find process", "no such process", "process not found"),
     "frida-process-not-found"),
    (("unable to connect", "connection refused", "need Gadget"),
     "frida-server-unreachable"),
    (("timed out", "timeout"), "frida-attach-timeout"),
    (("ambiguous", "multiple processes"), "frida-ambiguous-process"),
    (("permission", "denied", "not permitted"), "frida-permission-denied"),
    (("invalid session", "session was detached"), "frida-session-lost"),
    (("script", "syntax", "referenceerror", "typeerror"), "frida-script-error"),
)


def _frida_error_class(output: str) -> str:
    lowered = output.lower()
    for needles, label in _FRIDA_ERROR_CLASSES:
        if any(needle in lowered for needle in needles):
            return label
    return "frida-error-unclassified"


def adapter_from_env() -> PhantomEmulatorAdapter | None:
    """Configured only when MOBIUS_PHANTOM_ADB names an adb binary; the
    optional MOBIUS_PHANTOM_SERIAL pins one device and MOBIUS_PHANTOM_FRIDA
    names a frida CLI binary for the observation-only instrumentation probe.
    Absent config = no adapter, and emulator-target plans fail closed as
    before."""
    adb = os.environ.get("MOBIUS_PHANTOM_ADB", "").strip()
    if not adb:
        return None
    serial = os.environ.get("MOBIUS_PHANTOM_SERIAL", "").strip() or None
    frida = os.environ.get("MOBIUS_PHANTOM_FRIDA", "").strip() or None
    return PhantomEmulatorAdapter(adb_path=adb, serial=serial, frida_path=frida)
