"""PHANTOM emulator adapter (D-060, first slice): bounded read-only runtime probes.

A closed set of adb probes against a verified emulator only - physical devices
are refused before any probe runs. Every invocation is an argv list (never a
shell string) with a bounded timeout and capped output. Probes are read-only:
no install, no delete, no Frida, no proxy. An unconfigured environment fails
closed with PoCAdapterUnavailable, preserving the pre-adapter behavior.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from .poc_runner import PoCAdapterUnavailable

MAX_OUTPUT_BYTES = 262_144
PROBE_TIMEOUT_SECONDS = 30
_DETAIL_OUTPUT_BYTES = 4_000

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
        runner: Runner | None = None,
        emulator_check: Callable[[], bool] | None = None,
    ) -> None:
        self._adb = adb_path
        self._serial = serial
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


def adapter_from_env() -> PhantomEmulatorAdapter | None:
    """Configured only when MOBIUS_PHANTOM_ADB names an adb binary; the
    optional MOBIUS_PHANTOM_SERIAL pins one device. Absent config = no
    adapter, and emulator-target plans fail closed as before."""
    adb = os.environ.get("MOBIUS_PHANTOM_ADB", "").strip()
    if not adb:
        return None
    serial = os.environ.get("MOBIUS_PHANTOM_SERIAL", "").strip() or None
    return PhantomEmulatorAdapter(adb_path=adb, serial=serial)
