"""VECTOR fixture adapter: contained-capture machinery against a lab fixture.

Runs the D-061 fixture slice against the purpose-built lab APK inside the
contained environment: install, proxy configuration, launch, logcat verdict
read-back, backend receipt assertions, and a safe-GET request replay (a
second backend receipt of the same request; never response replay).

Scope honesty: this exercises the capture/replay/TLS-gate MACHINERY against a
substitute fixture target that explicitly trusts the per-run test CA. It
proves nothing about Allsafe or any real third-party target, and results must
be reported as substitute-target machinery evidence.

The adapter only runs where the harness placed it: env-configured paths,
observation of fixed fixture log tags, and fixed error classes in details
(never raw tool output), mirroring the PHANTOM sanitization boundary.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from .phantom import _subprocess_runner  # shared bounded runner, no shell

VERSION = "vector-fixture-1"

_TRUSTED_PKG = "local.mobius.d061lab"
_DEFAULT_PKG = "local.mobius.d061lab.defaulttrust"
_LOG_TAG = "D061FIXTURE"
_DETAIL_OUTPUT_BYTES = 2048
_PROXY_SETTING = "10.0.2.2:8080"


@dataclass
class FixtureResult:
    actual: Any
    detail: str


@dataclass
class VectorFixtureAdapter:
    """Drives the fixture capture inside the contained environment."""

    adb_path: str
    serial: str
    trusted_apk: str
    default_apk: str
    proxy_url: str          # http://127.0.0.1:8080 (namespace loopback)
    replay_url: str         # exact URL of the positive request to replay
    ca_pem: str             # per-run test CA (replay client verification)
    receipts_path: str
    runner: Any = _subprocess_runner
    VERSION: str = field(default=VERSION, init=False)

    def _argv(self, *args: str) -> list[str]:
        argv = [self.adb_path]
        if self.serial:
            argv += ["-s", self.serial]
        argv += list(args)
        return argv

    def _run(self, argv: Sequence[str], timeout: int = 60) -> tuple[int, str]:
        rc, out, err = self.runner(list(argv), timeout)
        text = (out + b"\n" + err).decode("utf-8", "replace")
        return rc, text

    # -- receipt accounting --------------------------------------------------
    def _receipt_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        try:
            with open(self.receipts_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    if entry.get("status") == 200 and entry.get("req"):
                        counts[entry["req"]] = counts.get(entry["req"], 0) + 1
        except FileNotFoundError:
            return {}
        return counts

    # -- logcat verdicts ------------------------------------------------------
    def _await_fixture_lines(self, package: str, timeout_s: int = 120) -> set[str]:
        """Launch the fixture and collect its fixed D061FIXTURE verdict lines."""
        self._run(self._argv("shell", "logcat", "-c"))
        self._run(self._argv(
            "shell", "monkey", "-p", package,
            "-c", "android.intent.category.LAUNCHER", "1"), timeout=60)
        deadline = time.monotonic() + timeout_s
        found: set[str] = set()
        while time.monotonic() < deadline:
            rc, text = self._run(self._argv("shell", "logcat", "-d", "-s", _LOG_TAG))
            for line in text.splitlines():
                for token in ("POSITIVE_OK", "POSITIVE_FAILED", "WRONGHOST_REJECTED",
                              "WRONGHOST_NOTREJECTED", "UNTRUSTED_REJECTED",
                              "UNTRUSTED_NOTREJECTED", "SUITE_DONE"):
                    if token in line:
                        found.add(token)
            if "SUITE_DONE" in found:
                return found
            time.sleep(3)
        return found

    # -- main entry ------------------------------------------------------------
    def run_fixture_capture(self, plan_package: str) -> FixtureResult:
        if plan_package != _TRUSTED_PKG:
            return FixtureResult(None, "rejected: fixture package mismatch")

        self._run(self._argv("install", "-r", self.trusted_apk), timeout=240)
        self._run(self._argv("shell", "settings", "put", "global",
                             "http_proxy", _PROXY_SETTING))
        try:
            trusted = self._await_fixture_lines(_TRUSTED_PKG)
            counts = self._receipt_counts()

            # Safe-GET request replay: re-issue the exact positive request
            # through the proxy; proven by a SECOND backend receipt of the
            # same request id. This is request replay, not response replay.
            replay_rc, _ = self._run(
                ["curl", "-sSf", "-x", self.proxy_url, "--cacert", self.ca_pem,
                 self.replay_url], timeout=60)
            counts_after = self._receipt_counts()
            replay_ok = (
                replay_rc == 0
                and counts.get("positive", 0) >= 1
                and counts_after.get("positive", 0) >= 2
            )

            self._run(self._argv("install", "-r", self.default_apk), timeout=240)
            default = self._await_fixture_lines(_DEFAULT_PKG)

            actual = {
                "positive_ok": "POSITIVE_OK" in trusted,
                "wronghost_rejected": "WRONGHOST_REJECTED" in trusted,
                "untrusted_rejected": "UNTRUSTED_REJECTED" in default,
                "positive_receipts": counts.get("positive", 0),
                "positive_receipts_after_replay": counts_after.get("positive", 0),
                "request_replay_second_receipt": replay_ok,
                "trusted_verdicts": sorted(trusted),
                "default_verdicts": sorted(default),
            }
            passed = (
                actual["positive_ok"]
                and actual["wronghost_rejected"]
                and actual["untrusted_rejected"]
                and replay_ok
            )
            detail = (
                ("fixture capture passed: " if passed else "fixture capture failed: ")
                + f"positive={actual['positive_ok']} "
                + f"wronghost_rejected={actual['wronghost_rejected']} "
                + f"untrusted_rejected={actual['untrusted_rejected']} "
                + f"replay_second_receipt={actual['request_replay_second_receipt']}"
            )[:_DETAIL_OUTPUT_BYTES]
            return FixtureResult(actual, detail)
        finally:
            self._run(self._argv("shell", "settings", "put", "global",
                                 "http_proxy", ":0"))
            self._run(self._argv("shell", "am", "force-stop", _TRUSTED_PKG))
            self._run(self._argv("shell", "am", "force-stop", _DEFAULT_PKG))
            self._run(self._argv("uninstall", _TRUSTED_PKG), timeout=120)
            self._run(self._argv("uninstall", _DEFAULT_PKG), timeout=120)


def adapter_from_env() -> VectorFixtureAdapter | None:
    """Configured only when all fixture paths are present; absent config means
    the action fails closed. Set by the D-061 contained harness only."""
    adb = os.environ.get("MOBIUS_PHANTOM_ADB", "").strip()
    serial = os.environ.get("MOBIUS_PHANTOM_SERIAL", "").strip()
    trusted = os.environ.get("MOBIUS_VECTOR_TRUSTED_APK", "").strip()
    default = os.environ.get("MOBIUS_VECTOR_DEFAULT_APK", "").strip()
    proxy = os.environ.get("MOBIUS_VECTOR_PROXY_URL", "").strip()
    replay_url = os.environ.get("MOBIUS_VECTOR_REPLAY_URL", "").strip()
    ca = os.environ.get("MOBIUS_VECTOR_CA_PEM", "").strip()
    receipts = os.environ.get("MOBIUS_VECTOR_RECEIPTS", "").strip()
    if not all([adb, trusted, default, proxy, replay_url, ca, receipts]):
        return None
    return VectorFixtureAdapter(
        adb_path=adb, serial=serial, trusted_apk=trusted, default_apk=default,
        proxy_url=proxy, replay_url=replay_url, ca_pem=ca, receipts_path=receipts,
    )
