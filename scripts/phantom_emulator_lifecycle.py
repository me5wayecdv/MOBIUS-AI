#!/usr/bin/env python3
"""Mobius-owned PHANTOM emulator lifecycle CLI (D-060).

The CI smoke exercises the product's lifecycle operations through this CLI
instead of inline adb calls, so boot verification and the pinned frida-server
lifecycle stay Mobius-managed code with their own tests. Subcommands:

  wait-boot     bounded boot verification (wait-for-device + boot_completed)
  start-server  verify the pinned sha256 of a local frida-server binary,
                push and start it on the verified emulator only
  stop-server   idempotent cleanup: stop any frida-server on the emulator

Configuration comes from the same environment as the adapter
(MOBIUS_PHANTOM_ADB, optional MOBIUS_PHANTOM_SERIAL). An unconfigured
environment fails closed. Exit status is 0 on success, 1 on any failure,
with a fixed single-line message - no raw tool output is printed.
"""
from __future__ import annotations

import argparse
import sys

from mobius.services.phantom import adapter_from_env
from mobius.services.poc_runner import PoCAdapterUnavailable


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phantom_emulator_lifecycle")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("wait-boot")
    start = sub.add_parser("start-server")
    start.add_argument("--server-path", required=True)
    start.add_argument("--sha256", required=True)
    sub.add_parser("stop-server")
    args = parser.parse_args(argv)

    adapter = adapter_from_env()
    if adapter is None:
        print("FAIL lifecycle: MOBIUS_PHANTOM_ADB is not configured")
        return 1
    try:
        if args.command == "wait-boot":
            if adapter.wait_for_boot():
                print("PASS wait-boot: emulator boot verified (bounded)")
                return 0
            print("FAIL wait-boot: boot not verified within the bounded budget")
            return 1
        if args.command == "start-server":
            detail = adapter.start_instrumentation(
                args.server_path, args.sha256)
            print(f"PASS start-server: {detail}")
            return 0
        if args.command == "stop-server":
            print(f"PASS stop-server: {adapter.stop_instrumentation()}")
            return 0
    except PoCAdapterUnavailable as exc:
        print(f"FAIL {args.command}: {exc}")
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
