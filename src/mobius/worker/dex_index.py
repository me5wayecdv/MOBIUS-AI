"""Container entrypoint: build a bounded DEX code index from one staged APK."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from ..adapters.dex import DexIndexError, index_apk
from ..adapters.dex_payload import code_index_payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--max-methods", type=int, default=50000)
    args = parser.parse_args()
    source = Path(args.input)
    if source != Path("/work/input.apk") or not source.is_file() or source.is_symlink():
        print("input must be the staged /work/input.apk regular file", file=sys.stderr)
        return 2
    if not 1 <= args.max_methods <= 50000:
        print("max-methods must be between 1 and 50000", file=sys.stderr)
        return 2
    try:
        apk = source.read_bytes()
        digest = hashlib.sha256(apk).hexdigest()
        index = index_apk(apk, max_methods=args.max_methods)
        payload = code_index_payload(index, digest)
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (OSError, DexIndexError, ValueError) as exc:
        print(f"DEX indexing failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    if len(encoded) > 19 * 1024 * 1024:
        print("DEX index JSON exceeds 19 MiB output budget", file=sys.stderr)
        return 4
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
