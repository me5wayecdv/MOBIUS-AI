#!/usr/bin/env python3
"""Fetch the benchmark corpus, verifying every pinned SHA-256.

    python scripts/fetch_corpus.py --dest /tmp/mobius-corpus
    python -m mobius.tools.benchmark /tmp/mobius-corpus/corpus.resolved.json

The APKs are not stored in this repository. This script is what makes the corpus
reproducible: `corpus/corpus.json` names a public artefact and its hash, and a byte that does
not match its hash is refused rather than analysed. A benchmark whose inputs can change
silently is not a measurement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

DEFAULT_MANIFEST = Path(__file__).resolve().parent.parent / "corpus" / "corpus.json"


def _get(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github.raw",
            "User-Agent": "mobius-corpus-fetch",
        },
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def fetch(manifest_path: Path, dest: Path, *, offline: bool) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    dest.mkdir(parents=True, exist_ok=True)
    resolved: list[dict] = []
    problems: list[str] = []

    for sample in manifest["samples"]:
        target = dest / sample["file"]
        expected = sample["sha256"]

        if target.exists():
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            if digest == expected:
                print(f"  ok       {sample['name']} (cached)")
                resolved.append({**sample, "apk_path": str(target)})
                continue
            print(f"  re-fetch {sample['name']} (cached bytes do not match the pinned hash)")
            target.unlink()

        if offline:
            problems.append(f"{sample['name']}: not present and --offline was given")
            continue

        try:
            data = _get(sample["url"])
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            problems.append(f"{sample['name']}: download failed ({type(exc).__name__}: {exc})")
            continue

        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            problems.append(
                f"{sample['name']}: SHA-256 mismatch (expected {expected[:16]}…, "
                f"got {digest[:16]}…) - refusing to use bytes we cannot pin"
            )
            continue

        target.write_bytes(data)
        print(f"  fetched  {sample['name']} ({len(data)} bytes)")
        resolved.append({**sample, "apk_path": str(target)})

    out = dest / "corpus.resolved.json"
    out.write_text(
        json.dumps({"samples": resolved, "problems": problems}, indent=2), encoding="utf-8"
    )

    if problems:
        print("\nPROBLEMS:", file=sys.stderr)
        for line in problems:
            print(f"  - {line}", file=sys.stderr)

    print(f"\n{len(resolved)}/{len(manifest['samples'])} samples ready -> {out}")
    return {"resolved": len(resolved), "problems": problems}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--dest", type=Path, default=Path("corpus-apks"))
    parser.add_argument(
        "--offline",
        action="store_true",
        help="use only files already present; never touch the network",
    )
    args = parser.parse_args(argv)

    result = fetch(args.manifest, args.dest, offline=args.offline)
    # A partial corpus is still usable, but it must be obvious that it is partial.
    return 1 if result["problems"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
