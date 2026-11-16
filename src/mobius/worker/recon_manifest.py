"""Container entrypoint: decode only AndroidManifest.xml from a staged APK."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..adapters.android_manifest import ManifestParseError, extract_manifest_bytes, to_text_xml


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    source = Path(args.input)
    if source != Path("/work/input.apk") or not source.is_file() or source.is_symlink():
        print("input must be the staged /work/input.apk regular file", file=sys.stderr)
        return 2
    try:
        raw = extract_manifest_bytes(source.read_bytes())
        xml = to_text_xml(raw)
    except (OSError, ManifestParseError) as exc:
        print(f"manifest decode failed: {exc}", file=sys.stderr)
        return 3
    if len(xml) > 10 * 1024 * 1024:
        print("decoded manifest exceeds output limit", file=sys.stderr)
        return 4
    sys.stdout.buffer.write(xml)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
