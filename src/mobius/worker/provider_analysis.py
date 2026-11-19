"""Container entrypoint: bounded provider-exposure analysis of one staged APK.

Runs the deterministic detector (core.providers) over /work/input.apk inside a
networkless OCI container and emits the provider-analysis payload on stdout.
Findings are NOT decided here: the API validates this payload against the
authorized artifact digest and pushes the attributes through the gate.

Exit codes are failure classes, never decorations: 2 = staged-input contract
violation, 3 = analysis failure, 4 = output budget exceeded. A run that cannot
see a DEX entry does not fail: the ledger records the gap and the API
downgrades the claims that depended on seeing it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from ..adapters.android_manifest import parse_apk
from ..adapters.flow_adapt import adapt_code
from ..adapters.provider_payload import (
    MAX_PROVIDER_JSON_BYTES,
    provider_analysis_payload,
)
from ..core.providers import detect_provider_exposures

#: The only path this binary may read; the OCI contract stages exactly one file.
_STAGED_INPUT = Path("/work/input.apk")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    source = Path(args.input)
    if source != _STAGED_INPUT or not source.is_file() or source.is_symlink():
        print("input must be the staged /work/input.apk regular file", file=sys.stderr)
        return 2
    try:
        apk = source.read_bytes()
        digest = hashlib.sha256(apk).hexdigest()
        surface = parse_apk(apk)
        methods, registers_sizes, superclasses, try_regions, ledger = adapt_code(apk)
        exposures = detect_provider_exposures(
            surface, methods, registers_sizes, superclasses, try_regions
        )
        payload = provider_analysis_payload(
            artifact_sha256=digest,
            package_name=surface.package_name,
            methods_adapted=len(methods),
            ledger=ledger,
            exposures=list(exposures),
        )
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except Exception as exc:
        print(f"provider analysis failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    # Truthful bounds reporting: an over-bounds result is an explicit service
    # limit ("too large"), never a detector verdict and never a malformed
    # payload. The API's caps are documented limits; label them as such.
    if len(methods) > 50000:
        print(
            f"provider analysis result exceeds the service method bound "
            f"({len(methods)} adapted methods > 50000); the APK is too large "
            "for this service's explicit limits",
            file=sys.stderr,
        )
        return 4
    if len(encoded) > MAX_PROVIDER_JSON_BYTES:
        print("provider analysis JSON exceeds the output budget", file=sys.stderr)
        return 4
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
