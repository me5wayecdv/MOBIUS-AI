"""Generate the CI worker-pipeline fixture APK.

Unlike scripts/seed_demo_apk.py (plain-text manifest plus a DEX stub - enough
for the startup smoke, which never runs the pipeline), this fixture carries a
real binary AXML manifest (the tests/_axml encoder, which androguard decodes in
the unit tests) and the real tests/fixtures/dex/AnalysisTest.dex, so the RECON
and DEX worker jobs exercise their actual decode/index paths.
"""
from __future__ import annotations

import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tests"))

from _axml import encode, manifest_xml  # noqa: E402


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("frontend/e2e/fixtures/pipeline-lab.apk")
    out.parent.mkdir(parents=True, exist_ok=True)
    entries = (
        ("AndroidManifest.xml", encode(manifest_xml())),
        ("classes.dex", (REPO / "tests" / "fixtures" / "dex" / "AnalysisTest.dex").read_bytes()),
    )
    with ZipFile(out, "w", ZIP_DEFLATED) as archive:
        for name, data in entries:
            info = ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    print(out)


if __name__ == "__main__":
    main()
