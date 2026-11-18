"""Generate a byte-for-byte reproducible minimal APK container for CI E2E only."""
from __future__ import annotations
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

out = Path("frontend/e2e/fixtures/demo-lab.apk")
out.parent.mkdir(parents=True, exist_ok=True)
manifest = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.lab" android:versionCode="1" android:versionName="1.0">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/>
  <application android:label="MOBIUS CI Fixture">
    <activity android:name=".MainActivity" android:exported="true"/>
  </application>
</manifest>"""
with ZipFile(out, "w", ZIP_DEFLATED) as archive:
    for name, data in (("AndroidManifest.xml", manifest), ("classes.dex", b"dex\n035\x00" + b"\x00" * 32)):
        info = ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
        info.compress_type = ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, data)
print(out)
