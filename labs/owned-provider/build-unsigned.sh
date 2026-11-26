#!/usr/bin/env bash
# Offline compilation only. No SDK download, emulator, adb, install, signing or publication.
set -euo pipefail
umask 077
: "${ANDROID_JAR:?Set the path to a locally installed API28 android.jar}"
: "${ANDROID_BUILD_TOOLS:?Set an existing Android build-tools directory}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
for tool in aapt2 d8; do test -x "$ANDROID_BUILD_TOOLS/$tool"; done
test -f "$ANDROID_JAR"
command -v javac
command -v jar
OUT="$(mktemp -d "${TMPDIR:-/tmp}/mobius-ownedlab.XXXXXXXX")"
mkdir -p "$OUT/classes"
"$ANDROID_BUILD_TOOLS/aapt2" link -I "$ANDROID_JAR" --manifest "$ROOT/AndroidManifest.xml" -o "$OUT/resources.apk"
javac -source 8 -target 8 -encoding UTF-8 -bootclasspath "$ANDROID_JAR" -d "$OUT/classes" "$ROOT"/src/com/mobius/ownedlab/*.java
jar cf "$OUT/classes.jar" -C "$OUT/classes" .
"$ANDROID_BUILD_TOOLS/d8" --min-api 26 --lib "$ANDROID_JAR" --output "$OUT" "$OUT/classes.jar"
python3 - "$OUT" <<'PY'
from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED,ZipInfo
import sys
root=Path(sys.argv[1])
with ZipFile(root/'resources.apk') as src,ZipFile(root/'owned-provider-UNSIGNED.apk','w') as dst:
    for name,data in sorted([(i.filename,src.read(i)) for i in src.infolist()]+[('classes.dex',(root/'classes.dex').read_bytes())]):
        item=ZipInfo(name,date_time=(2020,1,1,0,0,0));item.compress_type=ZIP_DEFLATED;item.external_attr=0o100644<<16
        dst.writestr(item,data)
print(root/'owned-provider-UNSIGNED.apk')
PY
