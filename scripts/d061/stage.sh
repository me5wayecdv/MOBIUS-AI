#!/usr/bin/env bash
# D-061 staging: downloads and verifies every pinned dependency, builds the
# fixture APKs, and generates the per-run test CA. Runs OUTSIDE the
# namespace, before any containment step. Network access happens only here,
# only to the pinned URLs.
#
# Produces $D061_STAGE_DIR (default /tmp/d061-stage) with:
#   sdk/            emulator + platform-tools + platforms;android-34 +
#                   build-tools;34.0.0 + system-images;android-29;default;x86_64
#   gradle/         gradle 8.9 distribution
#   ca/             per-run Mobius test CA (lab use only, destroyed at cleanup)
#   fixture/        built APKs (trustedCa + defaultTrust flavors)
#   STAGING_MANIFEST.txt  version and sha256 record of every artifact
set -euo pipefail
cd "$(dirname "$0")"
source ./pins.env

STAGE="${D061_STAGE_DIR:-/tmp/d061-stage}"
MANIFEST="$STAGE/STAGING_MANIFEST.txt"
mkdir -p "$STAGE/dl" "$STAGE/sdk" "$STAGE/ca"
: > "$MANIFEST"

log() { printf '[d061-stage %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

fetch() { # url sha1 dest
  local url="$1" sha1="$2" dest="$3"
  curl -sSfL -o "$dest" "$url"
  echo "$sha1  $dest" | sha1sum -c - >/dev/null
  { echo "url=$url"; echo "sha1=$sha1"; echo "sha256=$(sha256sum "$dest" | awk '{print $1}')"; echo; } >> "$MANIFEST"
}

log "emulator $EMULATOR_VERSION"
fetch "$EMULATOR_ZIP_URL" "$EMULATOR_ZIP_SHA1" "$STAGE/dl/emulator.zip"
unzip -q -o "$STAGE/dl/emulator.zip" -d "$STAGE/sdk"

log "platform-tools"
fetch "$PLATFORM_TOOLS_URL" "$PLATFORM_TOOLS_SHA1" "$STAGE/dl/platform-tools.zip"
unzip -q -o "$STAGE/dl/platform-tools.zip" -d "$STAGE/sdk"

log "platforms;android-34 (fixture compileSdk only)"
fetch "$PLATFORM34_URL" "$PLATFORM34_SHA1" "$STAGE/dl/platform34.zip"
mkdir -p "$STAGE/sdk/platforms/android-34"
unzip -q -o "$STAGE/dl/platform34.zip" -d "$STAGE/sdk/platforms"
# the zip root is android-14/ which IS the platform dir for API 34
if [ -d "$STAGE/sdk/platforms/android-14" ]; then
  mv "$STAGE/sdk/platforms/android-14" "$STAGE/sdk/platforms/android-34-tmp"
  rm -rf "$STAGE/sdk/platforms/android-34"
  mv "$STAGE/sdk/platforms/android-34-tmp" "$STAGE/sdk/platforms/android-34"
fi

log "build-tools;34.0.0"
fetch "$BUILD_TOOLS_URL" "$BUILD_TOOLS_SHA1" "$STAGE/dl/build-tools.zip"
mkdir -p "$STAGE/sdk/build-tools/34.0.0"
unzip -q -o "$STAGE/dl/build-tools.zip" -d "$STAGE/sdk/build-tools/34.0.0"

log "system image $SYSIMG_VERSION"
fetch "$SYSIMG_ZIP_URL" "$SYSIMG_ZIP_SHA1" "$STAGE/dl/sysimg.zip"
mkdir -p "$STAGE/sdk/system-images/android-29/default/x86_64"
unzip -q -o "$STAGE/dl/sysimg.zip" -d "$STAGE/sdk/system-images/android-29/default/x86_64"
# zip root is x86_64/; flatten
if [ -d "$STAGE/sdk/system-images/android-29/default/x86_64/x86_64" ]; then
  mv "$STAGE/sdk/system-images/android-29/default/x86_64/x86_64"/* \
     "$STAGE/sdk/system-images/android-29/default/x86_64/"
  rmdir "$STAGE/sdk/system-images/android-29/default/x86_64/x86_64"
fi

log "gradle $GRADLE_VERSION"
curl -sSfL -o "$STAGE/dl/gradle.zip" "$GRADLE_DIST_URL"
echo "$GRADLE_DIST_SHA256  $STAGE/dl/gradle.zip" | sha256sum -c - >/dev/null
{ echo "url=$GRADLE_DIST_URL"; echo "sha256=$GRADLE_DIST_SHA256"; echo; } >> "$MANIFEST"
unzip -q -o "$STAGE/dl/gradle.zip" -d "$STAGE"
mv "$STAGE/gradle-$GRADLE_VERSION" "$STAGE/gradle"

log "mitmproxy $MITMPROXY_VERSION (new dependency, review-flagged)"
python3 -m venv "$STAGE/mitm-venv"
"$STAGE/mitm-venv/bin/pip" install --quiet --upgrade pip
"$STAGE/mitm-venv/bin/pip" download --quiet --no-deps -d "$STAGE/dl" \
  "mitmproxy==$MITMPROXY_VERSION"
echo "$MITMPROXY_WHEEL_SHA256  $STAGE/dl/mitmproxy-$MITMPROXY_VERSION-py3-none-any.whl" \
  | sha256sum -c - >/dev/null
{ echo "mitmproxy==$MITMPROXY_VERSION"; echo "sha256=$MITMPROXY_WHEEL_SHA256"; echo; } >> "$MANIFEST"
"$STAGE/mitm-venv/bin/pip" install --quiet "mitmproxy==$MITMPROXY_VERSION"
# Record the fully resolved dependency set for review; transitive wheels are
# CI tooling pinned by this freeze, not repo dependencies.
"$STAGE/mitm-venv/bin/pip" freeze >> "$MANIFEST"

log "per-run Mobius test CA (lab only)"
openssl req -x509 -newkey rsa:2048 -keyout "$STAGE/ca/ca.key" -out "$STAGE/ca/ca.pem" \
  -days 1 -nodes -subj "/CN=Mobius D-061 Test CA" >/dev/null 2>&1
# mock origin server certificate for lab.mobius.local, signed by the test CA
openssl req -newkey rsa:2048 -keyout "$STAGE/ca/origin.key" -out "$STAGE/ca/origin.csr" \
  -nodes -subj "/CN=lab.mobius.local" >/dev/null 2>&1
printf 'subjectAltName=DNS:lab.mobius.local\n' > "$STAGE/ca/origin.ext"
openssl x509 -req -in "$STAGE/ca/origin.csr" -CA "$STAGE/ca/ca.pem" -CAkey "$STAGE/ca/ca.key" \
  -CAcreateserial -out "$STAGE/ca/origin.pem" -days 1 -extfile "$STAGE/ca/origin.ext" >/dev/null 2>&1
{ echo "test-ca-sha256=$(sha256sum "$STAGE/ca/ca.pem" | awk '{print $1}')"; echo; } >> "$MANIFEST"

log "fixture APKs (gradle + AGP $AGP_VERSION, new dependency, review-flagged)"
cp "$STAGE/ca/ca.pem" \
  "$(dirname "$0")/../../fixture/d061lab/app/src/trustedCa/res/raw/mobius_test_ca.pem"
cd "$(dirname "$0")/../../fixture/d061lab"
echo "sdk.dir=$STAGE/sdk" > local.properties
mkdir -p "$STAGE/sdk/licenses"
printf '\n8933bad161af4178b1185d1a37fbf41ea5269c55\n' > "$STAGE/sdk/licenses/android-sdk-license"
printf '\nd56f5187479451eabf01fb78af6dfcb131a6481e\n' >> "$STAGE/sdk/licenses/android-sdk-license"
"$STAGE/gradle/bin/gradle" --no-daemon -g "$STAGE/gradle-home" \
  assembleTrustedCaDebug assembleDefaultTrustDebug
cd - >/dev/null
{ find "$(dirname "$0")/../../fixture/d061lab/app/build/outputs/apk" -name '*.apk' \
    | sort | while read -r apk; do
        echo "apk=$apk sha256=$(sha256sum "$apk" | awk '{print $1}')"; done; echo; } >> "$MANIFEST"

log "staging complete; manifest at $MANIFEST"
