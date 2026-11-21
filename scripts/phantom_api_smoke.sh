#!/usr/bin/env bash
# PHANTOM API smoke (D-060 integration slice): on the CI emulator, install
# the pinned public Allsafe lab APK, boot the Mobius API on sqlite with the
# PHANTOM adapter configured, and drive a real read_only emulator PoC plan
# through the API end-to-end (upload -> authorization -> scan -> execute ->
# persisted run/evidence read-back).
#
# Constraints honoured: lab target only, ephemeral emulator, no credentials,
# no external target, read-only probes, no image publication, free runner.
set -u

WORK="${GITHUB_WORKSPACE:-$(pwd)}"
OUT="$WORK/phantom-smoke"
mkdir -p "$OUT"
APK="$WORK/allsafe.apk"
fail=0

expect() { # name condition
  if [ "$2" -eq 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi
}

echo "== verify pinned digest =="
echo "d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9  $APK" | sha256sum -c -
expect "apk-sha256-pinned" $?

echo "== install on emulator =="
timeout 240 adb -s emulator-5554 install -r "$APK" >"$OUT/install.out" 2>&1
expect "adb-install" $?

echo "== start Mobius API (sqlite, PHANTOM adapter from env) =="
export MOBIUS_DB_URL="sqlite+pysqlite:///$OUT/mobius.db"
export MOBIUS_ARTIFACT_ROOT="$OUT/artifacts"
export MOBIUS_ENV="development"
# This job runs the whole stack in one CI job with no isolated worker fleet,
# the same posture as local development; in-process RECON is enabled for
# manifest parsing only. Model-gated paths stay unused and disabled.
export MOBIUS_RECON_INLINE="1"
export MOBIUS_PHANTOM_ADB="$(command -v adb)"
export MOBIUS_PHANTOM_SERIAL="emulator-5554"
export MOBIUS_SMOKE_DB_FILE="$OUT/mobius.db"
export MOBIUS_SMOKE_API="http://127.0.0.1:8791"
export MOBIUS_SMOKE_APK="$APK"
python -m uvicorn mobius.api.app:app --host 127.0.0.1 --port 8791 \
  >"$OUT/api.out" 2>&1 &
API_PID=$!
scripts/healthcheck.sh http://127.0.0.1:8791 120
expect "api-health" $?

echo "== API PoC journey =="
python3 scripts/phantom_api_smoke.py | tee "$OUT/journey.out"
journey_rc=${PIPESTATUS[0]}
expect "phantom-api-journey" "$journey_rc"

kill "$API_PID" 2>/dev/null || true

echo "== summary =="
[ "$fail" -eq 0 ] && echo "PHANTOM_API_SMOKE: ALL_PASS" || echo "PHANTOM_API_SMOKE: HAS_FAILURES"
exit "$fail"
