#!/usr/bin/env bash
# PHANTOM instrumentation smoke (D-060, approval-gated observation-only slice):
# on the CI emulator, install and launch the pinned Allsafe lab APK, start a
# pinned frida-server inside the ephemeral emulator only, boot the Mobius API
# with the PHANTOM adapter + frida tooling configured, and drive the
# approval-gated instrumentation PoC journey through the API.
#
# Constraints honoured: lab target only, ephemeral emulator, no credentials,
# no external target, observation-only fixed script, instrumentation stopped
# by the PoC cleanup step, no image publication, free runner.
set -u

WORK="${GITHUB_WORKSPACE:-$(pwd)}"
OUT="$WORK/phantom-frida-smoke"
mkdir -p "$OUT"
APK="$WORK/allsafe.apk"
FRIDA_BIN="$WORK/frida-server-17.27.4-android-x86_64"
fail=0

expect() { # name condition
  if [ "$2" -eq 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi
}

echo "== verify pinned digests =="
echo "d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9  $APK" | sha256sum -c -
expect "apk-sha256-pinned" $?

# Lifecycle CLI configuration (same env the adapter uses; exported here so
# the Mobius-managed boot and server-lifecycle steps run before the API).
export MOBIUS_PHANTOM_ADB="$(command -v adb)"
export MOBIUS_PHANTOM_SERIAL="emulator-5554"

echo "== Mobius-managed boot verification =="
python3 scripts/phantom_emulator_lifecycle.py wait-boot
expect "emulator-boot-verified" $?

echo "== install and launch lab app =="
timeout 240 adb -s emulator-5554 install -r "$APK" >"$OUT/install.out" 2>&1
expect "adb-install" $?
timeout 60 adb -s emulator-5554 shell monkey -p infosecadventures.allsafe \
  -c android.intent.category.LAUNCHER 1 >"$OUT/launch.out" 2>&1
expect "app-launched" $?
for _ in $(seq 1 30); do
  if timeout 15 adb -s emulator-5554 shell pidof infosecadventures.allsafe >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
timeout 15 adb -s emulator-5554 shell pidof infosecadventures.allsafe >"$OUT/app-pid.out" 2>&1
expect "app-process-running" $?

echo "== Mobius-managed pinned frida-server lifecycle (ephemeral emulator only) =="
# The CLI verifies the local binary against this pinned sha256 of the
# uncompressed frida-server 17.27.4 android-x86_64 before any device traffic.
python3 scripts/phantom_emulator_lifecycle.py start-server \
  --server-path "$FRIDA_BIN" \
  --sha256 "69846bb6e0a554bc776f9e71a57bc03a9af983f8eeec232d5875989e5199a977"
expect "frida-server-pushed" $?
frida-ps -D emulator-5554 >"$OUT/frida-ps.out" 2>&1
expect "frida-server-answering" $?

echo "== start Mobius API (sqlite, PHANTOM adapter + frida from env) =="
export MOBIUS_DB_URL="sqlite+pysqlite:///$OUT/mobius.db"
export MOBIUS_ARTIFACT_ROOT="$OUT/artifacts"
export MOBIUS_ENV="development"
# In-process RECON only: this job has no isolated worker fleet (local-development
# posture). Model-gated paths stay unused and disabled.
export MOBIUS_RECON_INLINE="1"
export MOBIUS_PHANTOM_ADB="$(command -v adb)"
export MOBIUS_PHANTOM_SERIAL="emulator-5554"
export MOBIUS_PHANTOM_FRIDA="$(command -v frida)"
export MOBIUS_SMOKE_DB_FILE="$OUT/mobius.db"
export MOBIUS_SMOKE_API="http://127.0.0.1:8791"
export MOBIUS_SMOKE_APK="$APK"
python -m uvicorn mobius.api.app:app --host 127.0.0.1 --port 8791 \
  >"$OUT/api.out" 2>&1 &
API_PID=$!
scripts/healthcheck.sh http://127.0.0.1:8791 120
expect "api-health" $?

echo "== API approval-gated instrumentation journey =="
python3 scripts/phantom_frida_smoke.py | tee "$OUT/journey.out"
journey_rc=${PIPESTATUS[0]}
expect "phantom-frida-journey" "$journey_rc"

kill "$API_PID" 2>/dev/null || true
timeout 30 adb -s emulator-5554 shell pkill -f mobius-frida-server 2>/dev/null || true

echo "== summary =="
[ "$fail" -eq 0 ] && echo "PHANTOM_FRIDA_SMOKE: ALL_PASS" || echo "PHANTOM_FRIDA_SMOKE: HAS_FAILURES"
exit "$fail"
