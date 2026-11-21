#!/usr/bin/env bash
# Connected journey smoke: real consent-gated model hypothesis -> approved
# bounded observation-only Frida PoC on the pinned Allsafe lab app in the
# ephemeral emulator -> persisted evidence -> ARCHIVIST report, all through
# the product HTTP API. No hypothesis seeding, no approval bypass.
#
# Constraints honoured: lab target only, ephemeral emulator, no credentials,
# free OpenCode route (owner-authorized upstream scope: Mobius analysis data,
# free provider only), observation-only instrumentation stopped by cleanup,
# no image publication, free runner. The opencode CLI is CI job tooling only,
# never a repo dependency. The model leg is advisory and untuned: a model
# failure fails the journey honestly.
set -u

WORK="${GITHUB_WORKSPACE:-$(pwd)}"
OUT="$WORK/connected-journey"
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

# Lifecycle CLI configuration (same env the adapter uses).
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
python3 scripts/phantom_emulator_lifecycle.py start-server \
  --server-path "$FRIDA_BIN" \
  --sha256 "69846bb6e0a554bc776f9e71a57bc03a9af983f8eeec232d5875989e5199a977"
expect "frida-server-pushed" $?
frida-ps -D emulator-5554 >"$OUT/frida-ps.out" 2>&1
expect "frida-server-answering" $?

echo "== start Mobius API (sqlite, PHANTOM adapter + frida + free OpenCode route) =="
export MOBIUS_DB_URL="sqlite+pysqlite:///$OUT/mobius.db"
export MOBIUS_ARTIFACT_ROOT="$OUT/artifacts"
export MOBIUS_ENV="development"
# In-process RECON only: this job has no isolated worker fleet (local-development
# posture). Model-gated paths use the configured free OpenCode route only.
export MOBIUS_RECON_INLINE="1"
export MOBIUS_PHANTOM_FRIDA="$(command -v frida)"
export MOBIUS_MODEL_PROVIDER="opencode"
export MOBIUS_MODEL_NAME="${MOBIUS_MODEL_NAME:-deepseek-v4.1-flash-free}"
export MOBIUS_MODEL_TIMEOUT_SECONDS="${MOBIUS_MODEL_TIMEOUT_SECONDS:-180}"
export MOBIUS_SMOKE_API="http://127.0.0.1:8791"
export MOBIUS_SMOKE_APK="$APK"
python -m uvicorn mobius.api.app:app --host 127.0.0.1 --port 8791 \
  >"$OUT/api.out" 2>&1 &
API_PID=$!
scripts/healthcheck.sh http://127.0.0.1:8791 120
expect "api-health" $?

echo "== connected journey: consent -> model hypothesis -> approval -> PoC -> report =="
python3 scripts/connected_journey_smoke.py | tee "$OUT/journey.out"
journey_rc=${PIPESTATUS[0]}
expect "connected-journey" "$journey_rc"

kill "$API_PID" 2>/dev/null || true
timeout 30 adb -s emulator-5554 shell pkill -f mobius-frida-server 2>/dev/null || true

echo "== summary =="
[ "$fail" -eq 0 ] && echo "CONNECTED_JOURNEY: ALL_PASS" || echo "CONNECTED_JOURNEY: HAS_FAILURES"
exit "$fail"
