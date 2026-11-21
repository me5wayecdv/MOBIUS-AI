#!/usr/bin/env bash
printf "%s\n" "DISABLED DRAFT: exact technical review required; no execution." >&2
exit 78
# D-061 inner run: the whole contained-capture stack, executed INSIDE the
# no-uplink namespace as the unprivileged user with a scrubbed environment
# (invoked via netns_common.sh d061_ns_exec_user; execution held for review).
#
# Order: fresh HOME/AVD/TMPDIR -> internal adb server -> hand-written AVD ->
# pinned emulator boot (bounded) -> mock origin + mitmproxy (test CA,
# upstream verification on) + loopback tcpdump -> Mobius API (sqlite) ->
# fixture journey through the real product path -> bounded cleanup of every
# helper before the final inventory. No model leg; nothing upstream exists.
set -uo pipefail

WORK="${GITHUB_WORKSPACE:-$(pwd)}"
STAGE="$D061_STAGE_DIR"
RUN="$D061_RUN_DIR"
OUT="$WORK/d061-output"
mkdir -p "$OUT" "$RUN/home" "$RUN/tmp" "$RUN/avd" "$RUN/mitm-conf"

export HOME="$RUN/home"
export TMPDIR="$RUN/tmp"
export ANDROID_SDK_ROOT="$STAGE/sdk"
export ANDROID_HOME="$STAGE/sdk"
export ANDROID_AVD_HOME="$RUN/avd"
ADB="$STAGE/sdk/platform-tools/adb"
EMU="$STAGE/sdk/emulator/emulator"
fail=0
pids=()

expect() { if [ "$2" -eq 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi }

echo "== component versions (recorded, not trusted) =="
"$ADB" version | head -1
"$EMU" -version 2>/dev/null | head -3 || true
"$STAGE/mitm-venv/bin/mitmdump" --version | head -1
python3 --version

echo "== internal adb server =="
"$ADB" start-server
expect "adb-server-started" $?

echo "== hand-written AVD (pinned system image) =="
mkdir -p "$RUN/avd/d061.avd"
cat > "$RUN/avd/d061.ini" <<EOF
avd.ini.encoding=UTF-8
path=$RUN/avd/d061.avd
path.rel=avd/d061.avd
target=android-29
EOF
cat > "$RUN/avd/d061.avd/config.ini" <<EOF
avd.ini.encoding=UTF-8
hw.device.name=Nexus 6
image.sysdir.1=system-images/android-29/default/x86_64/
tag.id=default
disk.dataPartition.size=2G
EOF
echo "PASS avd-written"

echo "== emulator boot (bounded) =="
"$EMU" -avd d061 -no-window -gpu swiftshader_indirect -noaudio -no-boot-anim \
  -no-snapshot -wipe-data -ports 5554,5555 >"$OUT/emulator.log" 2>&1 &
pids+=($!)
"$ADB" -s emulator-5554 wait-for-device
booted=1
for _ in $(seq 1 100); do
  if [ "$("$ADB" -s emulator-5554 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
    booted=0; break
  fi
  sleep 3
done
expect "emulator-boot-verified" "$booted"

echo "== mock origin + mitmproxy + loopback capture =="
python3 "$WORK/scripts/d061/mock_origin.py" \
  "$STAGE/ca/origin.pem" "$STAGE/ca/origin.key" "$RUN/receipts.jsonl" 8443 \
  >"$OUT/mock-origin.log" 2>&1 &
pids+=($!)
sleep 2
grep -q "MOCK_ORIGIN_LISTENING" "$OUT/mock-origin.log"
expect "mock-origin-listening" $?

cat "$STAGE/ca/ca.key" "$STAGE/ca/ca.pem" > "$RUN/mitm-conf/mitmproxy-ca.pem"
printf '127.0.0.1 lab.mobius.local\n127.0.0.1 wronghost.mobius.local\n' > "$RUN/hosts"
"$STAGE/mitm-venv/bin/mitmdump" --listen-host 127.0.0.1 --listen-port 8080 \
  --set confdir="$RUN/mitm-conf" \
  --set modify_hosts="$RUN/hosts" \
  --set ssl_verify_upstream_trusted_ca="$STAGE/ca/ca.pem" \
  -w "$RUN/flows.mitm" >"$OUT/mitmdump.log" 2>&1 &
pids+=($!)
sleep 4
grep -qi "listening\|proxy server" "$OUT/mitmdump.log"
expect "mitmproxy-listening" $?

tcpdump -i lo -n -w "$RUN/capture.pcap" 'tcp port 8080 or tcp port 8443' \
  >"$OUT/tcpdump.log" 2>&1 &
pids+=($!)
echo "PASS capture-started"

echo "== Mobius API (sqlite, in-namespace) =="
export MOBIUS_DB_URL="sqlite+pysqlite:///$RUN/mobius.db"
export MOBIUS_ARTIFACT_ROOT="$RUN/artifacts"
export MOBIUS_ENV="development"
export MOBIUS_RECON_INLINE="1"
export MOBIUS_PHANTOM_ADB="$ADB"
export MOBIUS_PHANTOM_SERIAL="emulator-5554"
export MOBIUS_VECTOR_TRUSTED_APK="$STAGE/fixture-trustedCa.apk"
export MOBIUS_VECTOR_DEFAULT_APK="$STAGE/fixture-defaultTrust.apk"
export MOBIUS_VECTOR_PROXY_URL="http://127.0.0.1:8080"
export MOBIUS_VECTOR_REPLAY_URL="https://lab.mobius.local:8443/hello?req=positive"
export MOBIUS_VECTOR_CA_PEM="$STAGE/ca/ca.pem"
export MOBIUS_VECTOR_RECEIPTS="$RUN/receipts.jsonl"
export MOBIUS_SMOKE_API="http://127.0.0.1:8791"
cd "$WORK"
python -m uvicorn mobius.api.app:app --host 127.0.0.1 --port 8791 >"$OUT/api.log" 2>&1 &
pids+=($!)
"$WORK/scripts/healthcheck.sh" http://127.0.0.1:8791 120
expect "api-health" $?

echo "== fixture journey through the product path =="
python3 "$WORK/scripts/d061/vector_fixture_journey.py" | tee "$OUT/journey.log"
journey_rc=${PIPESTATUS[0]}
expect "fixture-journey" "$journey_rc"

echo "== evidence accounting (not a safety claim) =="
sha256sum "$RUN/capture.pcap" "$RUN/flows.mitm" 2>/dev/null | tee "$OUT/evidence-hashes.txt"
pcap_packets=$(tcpdump -n -r "$RUN/capture.pcap" 2>/dev/null | wc -l)
echo "pcap_packets=$pcap_packets" | tee -a "$OUT/evidence-hashes.txt"
receipts=$(wc -l < "$RUN/receipts.jsonl" 2>/dev/null || echo 0)
echo "backend_receipts=$receipts" | tee -a "$OUT/evidence-hashes.txt"

echo "== bounded cleanup: stop all helpers before final inventory =="
"$ADB" -s emulator-5554 emu kill 2>/dev/null || true
sleep 3
for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
sleep 3
for pid in "${pids[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
"$ADB" kill-server 2>/dev/null || true
cp "$RUN/receipts.jsonl" "$RUN/flows.mitm" "$RUN/capture.pcap" "$OUT/" 2>/dev/null || true

echo "== summary =="
[ "$fail" -eq 0 ] && echo "D061_FIXTURE: ALL_PASS" || echo "D061_FIXTURE: HAS_FAILURES"
exit "$fail"
