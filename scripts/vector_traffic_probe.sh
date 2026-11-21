#!/usr/bin/env bash
# VECTOR traffic-capture feasibility probe (D-061 reconciliation):
# on the ephemeral CI emulator, lock down ALL guest egress with iptables
# (allowing only the loopback, the host alias 10.0.2.2 so adb keeps working,
# and DNS via the host resolver), then launch the pinned Allsafe lab APK and
# record which remote endpoints it attempts from /proc/net/tcp{,6}.
#
# Isolation contract: no app traffic can reach any third-party endpoint -
# every outbound connection except the explicit allows is dropped inside the
# guest before launch. The probe observes connection attempts only; it
# captures no content and contacts nothing. The emulator is ephemeral.
#
# Output: fixed-format PASS/FAIL lines plus parsed endpoint evidence in
# $OUT. Raw dumps stay in the artifact for analysis.
set -u

WORK="${GITHUB_WORKSPACE:-$(pwd)}"
OUT="$WORK/vector-traffic-probe"
mkdir -p "$OUT"
APK="$WORK/allsafe.apk"
fail=0

expect() { # name condition
  if [ "$2" -eq 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi
}

echo "== verify emulator and pinned APK =="
QEMU="$(adb -s emulator-5554 shell getprop ro.kernel.qemu | tr -d '\r')"
[ "$QEMU" = "1" ]
expect "verified-emulator" $?
echo "d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9  $APK" | sha256sum -c -
expect "apk-sha256-pinned" $?

echo "== adb root =="
adb -s emulator-5554 root >"$OUT/adb-root.out" 2>&1 || true
adb -s emulator-5554 wait-for-device
sleep 2

echo "== iptables availability =="
adb -s emulator-5554 shell "which iptables" >"$OUT/iptables-which.out" 2>&1
WHICH_RC=$?
adb -s emulator-5554 shell "iptables -L OUTPUT -n 2>&1 | head -5" >"$OUT/iptables-list.out" 2>&1
LIST_RC=$?
echo "which-rc=$WHICH_RC list-rc=$LIST_RC"
if [ "$WHICH_RC" -eq 0 ] && [ "$LIST_RC" -eq 0 ]; then
  echo "PASS iptables-available"
  IPTABLES_OK=1
else
  echo "FAIL iptables-available"
  IPTABLES_OK=0
fi

LOCKDOWN=0
if [ "$IPTABLES_OK" -eq 1 ]; then
  echo "== apply egress lockdown (guest-internal, ephemeral) =="
  # Allows BEFORE the policy drop: loopback, the host alias (adb transport
  # safety), host-resolver DNS, and already-established flows.
  adb -s emulator-5554 shell "iptables -A OUTPUT -o lo -j ACCEPT"
  A1=$?
  adb -s emulator-5554 shell "iptables -A OUTPUT -d 10.0.2.2 -j ACCEPT"
  A2=$?
  adb -s emulator-5554 shell "iptables -A OUTPUT -d 10.0.2.3 -p udp --dport 53 -j ACCEPT"
  A3=$?
  adb -s emulator-5554 shell "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
  A4=$?
  adb -s emulator-5554 shell "iptables -P OUTPUT DROP"
  A5=$?
  echo "allow-rcs=$A1,$A2,$A3,$A4 policy-rc=$A5"
  adb -s emulator-5554 shell "iptables -L OUTPUT -n -v" >"$OUT/iptables-final.out" 2>&1
  if [ "$A1" -eq 0 ] && [ "$A2" -eq 0 ] && [ "$A3" -eq 0 ] && [ "$A4" -eq 0 ] && [ "$A5" -eq 0 ]; then
    echo "PASS egress-lockdown-applied"
    LOCKDOWN=1
  else
    echo "FAIL egress-lockdown-applied"
  fi
fi

if [ "$LOCKDOWN" -eq 1 ]; then
  echo "== baseline =="
  adb -s emulator-5554 shell "cat /proc/net/tcp /proc/net/tcp6" >"$OUT/net-baseline.txt" 2>&1

  echo "== install and launch lab app under lockdown =="
  timeout 240 adb -s emulator-5554 install -r "$APK" >"$OUT/install.out" 2>&1
  expect "adb-install" $?
  timeout 60 adb -s emulator-5554 shell monkey -p infosecadventures.allsafe \
    -c android.intent.category.LAUNCHER 1 >"$OUT/launch.out" 2>&1
  expect "app-launched" $?

  echo "== sample connection attempts (30s) =="
  : >"$OUT/net-samples.txt"
  for i in $(seq 1 10); do
    echo "--- sample $i $(date +%T) ---" >>"$OUT/net-samples.txt"
    adb -s emulator-5554 shell "cat /proc/net/tcp /proc/net/tcp6" >>"$OUT/net-samples.txt" 2>&1
    sleep 3
  done
  adb -s emulator-5554 shell pidof infosecadventures.allsafe >"$OUT/app-pid.out" 2>&1 || true

  echo "== attempted remote endpoints under lockdown =="
  python3 - "$OUT/net-samples.txt" >"$OUT/attempts.txt" <<'PYEOF'
import sys, collections
attempts = collections.Counter()
with open(sys.argv[1]) as fh:
    for line in fh:
        parts = line.split()
        if len(parts) < 4 or parts[0] == "sl":
            continue
        rem = parts[2]
        st = parts[3]
        try:
            addr_hex, port_hex = rem.rsplit(":", 1)
        except ValueError:
            continue
        port = int(port_hex, 16)
        if port == 0:
            continue
        if len(addr_hex) == 8:  # IPv4, little-endian
            b = bytes.fromhex(addr_hex)
            ip = ".".join(str(x) for x in reversed(b))
        else:  # IPv6 shown raw, truncated
            ip = "v6:" + addr_hex[:8]
        attempts[(ip, port, st)] += 1
state_names = {"02": "SYN_SENT", "01": "ESTABLISHED", "08": "CLOSE_WAIT"}
for (ip, port, st), n in sorted(attempts.items()):
    zone = "host-alias" if ip.startswith("10.0.2.") else (
        "loopback" if ip.startswith("127.") else "PUBLIC")
    print(f"{zone} {ip}:{port} {state_names.get(st, st)} seen={n}")
PYEOF
  cat "$OUT/attempts.txt"
  expect "attempts-recorded" $?

  adb -s emulator-5554 shell am force-stop infosecadventures.allsafe >/dev/null 2>&1 || true
else
  echo "SKIP app launch: lockdown unavailable - launching without it would"
  echo "let the lab app reach third-party endpoints, which this probe forbids."
fi

echo "== summary =="
[ "$fail" -eq 0 ] && echo "VECTOR_TRAFFIC_PROBE: ALL_PASS" || echo "VECTOR_TRAFFIC_PROBE: HAS_FAILURES"
exit "$fail"
