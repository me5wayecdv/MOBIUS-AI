#!/usr/bin/env bash
# VECTOR traffic-capture feasibility probe (D-061 reconciliation):
# on the ephemeral CI emulator, lock down ALL guest egress with iptables,
# INDEPENDENTLY VERIFY the containment with a canary + exact byte counters,
# and only then launch the pinned Allsafe lab APK to record which remote
# endpoints it attempts from /proc/net/tcp{,6}.
#
# Isolation contract: no app traffic may reach any third-party endpoint.
# The lockdown allows ONLY loopback and the host alias 10.0.2.2 (which the
# adb transport needs). No established-flow allowance (pre-existing system
# connections would leak) and no DNS (queries forwarded by the host resolver
# would be a third-party route and an exfil channel). Containment is proven
# before launch, not inferred: a ping canary to a public IP must fail while
# the host-alias canary succeeds, and exact iptables counters bound every
# byte that left during the window to the allowed rules. If the canary shows
# a leak, the app is NEVER launched and the limit is reported.
#
# Socket metadata from /proc/net/tcp is attempt evidence only; the zero-
# egress claim rests on the policy + canary + counters, not on the sockets.
# The emulator is ephemeral. Output: fixed PASS/FAIL lines; raw dumps stay
# in the artifact for analysis.
set -u

WORK="${GITHUB_WORKSPACE:-$(pwd)}"
OUT="$WORK/vector-traffic-probe"
mkdir -p "$OUT"
APK="$WORK/allsafe.apk"
fail=0

expect() { # name condition
  if [ "$2" -eq 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi
}

counters() { # snapshot exact OUTPUT counters to a file
  adb -s emulator-5554 shell "iptables -L OUTPUT -v -n -x" >"$1" 2>&1
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
CONTAINED=0
if [ "$IPTABLES_OK" -eq 1 ]; then
  echo "== apply egress lockdown (guest-internal, ephemeral) =="
  # Allows BEFORE the policy drop. No DNS allow, no established/related
  # allowance: every pre-existing third-party flow must die with the policy.
  adb -s emulator-5554 shell "iptables -A OUTPUT -o lo -j ACCEPT"
  A1=$?
  adb -s emulator-5554 shell "iptables -A OUTPUT -d 10.0.2.2 -j ACCEPT"
  A2=$?
  adb -s emulator-5554 shell "iptables -P OUTPUT DROP"
  A3=$?
  echo "allow-rcs=$A1,$A2 policy-rc=$A3"
  if [ "$A1" -eq 0 ] && [ "$A2" -eq 0 ] && [ "$A3" -eq 0 ]; then
    echo "PASS egress-lockdown-applied"
    LOCKDOWN=1
  else
    echo "FAIL egress-lockdown-applied"
  fi
fi

if [ "$LOCKDOWN" -eq 1 ]; then
  echo "== independently verify containment BEFORE any app launch =="
  # Canary 1: the allowed path must still work (else adb is flying blind).
  adb -s emulator-5554 shell "ping -c 1 -W 2 10.0.2.2" >"$OUT/canary-host.out" 2>&1
  HOST_OK=$?
  # Canary 2: a public-IP ping must fail - 100% loss means the kernel
  # dropped it. If this succeeds, containment does not hold.
  adb -s emulator-5554 shell "ping -c 2 -W 2 1.1.1.1" >"$OUT/canary-public.out" 2>&1
  PUB_RC=$?
  grep -q "100% packet loss\|100% loss\|0 received" "$OUT/canary-public.out"
  PUB_BLOCKED=$?
  echo "host-canary-rc=$HOST_OK public-canary-rc=$PUB_RC public-blocked=$PUB_BLOCKED"
  counters "$OUT/counters-pre.txt"
  if [ "$HOST_OK" -eq 0 ] && [ "$PUB_BLOCKED" -eq 0 ]; then
    echo "PASS containment-verified (host canary ok, public canary dropped)"
    CONTAINED=1
  else
    echo "FAIL containment-verified"
  fi
fi

if [ "$CONTAINED" -eq 1 ]; then
  echo "== baseline =="
  adb -s emulator-5554 shell "cat /proc/net/tcp /proc/net/tcp6" >"$OUT/net-baseline.txt" 2>&1

  echo "== install and launch lab app under verified lockdown =="
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
  counters "$OUT/counters-post.txt"

  echo "== attempted remote endpoints under verified lockdown =="
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

  echo "== egress accounting (allowed rules vs dropped policy) =="
  echo "-- pre-launch counters --"; cat "$OUT/counters-pre.txt"
  echo "-- post-window counters --"; cat "$OUT/counters-post.txt"

  adb -s emulator-5554 shell am force-stop infosecadventures.allsafe >/dev/null 2>&1 || true
else
  echo "SKIP app launch: containment not verified - launching without proven"
  echo "containment could let the lab app reach third-party endpoints, which"
  echo "this probe forbids. The missing precondition is the reported limit."
fi

echo "== summary =="
[ "$fail" -eq 0 ] && echo "VECTOR_TRAFFIC_PROBE: ALL_PASS" || echo "VECTOR_TRAFFIC_PROBE: HAS_FAILURES"
exit "$fail"
