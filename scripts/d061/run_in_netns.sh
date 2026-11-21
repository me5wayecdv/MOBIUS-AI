#!/usr/bin/env bash
printf "%s\n" "DISABLED DRAFT: exact technical review required; no execution." >&2
exit 78
# D-061 outer wrapper: host snapshot -> namespace create -> containment
# verification -> inner run inside the namespace (unprivileged, scrubbed
# environment) -> final inventory -> namespace teardown -> host-topology
# unchanged proof. Any verification mismatch aborts before the app leg.
# EXECUTION HELD pending technical review of these exact scripts.
set -euo pipefail
cd "$(dirname "$0")"
source ./netns_common.sh

INV="$D061_RUN_DIR/inventory"
mkdir -p "$INV" "$D061_RUN_DIR/home" "$D061_RUN_DIR/tmp" \
         "$D061_RUN_DIR/cache" "$D061_RUN_DIR/config" "$D061_RUN_DIR/data"

d061_host_snapshot "$INV/host-before.txt"
d061_ns_create

rc=0
trap 'd061_ns_teardown "$INV" || true; d061_host_verify_unchanged "$INV/host-before.txt" "$INV/host-after.txt" || true' EXIT

d061_ns_verify "$INV"
d061_ns_inventory "$INV/pre-run-inventory.txt"

set +e
d061_ns_exec_user bash "$(cd ..; pwd)/d061/inner_run.sh"
rc=$?
set -e
d061_log "inner run exit rc=$rc"

d061_ns_teardown "$INV"
trap - EXIT
d061_host_verify_unchanged "$INV/host-before.txt" "$INV/host-after.txt"

if [ "$rc" -eq 0 ]; then
  d061_log "D061_CONTAINED_RUN: ALL_PASS"
else
  d061_log "D061_CONTAINED_RUN: HAS_FAILURES rc=$rc"
fi
exit "$rc"
