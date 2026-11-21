#!/usr/bin/env bash
printf "%s\n" "DISABLED DRAFT: exact technical review required; no execution." >&2
exit 78
# D-061 infrastructure-only namespace capability check.
#
# The smallest possible demonstration of the containment property: create the
# namespace, bring up loopback, run the full containment verification, run a
# trivial unprivileged loopback-only workload inside it, tear down, and prove
# the host topology is unchanged.
#
# Bounds (per review): NO emulator, NO proxy, NO app, NO packets to any
# non-local address (the only lookups are local kernel routing decisions for
# documentation addresses RFC 5737 / RFC 3849), privileges dropped for the
# workload, bounded runtime, complete cleanup.
#
# EXECUTION IS HELD pending technical review of this exact script.

set -euo pipefail
cd "$(dirname "$0")"
source ./netns_common.sh

RUN="${D061_RUN_DIR}"
INV="$RUN/inventory"
mkdir -p "$INV" "$RUN/home" "$RUN/tmp" "$RUN/cache" "$RUN/config" "$RUN/data"

d061_host_snapshot "$INV/host-before.txt"

d061_ns_create
trap 'd061_ns_teardown "$INV" || true; d061_host_verify_unchanged "$INV/host-before.txt" "$INV/host-after.txt" || true' EXIT

d061_ns_verify "$INV"

# Trivial unprivileged workload: a loopback-only TCP round trip inside the
# namespace, proving loopback works while nothing else exists.
D061_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  d061_ns_exec_user bash -c '
    set -euo pipefail
    cd "$TMPDIR"
    python3 - <<'"'"'PY'"'"'
import socket, threading
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(1)
port = srv.getsockname()[1]
got = []
def serve():
    conn, _ = srv.accept()
    got.append(conn.recv(16))
threading.Thread(target=serve, daemon=True).start()
c = socket.create_connection(("127.0.0.1", port), timeout=5)
c.sendall(b"d061-loopback-ok")
c.close()
srv.close()
assert got == [b"d061-loopback-ok"], got
print("LOOPBACK_ROUNDTRIP_OK")
PY
  '

d061_ns_inventory "$INV/mid-inventory.txt"
d061_ns_teardown "$INV"
trap - EXIT
d061_host_verify_unchanged "$INV/host-before.txt" "$INV/host-after.txt"

d061_log "CAPABILITY_CHECK_OK"
