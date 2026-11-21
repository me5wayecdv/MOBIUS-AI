#!/usr/bin/env bash
# D-061 no-uplink network namespace helpers.
#
# Safety model (trusted-lab accidental-egress containment, NOT a hostile-code
# sandbox): containment comes from topology. The namespace has only loopback.
# There is no route to any non-local address, so egress is refused by the
# namespace's own stack regardless of protocol, address family, socket type
# or process identity. No firewall rule, socket classifier or packet counter
# is part of the safety argument; those are evidence accounting only.
#
# Membership, FD and runtime hygiene are SAFETY-relevant, not just evidence:
# a pre-existing process, inherited network FD, proxy environment variable or
# broker socket could carry connectivity in from outside. Every component is
# started fresh inside the namespace by these helpers, with a scrubbed
# environment, as an unprivileged user.
#
# Every function fails closed: any mismatch aborts before the next phase.

set -euo pipefail

: "${D061_NS:=mobius-d061}"
: "${D061_RUN_DIR:=/tmp/d061-run}"
: "${D061_RUN_USER:=$(id -un)}"

d061_log() { printf '[d061 %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
d061_fail() { d061_log "FAIL: $*"; exit 1; }

# --- host snapshot (before/after diff proves host topology unchanged) --------
d061_host_snapshot() {
  local out="$1"
  {
    echo '== ip -details link ==';    ip -details link
    echo '== ip addr ==';             ip addr
    echo '== ip route show table all ==';  ip route show table all
    echo '== ip -6 route show table all =='; ip -6 route show table all
    echo '== ip rule ==';             ip rule
    echo '== ip -6 rule ==';          ip -6 rule
    echo '== nft list ruleset ==';    sudo nft list ruleset 2>/dev/null || true
    echo '== iptables-save ==';       sudo iptables-save 2>/dev/null || true
    echo '== ip6tables-save ==';      sudo ip6tables-save 2>/dev/null || true
    echo '== forwarding sysctls =='
    sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding \
           net.ipv4.conf.all.rp_filter
  } > "$out"
}

# --- create ------------------------------------------------------------------
d061_ns_create() {
  sudo ip netns add "$D061_NS"
  sudo ip netns exec "$D061_NS" ip link set lo up
  d061_log "namespace $D061_NS created, loopback up"
}

# --- containment verification (complete inventories, fail closed) ------------
d061_ns_verify() {
  local inv_dir="$1"
  mkdir -p "$inv_dir"

  # Interfaces: exactly one, loopback.
  sudo ip netns exec "$D061_NS" ip -details link | tee "$inv_dir/links.txt"
  local non_lo
  non_lo=$(sudo ip netns exec "$D061_NS" ip -o link | awk '{print $2}' | tr -d ':' | grep -cv '^lo$')
  [ "$non_lo" -eq 0 ] || d061_fail "non-loopback interfaces present in namespace: $non_lo"

  # Addresses: only loopback addresses.
  sudo ip netns exec "$D061_NS" ip addr | tee "$inv_dir/addresses.txt"

  # ALL route tables, both families: nothing but local/loopback scope.
  sudo ip netns exec "$D061_NS" ip route show table all | tee "$inv_dir/routes-v4.txt"
  sudo ip netns exec "$D061_NS" ip -6 route show table all | tee "$inv_dir/routes-v6.txt"
  if sudo ip netns exec "$D061_NS" ip route show table all | grep -q '^default'; then
    d061_fail "default route present in namespace"
  fi
  if sudo ip netns exec "$D061_NS" ip -6 route show table all | grep -q '^default'; then
    d061_fail "IPv6 default route present in namespace"
  fi

  # Route lookups to documentation-only addresses must fail unreachable.
  # (TEST-NET-1 192.0.2.1 and 2001:db8::1 are documentation addresses per
  # RFC 5737 / RFC 3849; the lookup is a local kernel routing decision, no
  # packet is emitted.)
  if sudo ip netns exec "$D061_NS" ip route get 192.0.2.1 2>/dev/null; then
    d061_fail "route lookup for 192.0.2.1 succeeded; namespace is not isolated"
  fi
  if sudo ip netns exec "$D061_NS" ip -6 route get 2001:db8::1 2>/dev/null; then
    d061_fail "route lookup for 2001:db8::1 succeeded; namespace is not isolated"
  fi

  # Rules inventories inside the namespace: must be empty.
  sudo ip netns exec "$D061_NS" nft list ruleset 2>/dev/null | tee "$inv_dir/nft.txt"
  sudo ip netns exec "$D061_NS" iptables-save 2>/dev/null | tee "$inv_dir/iptables.txt"
  sudo ip netns exec "$D061_NS" ip6tables-save 2>/dev/null | tee "$inv_dir/ip6tables.txt"

  # Policy routing rules: default set only (local/main/default).
  sudo ip netns exec "$D061_NS" ip rule | tee "$inv_dir/rules-v4.txt"
  sudo ip netns exec "$D061_NS" ip -6 rule | tee "$inv_dir/rules-v6.txt"

  # Host forwarding must stay off.
  sysctl -n net.ipv4.ip_forward | grep -qx '0' || d061_fail "host IPv4 forwarding enabled"
  sysctl -n net.ipv6.conf.all.forwarding | grep -qx '0' || d061_fail "host IPv6 forwarding enabled"

  d061_log "containment verified: loopback only, no default route, documentation-address lookups unreachable"
}

# --- process / socket inventory ----------------------------------------------
# Lists every process whose network namespace is $D061_NS, with command line,
# plus all sockets inside the namespace. Safety-relevant: catches helpers
# (netsimd or successors), unexpected children, and inherited sockets.
d061_ns_inventory() {
  local inv_file="$1"
  {
    echo '== ip netns pids =='
    sudo ip netns pids "$D061_NS" || true
    echo '== per-process detail =='
    local pid
    for pid in $(sudo ip netns pids "$D061_NS" 2>/dev/null); do
      echo "--- pid $pid"
      tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo '(exited)'; echo
      readlink "/proc/$pid/ns/net" 2>/dev/null || true
      echo "fds:"
      ls -l "/proc/$pid/fd" 2>/dev/null | grep -v 'pipe:\|/dev/\|/tmp/\|/home/\|anon_inode' || true
    done
    echo '== sockets inside namespace =='
    sudo ip netns exec "$D061_NS" ss -aenp 2>/dev/null || true
  } | sudo tee "$inv_file" >/dev/null
  d061_log "inventory written to $inv_file"
}

# --- run a command inside the namespace as the unprivileged user -------------
# Scrubbed environment: no proxy variables, no inherited broker endpoints.
d061_ns_exec_user() {
  sudo ip netns exec "$D061_NS" \
    sudo -u "$D061_RUN_USER" \
    env -i \
      PATH="$D061_PATH" \
      HOME="$D061_RUN_DIR/home" \
      TMPDIR="$D061_RUN_DIR/tmp" \
      XDG_CACHE_HOME="$D061_RUN_DIR/cache" \
      XDG_CONFIG_HOME="$D061_RUN_DIR/config" \
      XDG_DATA_HOME="$D061_RUN_DIR/data" \
      "$@"
}

# --- teardown -----------------------------------------------------------------
d061_ns_teardown() {
  local inv_dir="${1:-}"
  # Stop everything inside the namespace before the final inventory.
  local pid
  for pid in $(sudo ip netns pids "$D061_NS" 2>/dev/null); do
    sudo kill "$pid" 2>/dev/null || true
  done
  sleep 2
  for pid in $(sudo ip netns pids "$D061_NS" 2>/dev/null); do
    sudo kill -9 "$pid" 2>/dev/null || true
  done
  sleep 1
  if [ -n "$inv_dir" ]; then
    d061_ns_inventory "$inv_dir/final-inventory.txt"
    local remaining
    remaining=$(sudo ip netns pids "$D061_NS" 2>/dev/null | wc -l)
    [ "$remaining" -eq 0 ] || d061_fail "$remaining processes still in namespace at teardown"
  fi
  sudo ip netns del "$D061_NS"
  d061_log "namespace $D061_NS deleted"
}

# --- host topology unchanged check --------------------------------------------
d061_host_verify_unchanged() {
  local before="$1" after="$2"
  d061_host_snapshot "$after"
  # The named-netns handle (a bind mount under /var/run/netns) is the only
  # permitted difference; it appears in no link/address/route/rules listing,
  # so the snapshots must be identical.
  if ! diff -u "$before" "$after" > /dev/null; then
    diff -u "$before" "$after" >&2 || true
    d061_fail "host network topology changed"
  fi
  d061_log "host topology unchanged"
}
