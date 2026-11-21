#!/usr/bin/env python3
"""HELD FOR REVIEW. Infrastructure-only no-uplink namespace capability check.

No emulator, proxy, application, package install, external canary or firewall
write. Only a bounded fresh Python workload doing a loopback roundtrip.
Run only after exact-script technical disposition: sudo python3 THIS_SCRIPT.
Trusted-lab accidental-egress test, not a hostile-code sandbox.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import tempfile

NS = "mobius-d061-infra-review"
IP = "/usr/sbin/ip"
SETPRIV = "/usr/bin/setpriv"
PYTHON = "/usr/bin/python3"

WORKLOAD = r'''
import os, socket, threading
assert os.geteuid() != 0
assert os.readlink('/proc/self/ns/net') == os.environ['EXPECTED_NETNS']
status = dict(line.strip().split(':', 1) for line in open('/proc/self/status') if ':' in line)
assert int(status['CapEff'].strip(), 16) == 0
assert status['NoNewPrivs'].strip() == '1'
# Only stdio is inherited. They are opened to /dev/null and a regular log file.
assert not any(os.readlink('/proc/self/fd/' + fd).startswith('socket:')
               for fd in ('0', '1', '2'))
srv = socket.socket()
srv.settimeout(5)
srv.bind(('127.0.0.1', 0))
srv.listen(1)
port = srv.getsockname()[1]
got = []
def serve():
    conn, _ = srv.accept()
    with conn:
        got.append(conn.recv(64))
t = threading.Thread(target=serve)
t.start()
with socket.create_connection(('127.0.0.1', port), timeout=5) as c:
    c.sendall(b'd061-loopback-ok')
t.join(6)
srv.close()
assert not t.is_alive() and got == [b'd061-loopback-ok'], got
print('LOOPBACK_ROUNDTRIP_OK', flush=True)
'''


def run(argv, *, timeout=10):
    return subprocess.run(argv, check=True, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, close_fds=True, timeout=timeout,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def ip(*args, ns=False):
    return run([IP] + (["-n", NS] if ns else []) + list(args)).stdout


def inventory(ns=False):
    return {
        "links": json.loads(ip("-j", "link", ns=ns)),
        "addresses": json.loads(ip("-j", "addr", ns=ns)),
        "routes4": json.loads(ip("-j", "-4", "route", "show", "table", "all", ns=ns)),
        "routes6": json.loads(ip("-j", "-6", "route", "show", "table", "all", ns=ns)),
        "rules4": json.loads(ip("-j", "-4", "rule", "show", ns=ns)),
        "rules6": json.loads(ip("-j", "-6", "rule", "show", ns=ns)),
    }


def host_snapshot():
    data = inventory()
    data["forwarding"] = {
        p: Path(p).read_text() for p in (
            "/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding")}
    # Read failures are failures, not silently empty inventories.
    for name, argv in {
        "nft": ["/usr/sbin/nft", "list", "ruleset"],
        "iptables": ["/usr/sbin/iptables-save"],
        "ip6tables": ["/usr/sbin/ip6tables-save"],
    }.items():
        data[name] = run(argv).stdout
    return data


def validate(data):
    assert len(data["links"]) == 1 and data["links"][0]["ifname"] == "lo"
    for interface in data["addresses"]:
        assert interface["ifname"] == "lo"
        for addr in interface.get("addr_info", []):
            assert ipaddress.ip_address(addr["local"]).is_loopback
    for key in ("routes4", "routes6"):
        for route in data[key]:
            assert route.get("dev") == "lo", route
            assert route.get("dst") != "default", route
            assert not route.get("gateway"), route
    for key in ("rules4", "rules6"):
        for rule in data[key]:
            assert rule.get("table") in ("local", "main", "default"), rule
            assert set(rule) <= {"priority", "src", "dst", "table", "protocol"}, rule
    # Local routing decisions only: these commands do not send packets.
    # Documentation prefixes RFC5737 / RFC3849. Assert the specific failure,
    # not merely any nonzero command result.
    for family, address in (("-4", "192.0.2.1"), ("-6", "2001:db8::1")):
        try:
            ip(family, "route", "get", address, ns=True)
        except subprocess.CalledProcessError as exc:
            assert "Network is unreachable" in exc.stderr, exc.stderr
        else:
            raise AssertionError("unexpected nonlocal route")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--review-authorized", action="store_true")
    args = parser.parse_args()
    if not args.review_authorized:
        raise SystemExit("Execution held. Exact-script technical disposition required.")
    if os.geteuid() != 0:
        raise SystemExit("Root orchestration required; workload privileges are dropped.")
    # Fresh artifacts, no reuse and no deletion of unrelated paths.
    out = Path(tempfile.mkdtemp(prefix="d061-infra-", dir="/tmp"))
    created = False
    before = host_snapshot()
    (out / "host-before.json").write_text(json.dumps(before, indent=2))
    failure = None
    try:
        # Refuse existing name. Never adopt/delete someone else's namespace.
        names = {row["name"] for row in json.loads(ip("-j", "netns", "list"))}
        assert NS not in names
        ip("netns", "add", NS)
        created = True
        ip("link", "set", "lo", "up", ns=True)
        state = inventory(ns=True)
        (out / "namespace.json").write_text(json.dumps(state, indent=2))
        validate(state)
        netns_id = run(
            [IP, "netns", "exec", NS, PYTHON, "-I", "-c",
             "import os; print(os.readlink('/proc/self/ns/net'))"]).stdout.strip()
        who = pwd.getpwnam("nobody")
        # No inherited env, network FDs, root identity or effective capabilities.
        # Workload uses no broker/socket path from the filesystem. Full harness
        # broker hygiene is a separate review item and NOT established here.
        with (out / "workload.log").open("w") as log:
            subprocess.run(
                [IP, "netns", "exec", NS, SETPRIV,
                 "--reuid", str(who.pw_uid), "--regid", str(who.pw_gid),
                 "--clear-groups", "--bounding-set=-all", "--inh-caps=-all",
                 "--ambient-caps=-all", "--no-new-privs", PYTHON, "-I", "-c", WORKLOAD],
                check=True, timeout=15, close_fds=True, cwd="/",
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "EXPECTED_NETNS": netns_id})
        assert "LOOPBACK_ROUNDTRIP_OK" in (out / "workload.log").read_text()
        final = inventory(ns=True)
        (out / "namespace-final.json").write_text(json.dumps(final, indent=2))
        validate(final)
    except BaseException as exc:
        failure = exc
    finally:
        if created:
            pids = ip("netns", "pids", NS).split()
            for pid in pids:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            # A bounded wait for reaping, fail if any process remains.
            import time
            for _ in range(20):
                if not ip("netns", "pids", NS).strip():
                    break
                time.sleep(0.1)
            remaining = ip("netns", "pids", NS).split()
            (out / "final-pids.json").write_text(json.dumps(remaining))
            ip("netns", "del", NS)
            if remaining and failure is None:
                failure = AssertionError("namespace processes remained at cleanup")
        after = host_snapshot()
        (out / "host-after.json").write_text(json.dumps(after, indent=2))
        # Strict comparison may fail conservatively if unrelated host lifetimes
        # changed. It must never turn an ambiguous difference into a pass.
        if before != after and failure is None:
            failure = AssertionError("host snapshot changed; inspect artifacts")
    print("artifacts=" + str(out))
    if failure is not None:
        raise failure
    print("INFRASTRUCTURE_ONLY_CHECK_OK. No emulator/proxy/app capture demonstrated.")


if __name__ == "__main__":
    main()
