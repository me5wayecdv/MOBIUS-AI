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
import re
import sys
import time
import uuid
import traceback

NS = ""  # Fresh per invocation; cleanup-only mode recovers the recorded name.
IP = "/usr/sbin/ip"
SETPRIV = "/usr/bin/setpriv"
PYTHON = "/usr/bin/python3"
DIAGNOSTIC_DIR = None
COMMAND_SEQUENCE = 0
DIAGNOSTIC_ERRORS = []
CURRENT_STAGE = "initialization"

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


def run(argv, *, timeout=3):
    global COMMAND_SEQUENCE
    COMMAND_SEQUENCE += 1
    number = COMMAND_SEQUENCE
    record = {"argv": argv, "sequence": number, "stage": CURRENT_STAGE}
    try:
        result = subprocess.run(argv, check=True, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, close_fds=True, timeout=timeout,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        return result
    except BaseException as exc:
        record.update(error_type=type(exc).__name__, error=str(exc),
                      returncode=getattr(exc, "returncode", None),
                      stdout=getattr(exc, "stdout", None), stderr=getattr(exc, "stderr", None))
        raise
    finally:
        if DIAGNOSTIC_DIR is not None:
            # Only this fixed allowlisted infrastructure-command wrapper is
            # recorded. No environment, credentials, model/app payloads.
            try:
                (DIAGNOSTIC_DIR / ("command-%04d.json" % number)).write_text(
                    json.dumps(record, indent=2, default=str))
            except BaseException as exc:
                DIAGNOSTIC_ERRORS.append("command evidence write failed: " + repr(exc))


def phase_record(out, phase):
    """Persist before mutations; an interrupted write is UNKNOWN, never safe ownership."""
    with (out / "phase.json").open("w") as fh:
        json.dump({"phase": phase, "name": NS}, fh)
        fh.flush()
        os.fsync(fh.fileno())
    fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def namespace_names(raw, *, empty_confirmed=False):
    """iproute2 may print no bytes for an empty netns listing.

    Only whitespace-only output independently confirmed against the namespace
    handle directory is the empty-list exception. Every nonempty
    response must be a strict JSON array of objects with valid name fields.
    JSON null, objects, arbitrary text and malformed/truncated JSON fail.
    """
    if not raw.strip():
        require(empty_confirmed, "empty namespace stdout not independently confirmed")
        return set()
    rows = json.loads(raw)
    require(isinstance(rows, list), "namespace listing is not an array")
    names = set()
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get("name"), str)
                and bool(row["name"]) and not any(c.isspace() for c in row["name"]),
                "invalid namespace listing entry")
        require(row["name"] not in names, "duplicate namespace listing entry")
        names.add(row["name"])
    return names


def ip(*args, ns=False):
    return run([IP] + (["-n", NS] if ns else []) + list(args)).stdout


def json_rows(raw, label):
    rows = json.loads(raw)
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows),
            label + " must be a JSON array of objects")
    return rows


def inventory(ns=False):
    return {
        "links": json_rows(ip("-j", "link", ns=ns), "links"),
        "addresses": json_rows(ip("-j", "addr", ns=ns), "addresses"),
        "routes4": json_rows(ip("-j", "-4", "route", "show", "table", "all", ns=ns), "routes4"),
        "routes6": json_rows(ip("-j", "-6", "route", "show", "table", "all", ns=ns), "routes6"),
        "rules4": json_rows(ip("-j", "-4", "rule", "show", ns=ns), "rules4"),
        "rules6": json_rows(ip("-j", "-6", "rule", "show", ns=ns), "rules6"),
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


def require(condition, description):
    if not condition:
        raise RuntimeError(description)


def normalized(value):
    """Remove only observations that expire/change without configuration edits.

    Preserve raw snapshots separately. Unknown fields remain, conservatively
    failing comparison rather than concealing a potential configuration change.
    """
    volatile = {"valid_life_time", "preferred_life_time", "expires", "cacheinfo"}
    if isinstance(value, dict):
        return {k: normalized(v) for k, v in value.items() if k not in volatile}
    if isinstance(value, list):
        return [normalized(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r"counter packets [0-9]+ bytes [0-9]+", "counter packets <observed> bytes <observed>", value)
        value = re.sub(r"^# (Generated by|Completed on).*?$", "", value, flags=re.M)
    return value


def signal_failure(signum, frame):
    raise InterruptedError("controlled cancellation signal=" + str(signum))


def cleanup(out, ownership):
    """Independently guarded cleanup/evidence steps. Returns every error.

    Never adopts a name. Ownership needs our successful-create journal AND
    matching namespace inode. Removal does not excuse failed process cleanup.
    SIGKILL/host loss cannot be handled; independent CI cleanup uses this journal.
    """
    errors = []
    def attempt(label, action):
        try:
            return action()
        except BaseException as exc:
            errors.append(label + ": " + type(exc).__name__ + ": " + str(exc))
            return None

    name = ownership.get("name", "")
    inode = ownership.get("inode")
    safe_name = bool(re.fullmatch(r"d061-infra-[0-9a-f]{32}", name))
    require(safe_name, "invalid ownership journal namespace")
    path = Path("/var/run/netns") / name
    exists = attempt("read namespace name presence", path.exists)
    matched = False
    if exists:
        current = attempt("read namespace identity", lambda: path.stat().st_ino)
        matched = ownership.get("created") is True and inode is not None and current == inode
        if not matched:
            errors.append("ownership mismatch: namespace left untouched")
    if matched:
        listed = attempt("initial process inventory", lambda: ip("netns", "pids", name).split())
        tracked = []
        for raw in listed or []:
            def kill_one(raw=raw):
                pid = int(raw)
                # Check actual membership immediately before kill. This is not
                # a hostile PID-race sandbox. Retain failures, never infer pass.
                try:
                    identity = os.stat("/proc/" + raw + "/ns/net").st_ino
                except FileNotFoundError:
                    return
                require(identity == inode, "process membership changed; not killed")
                os.kill(pid, signal.SIGKILL)
                tracked.append(pid)
            attempt("kill namespace pid " + raw, kill_one)
        remaining = None
        for _ in range(5):
            remaining = attempt("poll remaining processes", lambda: ip("netns", "pids", name).split())
            if remaining == []:
                break
            time.sleep(0.1)
        if remaining != []:
            errors.append("process cleanup incomplete or unverifiable before namespace deletion")
        attempt("write final process evidence", lambda: (out / "final-pids.json").write_text(
            json.dumps({"remaining": remaining, "killed": tracked}, indent=2)))
        attempt("delete owned namespace", lambda: ip("netns", "del", name))
    final_exists = attempt("final name absence check", path.exists)
    if final_exists is not False:
        errors.append("namespace name absence not established")
    after = attempt("host after snapshot", host_snapshot)
    if after is not None:
        attempt("write raw after snapshot", lambda: (out / "host-after.json").write_text(json.dumps(after, indent=2)))
    def compare():
        before = json.loads((out / "host-before.json").read_text())
        require(after is not None, "after snapshot unavailable")
        a, b = normalized(before), normalized(after)
        (out / "host-before-normalized.json").write_text(json.dumps(a, indent=2))
        (out / "host-after-normalized.json").write_text(json.dumps(b, indent=2))
        require(a == b, "configuration-normalized host topology changed")
    attempt("host configuration comparison", compare)
    return errors


def main():
    global NS, DIAGNOSTIC_DIR, COMMAND_SEQUENCE, CURRENT_STAGE
    parser = argparse.ArgumentParser()
    parser.add_argument("--review-authorized", action="store_true")
    parser.add_argument("--cleanup-only", type=Path, help="exact ownership journal from this job")
    parser.add_argument("--collector-gid", type=int, help="uploader primary group, private evidence read access")
    parser.add_argument("--output-pointer", type=Path, help="fresh job-local evidence pointer, not ownership authorization")
    parser.add_argument("--journal-pointer", type=Path, help="fresh job-local pointer for independent CI cleanup")
    args = parser.parse_args()
    require(not sys.flags.optimize, "Python optimization forbidden: safety assertions must remain enabled")
    require(args.review_authorized, "execution held pending exact-script review")
    require(os.geteuid() == 0, "root orchestration required; workload drops privileges")
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, signal_failure)
    if args.cleanup_only:
        out = args.cleanup_only.resolve().parent
        DIAGNOSTIC_DIR = out
        COMMAND_SEQUENCE = max([int(p.stem.split("-")[1]) for p in out.glob("command-[0-9][0-9][0-9][0-9].json")] or [0])
        ownership = json.loads(args.cleanup_only.read_text())
        NS = ownership["name"]
        errors = []
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(sig, signal.SIG_IGN)
        try:
            errors = cleanup(out, ownership)
            errors.extend(DIAGNOSTIC_ERRORS)
        except BaseException as exc:
            errors.append("cleanup failure: " + repr(exc))
        finally:
            print("artifacts=" + str(out), flush=True)
            print(json.dumps({"cleanup_only": True, "failed": bool(errors), "errors": errors}), flush=True)
        return 1 if errors else 0

    require(args.collector_gid is not None and args.collector_gid > 0, "non-root uploader group required")
    os.umask(0o027)
    out = Path(tempfile.mkdtemp(prefix="d061-infra-", dir="/tmp"))
    os.chown(out, 0, args.collector_gid)
    out.chmod(0o2750)  # job-specific uploader group only, no world access; children inherit group
    DIAGNOSTIC_DIR = out
    if args.output_pointer:
        with args.output_pointer.open("x") as pointer:
            pointer.write(str(out))
    # External CI can recover this exact journal path. A missing journal must
    # never be converted into permission to delete a guessed namespace name.
    print("artifacts=" + str(out), flush=True)
    print("ownership_journal=" + str(out / "ownership.json"), flush=True)
    if args.journal_pointer:
        require(not args.journal_pointer.exists(), "refuse existing CI journal pointer")
    NS = "d061-infra-" + uuid.uuid4().hex
    ownership = {"name": NS, "created": False, "inode": None}
    original_errors, cleanup_errors = [], []
    try:
        phase_record(out, "NOT_CREATED")
        CURRENT_STAGE = "host-before snapshot"
        before = host_snapshot()
        (out / "host-before.json").write_text(json.dumps(before, indent=2))
        CURRENT_STAGE = "pre-create namespace listing"
        raw_names = ip("-j", "netns", "list")
        nsdir = Path("/var/run/netns")
        empty_confirmed = not nsdir.exists() or not any(nsdir.iterdir())
        names = namespace_names(raw_names, empty_confirmed=empty_confirmed)
        require(NS not in names, "refuse existing namespace")
        # Normal termination is deferred across create+identity journal.
        # SIGKILL here is unhandleable: without a successful-create journal,
        # fallback must leave the name untouched and fail, not guess ownership.
        oldmask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGHUP, signal.SIGINT})
        try:
            CURRENT_STAGE = "namespace create, ownership not yet journaled"
            phase_record(out, "UNKNOWN_CREATE_WINDOW")
            ip("netns", "add", NS)
            ownership["created"] = True
            ownership["inode"] = Path("/var/run/netns", NS).stat().st_ino
            (out / "ownership.json").write_text(json.dumps(ownership))
            if args.journal_pointer:
                args.journal_pointer.write_text(str(out / "ownership.json"))
            phase_record(out, "CREATED_JOURNALED")
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, oldmask)
        CURRENT_STAGE = "namespace setup and validation"
        ip("link", "set", "lo", "up", ns=True)
        state = inventory(ns=True)
        (out / "namespace.json").write_text(json.dumps(state, indent=2))
        validate(state)
        CURRENT_STAGE = "IPv4 loopback workload"
        who = pwd.getpwnam("nobody")
        with (out / "workload.log").open("w") as log:
            subprocess.run(
                [IP, "netns", "exec", NS, SETPRIV,
                 "--reuid", str(who.pw_uid), "--regid", str(who.pw_gid),
                 "--clear-groups", "--bounding-set=-all", "--inh-caps=-all",
                 "--ambient-caps=-all", "--no-new-privs", PYTHON, "-I", "-c", WORKLOAD],
                check=True, timeout=15, close_fds=True, cwd="/",
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "EXPECTED_NETNS": "net:[" + str(ownership["inode"]) + "]"})
        require("LOOPBACK_ROUNDTRIP_OK" in (out / "workload.log").read_text(), "IPv4 loopback marker missing")
        final = inventory(ns=True)
        (out / "namespace-final.json").write_text(json.dumps(final, indent=2))
        validate(final)
    except BaseException as exc:
        original_errors.append(type(exc).__name__ + ": " + str(exc))
        try:
            (out / "original-traceback.txt").write_text(traceback.format_exc())
        except BaseException as evidence_exc:
            DIAGNOSTIC_ERRORS.append("traceback evidence write failed: " + repr(evidence_exc))
    finally:
        # Protect finite cleanup steps from ordinary CI termination signals.
        # SIGKILL/host loss remains outside process control; CI fallback needed.
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(sig, signal.SIG_IGN)
        try:
            CURRENT_STAGE = "protected cleanup and after snapshot"
            cleanup_errors = cleanup(out, ownership)
        except BaseException as exc:
            cleanup_errors.append("unexpected cleanup failure: " + repr(exc))
        finally:
            cleanup_errors.extend(DIAGNOSTIC_ERRORS)
            summary = {"failed": bool(original_errors or cleanup_errors),
                       "original_errors": original_errors, "cleanup_errors": cleanup_errors,
                       "IPv4_loopback": "tested only if workload marker exists",
                       "IPv6": "topology inspected; no IPv6 roundtrip tested",
                       "SIGKILL_limit": "independent job cleanup required; journal-less creation window cannot be safely adopted"}
            try:
                (out / "summary.json").write_text(json.dumps(summary, indent=2))
            except BaseException as exc:
                summary["failed"] = True
                cleanup_errors.append("summary evidence write failed: " + repr(exc))
            print("artifacts=" + str(out), flush=True)
            print(json.dumps(summary), flush=True)
    return 1 if original_errors or cleanup_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
