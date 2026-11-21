"""HELD trusted outer supervisor for archive staging. Source only, not reviewed for activation.

It owns one stager child. Honest limits: size checks are polling, NOT a disk quota (a fast writer can
overshoot between polls, bounded by write rate and RLIMIT_FSIZE per file); descendants are contained
only by the child's own session/process group plus a /proc scan, NOT by a PID namespace or cgroup
(production should add one); RLIMIT_NPROC is per-UID and is not claimed as a per-stager process cap.
Exit status 0 is never proof of staging: success needs absence of the stager group, the final
report file, each role root's closure-lock.json and a final bounded anchored scan inside budgets.
"""
import ctypes
import json
import os
from pathlib import Path
import resource
import secrets
import select
import signal
import stat as _stat
import subprocess
import sys
import time

APPROVED_FOR_EXECUTION = False
WALL_SECONDS = 1200
CPU_SECONDS = 1100
MAX_OUTPUT_BYTES = 25 * 1024**3
MAX_OUTPUT_FILES = 100500
MAX_OUTPUT_DIRS = 20000
MAX_FILE_BYTES = 4 * 1024**3 + 4096
MAX_OPEN = 256
MAX_ADDRESS_SPACE = 8 * 1024**3
MAX_SCAN_DEPTH = 32
POLL = 1.0
ABSENCE_WAIT = 10.0
STAGER = Path(__file__).with_name('stage_archives.py')
PR_SET_PDEATHSIG = 1


def scan_roots(roots, *, max_files=MAX_OUTPUT_FILES, max_dirs=MAX_OUTPUT_DIRS, max_bytes=MAX_OUTPUT_BYTES,
               deadline=None, clock=time.monotonic):
    """Anchored (dir_fd, O_NOFOLLOW) bounded traversal of exact roots; counts dirs AND files.

    Budgets and the deadline are checked between every entry. Any symlink or non-regular entry raises.
    Absent roots are reported, not an error.
    """
    files = dirs = size = 0
    absent = []

    def walk(fd, depth):
        nonlocal files, dirs, size
        if depth > MAX_SCAN_DEPTH:
            raise ValueError('staging output depth ceiling')
        with os.scandir(fd) as it:
            for entry in it:
                if deadline is not None and clock() > deadline:
                    raise TimeoutError('scan exceeded watchdog deadline')
                st = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                if _stat.S_ISDIR(st.st_mode):
                    dirs += 1
                    if dirs > max_dirs:
                        raise ValueError('staging output directory ceiling')
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        walk(child, depth + 1)
                    finally:
                        os.close(child)
                elif _stat.S_ISREG(st.st_mode):
                    files += 1
                    size += st.st_size
                    if files > max_files:
                        raise ValueError('staging output file ceiling')
                    if size > max_bytes:
                        raise ValueError('staging output byte ceiling')
                else:
                    raise ValueError('non-regular or symlink entry in staging output')

    for root in roots:
        try:
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            absent.append(str(root))
            continue
        try:
            walk(fd, 0)
        finally:
            os.close(fd)
    return {'files': files, 'dirs': dirs, 'bytes': size, 'absent_roots': absent}


def quarantine_partial(roots, attempt, uid=None):
    """Rename any root lacking a completed closure-lock.json to a private failed name. Never deletes."""
    uid = os.geteuid() if uid is None else uid
    out = []
    for root in roots:
        root = Path(root)
        try:
            st = os.lstat(root)
        except FileNotFoundError:
            out.append({'root': str(root), 'state': 'absent'})
            continue
        if not _stat.S_ISDIR(st.st_mode) or st.st_uid != uid:
            out.append({'root': str(root), 'state': 'refused_not_owned_directory'})
            continue
        lock = root / 'closure-lock.json'
        if lock.is_file() and not lock.is_symlink():
            out.append({'root': str(root), 'state': 'complete_lock_present_not_moved'})
            continue
        target = root.with_name(root.name + '.failed-' + attempt)
        if os.path.lexists(target):
            out.append({'root': str(root), 'state': 'refused_target_exists'})
            continue
        os.rename(root, target)
        os.chmod(target, 0o700, follow_symlinks=False)
        out.append({'root': str(root), 'state': 'quarantined', 'to': str(target)})
    return out


def process_identity(pid):
    """(pid, start_ticks, pgrp) from /proc, or None. start_ticks defeats PID reuse."""
    try:
        text = Path('/proc/%d/stat' % pid).read_text()
    except (FileNotFoundError, ProcessLookupError):
        return None
    fields = text[text.rindex(')') + 2:].split()
    return {'pid': pid, 'pgrp': int(fields[2]), 'state': fields[0], 'start_ticks': int(fields[19])}


def group_members(pgid):
    """Live (non-zombie) processes still in process group pgid, via /proc scan."""
    members = []
    for entry in os.scandir('/proc'):
        if not entry.name.isdigit():
            continue
        ident = process_identity(int(entry.name))
        if ident and ident['pgrp'] == pgid and ident['state'] != 'Z':
            members.append(ident['pid'])
    return members


def child_limits(expected_parent):
    def apply():
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))
        resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_OPEN, MAX_OPEN))
        resource.setrlimit(resource.RLIMIT_AS, (MAX_ADDRESS_SPACE, MAX_ADDRESS_SPACE))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        ctypes.CDLL(None, use_errno=True).prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
        if os.getppid() != expected_parent:  # watchdog already died between fork and prctl
            os._exit(111)
    return apply


def record(directory, name, value):
    path = Path(directory) / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(json.dumps(value, sort_keys=True))
        handle.flush()
        os.fsync(handle.fileno())


def kill_group_then_reap(child, pgid):
    """Kill the group while the unreaped leader still reserves its PID/PGID, verify absence, then reap."""
    try:
        os.killpg(pgid, signal.SIGKILL)  # safe: leader unreaped, so pgid cannot be reused yet
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + ABSENCE_WAIT
    while group_members(pgid) and time.monotonic() < deadline:
        time.sleep(0.05)
    remaining = group_members(pgid)
    code = child.wait()
    return code, remaining


def supervise(argv, output, *, roots=(), attempt=None, record_dir=None, cancel=None, wall=WALL_SECONDS,
              max_bytes=MAX_OUTPUT_BYTES, max_files=MAX_OUTPUT_FILES, max_dirs=MAX_OUTPUT_DIRS,
              clock=time.monotonic, sleep=time.sleep, preexec=None):
    if not APPROVED_FOR_EXECUTION:
        raise RuntimeError('staging watchdog HELD')
    attempt = attempt or secrets.token_hex(16)
    record_dir = Path(record_dir) if record_dir else None
    roots = [str(r) for r in roots]
    started = clock()
    deadline = started + wall
    # Durable attributable intent BEFORE any effect.
    if record_dir:
        record(record_dir, 'stage-watchdog-intent-%s.json' % attempt,
               {'attempt': attempt, 'argv': list(argv), 'roots': roots, 'output': str(output),
                'watchdog_pid': os.getpid(), 'watchdog_identity': process_identity(os.getpid())})
    child = subprocess.Popen(argv, preexec_fn=preexec or child_limits(os.getpid()), stdin=subprocess.DEVNULL, close_fds=True)
    pgid = child.pid  # setsid made the child its own group leader; unreaped, so PID is reserved
    pidfd = os.pidfd_open(child.pid)
    ident = process_identity(child.pid)
    if record_dir:
        record(record_dir, 'stage-watchdog-progress-%s.json' % attempt,
               {'attempt': attempt, 'child_identity': ident, 'pgid': pgid})
    reason = None
    scan_error = None
    try:
        while True:
            ready, _, _ = select.select([pidfd], [], [], 0)
            if ready:
                break  # leader exited (still unreaped)
            if cancel is not None and cancel.is_set():
                reason = 'cancelled'
            elif clock() > deadline:
                reason = 'wall_clock'
            else:
                try:
                    scan_roots(roots, max_files=max_files, max_dirs=max_dirs, max_bytes=max_bytes, deadline=deadline, clock=clock)
                except (ValueError, TimeoutError, OSError) as error:
                    reason = 'output_scan:' + type(error).__name__
            if reason:
                break
            sleep(POLL)
    except BaseException:
        kill_group_then_reap(child, pgid)
        os.close(pidfd)
        raise
    code, remaining = kill_group_then_reap(child, pgid)  # also reaps stragglers after a normal exit
    os.close(pidfd)
    # Final scan even after a fast exit 0: no report is not zero materialization.
    final = None
    try:
        final = scan_roots(roots, max_files=max_files, max_dirs=max_dirs, max_bytes=max_bytes)
    except (ValueError, TimeoutError, OSError) as error:
        scan_error = type(error).__name__ + ':' + str(error)[:120]
    locks = {}
    for root in roots:
        lock = Path(root) / 'closure-lock.json'
        locks[root] = lock.is_file() and not lock.is_symlink()
    report = Path(output)
    report_ok = report.is_file() and not report.is_symlink()
    complete = (code == 0 and reason is None and not remaining and scan_error is None and report_ok
                and bool(roots) and all(locks.values()))
    dispositions = [] if complete else quarantine_partial(roots, attempt)
    result = {'version': 'staging-watchdog/2', 'attempt': attempt, 'exit_code': code, 'killed_reason': reason,
              'group_members_remaining': remaining, 'final_scan': final, 'final_scan_error': scan_error,
              'closure_locks_present': locks, 'report_file_present': report_ok, 'complete': complete,
              'root_dispositions': dispositions, 'elapsed_seconds': round(clock() - started, 3),
              'exit0_alone_is_not_proof': True, 'not_attestation': True}
    if record_dir:
        record(record_dir, 'stage-watchdog-result-%s.json' % attempt, result)
    return result


def recover(record_dir, attempt):
    """Independent attributable recovery after a watchdog death. Never signals on a bare numeric PID.

    A recorded child is signalled only if its live (pid, start_ticks) still matches the progress record.
    Writes a uniquely scoped recovery record and never overwrites the originals.
    """
    if not APPROVED_FOR_EXECUTION:
        raise RuntimeError('staging watchdog HELD')
    record_dir = Path(record_dir)
    intent = json.loads((record_dir / ('stage-watchdog-intent-%s.json' % attempt)).read_text())
    if (record_dir / ('stage-watchdog-result-%s.json' % attempt)).exists():
        return {'attempt': attempt, 'state': 'original_result_present_no_action'}
    progress_path = record_dir / ('stage-watchdog-progress-%s.json' % attempt)
    signalled = 'no_progress_record_child_never_confirmed_spawned_unverified'
    remaining = None
    if progress_path.exists():
        progress = json.loads(progress_path.read_text())
        recorded = progress['child_identity']
        live = process_identity(recorded['pid']) if recorded else None
        if live and live['start_ticks'] == recorded['start_ticks'] and live['state'] != 'Z':
            try:
                os.killpg(recorded['pgrp'], signal.SIGKILL)
            except ProcessLookupError:
                pass
            signalled = 'identity_matched_group_killed'
            deadline = time.monotonic() + ABSENCE_WAIT
            while group_members(recorded['pgrp']) and time.monotonic() < deadline:
                time.sleep(0.05)
            remaining = group_members(recorded['pgrp'])
        else:
            signalled = 'recorded_identity_not_live_no_signal'
    token = secrets.token_hex(8)
    result = {'attempt': attempt, 'recovery_id': token, 'child': signalled, 'group_members_remaining': remaining,
              'root_dispositions': quarantine_partial(intent['roots'], attempt + '-r' + token)}
    record(record_dir, 'stage-watchdog-recovery-%s-%s.json' % (attempt, token), result)
    return result


def main():
    if not APPROVED_FOR_EXECUTION:
        raise SystemExit('HELD reviewed trusted staging watchdog required')
    if os.geteuid() != 0:
        raise RuntimeError('disposable root watchdog only')
    from threading import Event
    from stage_archives import ROLES
    args = sys.argv[1:]
    output = Path(args[args.index('--output') + 1])
    cancel = Event()
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, lambda *_: cancel.set())
    record_dir = Path(os.environ['WATCHDOG_RECORD_DIR'])
    result = supervise([sys.executable, str(STAGER)] + args, output, roots=[ROLES[r][0] for r in ('runtime', 'control')],
                       record_dir=record_dir, cancel=cancel)
    print(json.dumps(result))
    if not result['complete']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
