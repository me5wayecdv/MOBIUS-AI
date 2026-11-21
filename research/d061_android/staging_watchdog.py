"""HELD trusted outer supervisor for archive staging. Source only, not reviewed for activation.

Honest limits. Size scans are polling, NOT a disk quota (a fast writer can overshoot between polls, bounded
by write rate and RLIMIT_FSIZE per file). Descendants are contained only by the child's own session plus
per-process pidfd signalling found through /proc, NOT by a PID namespace or cgroup: a process that leaves
the session (setsid) escapes it, so production still needs a namespace/cgroup boundary. RLIMIT_NPROC is
per-UID and is not claimed. Exit status 0 is never proof: completion needs verified group absence, the
exact reviewed lock identity, the report/closure/file-hash content and a clean bounded final validation.
Root mutation (quarantine) happens ONLY after absence is verified; otherwise the state is recorded UNVERIFIED.
"""
import ctypes
import hashlib
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
FINAL_SECONDS = 600
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
REAP_WAIT = 10.0
STAGER = Path(__file__).with_name('stage_archives.py')
PR_SET_PDEATHSIG = 1
ROLE_NAMES = ('runtime', 'control')


# ---------------------------------------------------------------- anchored filesystem helpers
def open_dir(path):
    """Open an absolute directory by walking EVERY component with O_NOFOLLOW|O_DIRECTORY from '/'."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('absolute path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if part in ('', '.', '..'):
                raise ValueError('non-canonical path component')
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def lexists_anchored(path):
    path = Path(path)
    parent = open_dir(path.parent)
    try:
        os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    finally:
        os.close(parent)


def read_anchored(path, limit):
    """Read a regular file through anchored ancestors, O_NOFOLLOW|O_NONBLOCK, bounded."""
    path = Path(path)
    parent = open_dir(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        if not _stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('regular file required')
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise ValueError('file exceeds bound')
        return data
    finally:
        os.close(fd)


def record(directory, name, value):
    """Create-exclusive private record file through an anchored directory fd."""
    dfd = open_dir(directory)
    try:
        st = os.fstat(dfd)
        if st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise ValueError('private owned record directory required')
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        with os.fdopen(fd, 'w') as handle:
            handle.write(json.dumps(value, sort_keys=True))
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(dfd)


def walk_root(root, *, max_files=MAX_OUTPUT_FILES, max_dirs=MAX_OUTPUT_DIRS, max_bytes=MAX_OUTPUT_BYTES,
              deadline=None, clock=time.monotonic, collect=False):
    """Anchored bounded traversal of one exact root. Counts dirs AND files; budgets/deadline checked per entry.

    Returns (files, dirs, bytes, entries) where entries (if collect) maps relative path -> (size, mode, fd-less).
    Raises on symlink/special file. Absent root returns None.
    """
    try:
        rfd = open_dir(root)
    except FileNotFoundError:
        return None
    files = dirs = size = 0
    entries = {}

    def walk(fd, prefix, depth):
        nonlocal files, dirs, size
        if depth > MAX_SCAN_DEPTH:
            raise ValueError('staging output depth ceiling')
        with os.scandir(fd) as it:
            for entry in it:
                if deadline is not None and clock() > deadline:
                    raise TimeoutError('scan exceeded deadline')
                st = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                rel = prefix + entry.name
                if _stat.S_ISDIR(st.st_mode):
                    dirs += 1
                    if dirs > max_dirs:
                        raise ValueError('staging output directory ceiling')
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        walk(child, rel + '/', depth + 1)
                    finally:
                        os.close(child)
                elif _stat.S_ISREG(st.st_mode):
                    files += 1
                    size += st.st_size
                    if files > max_files:
                        raise ValueError('staging output file ceiling')
                    if size > max_bytes:
                        raise ValueError('staging output byte ceiling')
                    if collect:
                        entries[rel] = (st.st_size, _stat.S_IMODE(st.st_mode))
                else:
                    raise ValueError('non-regular or symlink entry in staging output')
    try:
        walk(rfd, '', 0)
    finally:
        os.close(rfd)
    return files, dirs, size, entries


def scan_roots(roots, **kw):
    out = {'files': 0, 'dirs': 0, 'bytes': 0, 'absent_roots': []}
    for root in roots:
        res = walk_root(root, **kw)
        if res is None:
            out['absent_roots'].append(str(root))
        else:
            out['files'] += res[0]
            out['dirs'] += res[1]
            out['bytes'] += res[2]
    return out


def hash_anchored(root, rel, deadline, clock=time.monotonic):
    rfd = open_dir(root)
    fd = None
    try:
        parts = rel.split('/')
        cur = rfd
        opened = []
        for part in parts[:-1]:
            cur = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cur)
            opened.append(cur)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=cur)
        for d in opened:
            os.close(d)
        h = hashlib.sha256()
        total = 0
        while block := os.read(fd, 1048576):
            if clock() > deadline:
                raise TimeoutError('hash exceeded deadline')
            total += len(block)
            h.update(block)
        return total, h.hexdigest()
    finally:
        if fd is not None:
            os.close(fd)
        os.close(rfd)


def canonical_digest(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_staged(role_roots, lock, report_bytes, *, deadline, clock=time.monotonic):
    """Content validation: report, closure-lock and every staged file's exact size/mode/sha256, no extras."""
    report = json.loads(report_bytes)
    if report.get('no_code_executed') is not True or not isinstance(report.get('results'), list):
        raise ValueError('report content invalid')
    by_role = {r.get('role'): r for r in report['results']}
    if set(by_role) != set(role_roots):
        raise ValueError('report roles differ from exact owned roots')
    for role, root in role_roots.items():
        manifest = lock['roles'][role]
        row = by_role[role]
        if row.get('root') != str(root) or row.get('closure_sha256') != canonical_digest(manifest) or row.get('file_count') != len(manifest['files']):
            raise ValueError('report role identity differs from reviewed lock')
        walked = walk_root(root, deadline=deadline, clock=clock, collect=True)
        if walked is None:
            raise ValueError('role root absent')
        entries = walked[3]
        if json.loads(read_anchored(Path(root) / 'closure-lock.json', 16 * 1024**2)) != manifest:
            raise ValueError('closure-lock content differs from reviewed lock')
        expected = {f['source']: f for f in manifest['files']}
        if set(entries) != set(expected) | {'closure-lock.json'}:
            raise ValueError('staged file set differs from reviewed lock (extra or missing)')
        for rel, f in expected.items():
            size, mode = entries[rel]
            if size != f['size'] or mode != f['mode']:
                raise ValueError('staged file size/mode differs from reviewed lock')
            if hash_anchored(root, rel, deadline, clock) != (f['size'], f['sha256']):
                raise ValueError('staged file digest differs from reviewed lock')


# ---------------------------------------------------------------- process identity and containment
def process_identity(pid):
    """(pid, pgrp, sid, state, start_ticks) from /proc, or None. start_ticks defeats PID reuse."""
    try:
        text = Path('/proc/%d/stat' % pid).read_text()
    except (FileNotFoundError, ProcessLookupError):
        return None
    fields = text[text.rindex(')') + 2:].split()
    return {'pid': pid, 'state': fields[0], 'pgrp': int(fields[2]), 'sid': int(fields[3]), 'start_ticks': int(fields[19])}


def session_members(sid):
    """Live (non-zombie) pids still in session sid, via a /proc scan."""
    members = []
    for entry in os.scandir('/proc'):
        if entry.name.isdigit():
            ident = process_identity(int(entry.name))
            if ident and ident['sid'] == sid and ident['state'] != 'Z':
                members.append(ident)
    return members


def kill_session_stable(sid, wait=ABSENCE_WAIT, clock=time.monotonic):
    """Signal each live member through its own pidfd after re-verifying identity; never a numeric kill.

    Repeats until no member remains or the bounded wait expires. Returns the remaining members.
    """
    deadline = clock() + wait
    while True:
        members = session_members(sid)
        if not members:
            return []
        for ident in members:
            try:
                pfd = os.pidfd_open(ident['pid'])
            except ProcessLookupError:
                continue
            except OSError:
                continue  # cannot signal stably: the member stays listed, so absence is NOT verified
            try:
                again = process_identity(ident['pid'])
                if again and again['sid'] == sid and again['start_ticks'] == ident['start_ticks']:
                    signal.pidfd_send_signal(pfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(pfd)
        if clock() > deadline:
            return session_members(sid)
        time.sleep(0.02)


def child_limits(expected_parent):
    def apply():
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))
        resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_OPEN, MAX_OPEN))
        resource.setrlimit(resource.RLIMIT_AS, (MAX_ADDRESS_SPACE, MAX_ADDRESS_SPACE))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
            os._exit(112)
        if os.getppid() != expected_parent:  # watchdog already died between fork and prctl
            os._exit(111)
    return apply


def quarantine_partial(roots, attempt, uid=None):
    """Rename roots to a private failed name through anchored parents. Never deletes; callers MUST have
    verified process absence first. Only roots this run created are passed in (never preexisting ones)."""
    uid = os.geteuid() if uid is None else uid
    out = []
    for root in roots:
        root = Path(root)
        try:
            pfd = open_dir(root.parent)
        except (FileNotFoundError, OSError) as error:
            out.append({'root': str(root), 'state': 'refused_parent:' + type(error).__name__})
            continue
        try:
            try:
                st = os.stat(root.name, dir_fd=pfd, follow_symlinks=False)
            except FileNotFoundError:
                out.append({'root': str(root), 'state': 'absent'})
                continue
            if not _stat.S_ISDIR(st.st_mode) or st.st_uid != uid:
                out.append({'root': str(root), 'state': 'refused_not_owned_directory'})
                continue
            target = root.name + '.failed-' + attempt
            try:
                os.stat(target, dir_fd=pfd, follow_symlinks=False)
                out.append({'root': str(root), 'state': 'refused_target_exists'})
                continue
            except FileNotFoundError:
                pass
            os.rename(root.name, target, src_dir_fd=pfd, dst_dir_fd=pfd)
            tfd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
            try:
                os.fchmod(tfd, 0o700)
            finally:
                os.close(tfd)
            out.append({'root': str(root), 'state': 'quarantined', 'to': str(root.parent / target)})
        finally:
            os.close(pfd)
    return out


def stop_and_reap(child, sid):
    """Bounded: kill the session via pidfds, verify absence, then reap the leader with a timeout."""
    remaining = kill_session_stable(sid)
    if child.poll() is None:
        child.kill()  # Popen-guarded kill of the still-unreaped leader (fallback when pidfd signalling failed)
        end = time.monotonic() + ABSENCE_WAIT
        remaining = session_members(sid)
        while remaining and time.monotonic() < end:
            time.sleep(0.02)
            remaining = session_members(sid)
    code = None
    try:
        code = child.wait(timeout=REAP_WAIT)
    except subprocess.TimeoutExpired:
        remaining = remaining or ['leader_unreaped']
    return code, remaining


def supervise(argv, report_path, *, role_roots, lock_bytes, expected_lock_sha256, attempt=None, record_dir,
              cancel=None, wall=WALL_SECONDS, final_seconds=FINAL_SECONDS, max_bytes=MAX_OUTPUT_BYTES,
              max_files=MAX_OUTPUT_FILES, max_dirs=MAX_OUTPUT_DIRS, clock=time.monotonic, sleep=time.sleep,
              preexec=None):
    if not APPROVED_FOR_EXECUTION:
        raise RuntimeError('staging watchdog HELD')
    attempt = attempt or secrets.token_hex(16)
    roots = {r: str(role_roots[r]) for r in ROLE_NAMES if r in role_roots}
    if set(roots) != set(role_roots) or not roots:
        raise ValueError('exact owned role roots required')
    # ---- one-shot pre-effect identities: exact reviewed lock, and no preexisting output to adopt.
    if hashlib.sha256(lock_bytes).hexdigest() != expected_lock_sha256:
        raise ValueError('lock bytes differ from the reviewed lock identity')
    lock = json.loads(lock_bytes)
    if lock.get('status') != 'EXACT_REVIEWED_SIBLING_STAGE_LOCK' or set(lock.get('roles', {})) < set(roots):
        raise ValueError('unresolved or incomplete reviewed lock')
    for path in list(roots.values()) + [str(report_path)]:
        if lexists_anchored(path):
            raise ValueError('refusing preexisting stage output (never adopted or quarantined): ' + path)
    started = clock()
    deadline = started + wall
    # Durable attributable intent BEFORE any effect.
    record(record_dir, 'stage-watchdog-intent-%s.json' % attempt,
           {'attempt': attempt, 'argv': list(argv), 'roots': roots, 'report': str(report_path),
            'lock_sha256': expected_lock_sha256, 'watchdog_pid': os.getpid(),
            'watchdog_identity': process_identity(os.getpid())})
    child = subprocess.Popen(argv, preexec_fn=preexec or child_limits(os.getpid()), stdin=subprocess.DEVNULL, close_fds=True)
    sid = child.pid  # setsid in the child; leader unreaped, so the number is reserved until we reap
    reason = None
    setup_error = None
    pidfd = None
    try:
        # ALL post-Popen setup is inside this guard.
        pidfd = os.pidfd_open(child.pid)
        ident = process_identity(child.pid)
        if ident is None or ident['sid'] != sid:
            raise RuntimeError('child session identity not confirmed')
        record(record_dir, 'stage-watchdog-progress-%s.json' % attempt, {'attempt': attempt, 'child_identity': ident, 'sid': sid})
        while True:
            if select.select([pidfd], [], [], 0)[0]:
                break  # leader exited (still unreaped)
            if cancel is not None and cancel.is_set():
                reason = 'cancelled'
            elif clock() > deadline:
                reason = 'wall_clock'
            else:
                try:
                    scan_roots(roots.values(), max_files=max_files, max_dirs=max_dirs, max_bytes=max_bytes, deadline=deadline, clock=clock)
                except (ValueError, TimeoutError, OSError) as error:
                    reason = 'output_scan:' + type(error).__name__
            if reason:
                break
            sleep(POLL)
    except BaseException as error:
        setup_error = type(error).__name__ + ':' + str(error)[:120]
        reason = reason or 'supervision_error'
    code, remaining = stop_and_reap(child, sid)
    if pidfd is not None:
        os.close(pidfd)
    absence_verified = not remaining
    # ---- bounded final validation, even after exit 0; only meaningful with verified absence.
    scan_error = None
    complete = False
    final = None
    if absence_verified:
        final_deadline = clock() + final_seconds
        try:
            final = scan_roots(roots.values(), max_files=max_files, max_dirs=max_dirs, max_bytes=max_bytes, deadline=final_deadline, clock=clock)
            if code == 0 and reason is None and setup_error is None:
                validate_staged(roots, lock, read_anchored(report_path, 1048576), deadline=final_deadline, clock=clock)
                complete = True
        except BaseException as error:
            scan_error = type(error).__name__ + ':' + str(error)[:120]
    if absence_verified and not complete:
        dispositions = quarantine_partial(list(roots.values()), attempt)
    elif not absence_verified:
        dispositions = [{'state': 'UNVERIFIED_ABSENCE_NO_ROOT_MUTATION'}]
    else:
        dispositions = []
    result = {'version': 'staging-watchdog/3', 'attempt': attempt, 'exit_code': code, 'killed_reason': reason,
              'setup_error': setup_error, 'absence_verified': absence_verified,
              'session_members_remaining': [m if isinstance(m, str) else m['pid'] for m in remaining],
              'final_scan': final, 'final_validation_error': scan_error, 'complete': complete,
              'root_dispositions': dispositions, 'elapsed_seconds': round(clock() - started, 3),
              'exit0_alone_is_not_proof': True, 'not_attestation': True}
    record(record_dir, 'stage-watchdog-result-%s.json' % attempt, result)
    return result


def recover(record_dir, attempt):
    """Independent attributable recovery after a watchdog death.

    Never uses a numeric group kill. Members of the RECORDED session are signalled only through pidfds after
    identity re-verification. Roots are renamed only if absence is verified; otherwise UNVERIFIED, no mutation.
    Originals are never overwritten; a unique recovery record is written.
    """
    if not APPROVED_FOR_EXECUTION:
        raise RuntimeError('staging watchdog HELD')
    intent = json.loads(read_anchored(Path(record_dir) / ('stage-watchdog-intent-%s.json' % attempt), 65536))
    if lexists_anchored(Path(record_dir) / ('stage-watchdog-result-%s.json' % attempt)):
        return {'attempt': attempt, 'state': 'original_result_present_no_action'}
    token = secrets.token_hex(8)
    try:
        progress = json.loads(read_anchored(Path(record_dir) / ('stage-watchdog-progress-%s.json' % attempt), 65536))
    except FileNotFoundError:
        progress = None
    if progress is None:
        result = {'attempt': attempt, 'recovery_id': token, 'state': 'UNVERIFIED_no_progress_record',
                  'root_dispositions': [{'state': 'UNVERIFIED_ABSENCE_NO_ROOT_MUTATION'}]}
    else:
        sid = progress['sid']
        remaining = kill_session_stable(sid)
        verified = not remaining
        result = {'attempt': attempt, 'recovery_id': token, 'sid': sid,
                  'state': 'absence_verified' if verified else 'UNVERIFIED_members_remain',
                  'session_members_remaining': [m['pid'] for m in remaining],
                  'root_dispositions': quarantine_partial(list(intent['roots'].values()), attempt + '-r' + token)
                  if verified else [{'state': 'UNVERIFIED_ABSENCE_NO_ROOT_MUTATION'}]}
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
    report = Path(args[args.index('--output') + 1])
    lock_path = Path(args[args.index('--lock') + 1])
    cancel = Event()
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, lambda *_: cancel.set())
    result = supervise([sys.executable, str(STAGER)] + args, report,
                       role_roots={r: ROLES[r][0] for r in ROLE_NAMES},
                       lock_bytes=read_anchored(lock_path, 16 * 1024**2),
                       expected_lock_sha256=os.environ['WATCHDOG_REVIEWED_LOCK_SHA256'],
                       record_dir=Path(os.environ['WATCHDOG_RECORD_DIR']), cancel=cancel)
    print(json.dumps(result))
    if not result['complete']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
