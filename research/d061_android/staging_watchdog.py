"""HELD trusted outer watchdog for archive staging: hard wall clock, process-group kill,
resource limits and a polled output-size ceiling. It supervises a child and never
interprets archive content. Source only, not reviewed for activation.
"""
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time

APPROVED_FOR_EXECUTION = False
WALL_SECONDS = 1200
CPU_SECONDS = 1100
MAX_OUTPUT_BYTES = 25 * 1024**3
MAX_OUTPUT_FILES = 100500
MAX_FILE_BYTES = 4 * 1024**3 + 4096
MAX_OPEN = 256
POLL = 1.0
STAGER = Path(__file__).with_name('stage_archives.py')


def usage(path, limit_files=MAX_OUTPUT_FILES, deadline=None, clock=time.monotonic):
    """Bounded no-follow size/count scan of the staging output; raises past limits."""
    files = size = 0
    stack = [str(path)]
    while stack:
        if deadline is not None and clock() > deadline:
            raise TimeoutError('usage scan exceeded watchdog deadline')
        try:
            with os.scandir(stack.pop()) as it:
                for entry in it:
                    if entry.is_symlink():
                        raise ValueError('symlink in staging output')
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    else:
                        files += 1
                        size += entry.stat(follow_symlinks=False).st_size
                        if files > limit_files:
                            raise ValueError('staging output file ceiling')
        except FileNotFoundError:
            continue
    return files, size


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_OPEN, MAX_OPEN))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.setsid()


def supervise(argv, output, *, wall=WALL_SECONDS, max_bytes=MAX_OUTPUT_BYTES, max_files=MAX_OUTPUT_FILES,
              clock=time.monotonic, sleep=time.sleep, preexec=limits):
    if not APPROVED_FOR_EXECUTION:
        raise RuntimeError('staging watchdog HELD')
    started = clock()
    deadline = started + wall
    child = subprocess.Popen(argv, preexec_fn=preexec, stdin=subprocess.DEVNULL, close_fds=True)
    reason = None
    try:
        while True:
            code = child.poll()
            if code is not None:
                break
            if clock() > deadline:
                reason = 'wall_clock'
            else:
                try:
                    files, size = usage(output, max_files, deadline, clock)
                    if size > max_bytes:
                        reason = 'output_bytes'
                except (ValueError, TimeoutError) as error:
                    reason = 'output_scan:' + type(error).__name__
            if reason:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                code = child.wait()
                break
            sleep(POLL)
    except BaseException:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        raise
    # Always reap any stragglers left in the child's process group.
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return {'version': 'staging-watchdog/1', 'exit_code': code, 'killed_reason': reason,
            'elapsed_seconds': round(clock() - started, 3), 'partial_output_unverified_unless_exit0': code != 0,
            'not_attestation': True}


def main():
    if not APPROVED_FOR_EXECUTION:
        raise SystemExit('HELD reviewed trusted staging watchdog required')
    if os.geteuid() != 0:
        raise RuntimeError('disposable root watchdog only')
    args = sys.argv[1:]
    output = Path(args[args.index('--output') + 1])
    result = supervise([sys.executable, str(STAGER)] + args, output)
    print(json.dumps(result))
    if result['exit_code'] != 0:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
