#!/usr/bin/env python3
"""HELD diagnostic-fix candidate: export only exact job output, no namespace effects.

Root reads an exact pointer written by this job's preflight, then copies only
allowlisted regular evidence files to a fresh runner-owned directory. No glob
collection, recursive chown/chmod, secret/environment read or symlink traversal.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat

FIXED = {
    'host-before.json', 'host-after.json', 'host-before-normalized.json',
    'host-after-normalized.json', 'namespace.json', 'namespace-final.json',
    'final-pids.json', 'summary.json', 'workload.log', 'original-traceback.txt',
    'ownership.json', 'phase.json', 'final-name-absence.json',
}


def require(ok, detail):
    if not ok:
        raise RuntimeError(detail)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-pointer', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--gid', type=int, required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'root exporter required')
    require(args.uid > 0 and args.gid > 0, 'non-root collector identity required')
    ptrstat = args.output_pointer.lstat()
    require(stat.S_ISREG(ptrstat.st_mode) and ptrstat.st_uid == 0, 'invalid job output pointer')
    raw = args.output_pointer.read_text()
    require(re.fullmatch(r'/tmp/d061-infra-[a-z0-9_]+', raw) is not None, 'unexpected output path')
    source = Path(raw)
    srcstat = source.lstat()
    require(stat.S_ISDIR(srcstat.st_mode) and srcstat.st_uid == 0, 'invalid source directory')
    require(source.resolve() == source, 'source path traverses symlink')
    require(not args.destination.exists() and not args.destination.is_symlink(), 'destination must be fresh')
    # Parent chosen by the current job, not by evidence or external data.
    require(args.destination.parent.resolve() == args.output_pointer.parent.resolve(), 'destination outside job pointer directory')
    args.destination.mkdir(mode=0o700)
    errors, copied = [], []
    try:
        for entry in source.iterdir():
            if entry.name not in FIXED and not re.fullmatch(r'command-[0-9]{4}.json', entry.name):
                errors.append('unexpected evidence filename: ' + entry.name)
                continue
            fd = None
            try:
                fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                st = os.fstat(fd)
                require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1,
                        'non-regular or unowned evidence rejected')
                require(st.st_size <= 8 * 1024 * 1024, 'evidence file too large')
                with os.fdopen(os.dup(fd), 'rb') as fh:
                    data = fh.read(8 * 1024 * 1024 + 1)
                require(len(data) <= 8 * 1024 * 1024, 'evidence grew beyond limit')
                dest = args.destination / entry.name
                with dest.open('xb') as fh:
                    fh.write(data)
                dest.chmod(0o600)
                os.chown(dest, args.uid, args.gid)
                copied.append(entry.name)
            except BaseException as exc:
                errors.append(entry.name + ': ' + type(exc).__name__ + ': ' + str(exc))
            finally:
                if fd is not None:
                    os.close(fd)
        if 'summary.json' not in copied:
            errors.append('summary.json missing; runtime result not established')
    finally:
        report = args.destination / 'collector-summary.json'
        report.write_text(json.dumps({'copied': copied, 'errors': errors, 'failed': bool(errors)}, indent=2))
        report.chmod(0o600)
        os.chown(report, args.uid, args.gid)
        os.chown(args.destination, args.uid, args.gid)
        print('collector_output=' + str(args.destination), flush=True)
        print('collector_failed=' + str(bool(errors)), flush=True)
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
