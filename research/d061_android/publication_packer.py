"""HELD source: trusted-root packer turning the private 0700 final export into ONE deterministic, runner-readable tarball.

The runner-side artifact uploader then uploads only that single regular file. Nothing here chowns/chmods the export itself,
mounts anything, or widens the runner's access to the private directory. Not run, not wired into any workflow.
"""
import hashlib
import io
import json
import os
import stat
import tarfile
from pathlib import Path

APPROVED_FOR_EXECUTION = False
MAX_FILES = 512
MAX_TOTAL = 256 * 1024 ** 2
SUMMARY = 'export-summary.json'


def _read_nofollow(dirfd, rel, limit):
    parts = rel.split('/')
    fd = dirfd
    opened = []
    try:
        for p in parts[:-1]:
            fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            opened.append(fd)
        ffd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            st = os.fstat(ffd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
                raise ValueError('not a bounded regular file: ' + rel)
            return os.read(ffd, st.st_size) if st.st_size else b''
        finally:
            os.close(ffd)
    finally:
        for o in opened:
            os.close(o)


def _walk(dirfd, prefix, out, depth=0):
    if depth > 8:
        raise ValueError('export depth ceiling')
    with os.scandir(dirfd) as it:
        for e in it:
            st = os.stat(e.name, dir_fd=dirfd, follow_symlinks=False)
            rel = prefix + e.name
            if stat.S_ISDIR(st.st_mode):
                c = os.open(e.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirfd)
                try:
                    _walk(c, rel + '/', out, depth + 1)
                finally:
                    os.close(c)
            elif stat.S_ISREG(st.st_mode):
                out.append(rel)
                if len(out) > MAX_FILES:
                    raise ValueError('export file ceiling')
            else:
                raise ValueError('non-regular entry in export: ' + rel)


def pack(export_dir, out_tar):
    """Verify the export against its own inventory (exact set + sha256), then write a deterministic tar (uid/gid 0, mode 0644,
    mtime 0, sorted) to a NEW path. Returns the packed-manifest dict. Refuses on any mismatch; preexisting output is refused."""
    if not APPROVED_FOR_EXECUTION:
        raise RuntimeError('publication packer HELD')
    dfd = os.open(str(export_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.fstat(dfd).st_uid != os.geteuid():
            raise ValueError('export root must be owned by the packing identity')
        summary = json.loads(_read_nofollow(dfd, SUMMARY, 16 * 1024 ** 2))
        if summary.get('private_candidates_exported') is not False or summary.get('version') != 'owned-final-export/1':
            raise ValueError('summary does not describe an allowlisted export')
        inv = summary.get('inventory')
        if not isinstance(inv, list):
            raise ValueError('summary inventory missing')
        listed = {}
        for row in inv:
            if row['path'] in listed or row['path'] == SUMMARY:
                raise ValueError('duplicate or reserved inventory path')
            listed[row['path']] = row
        present = []
        _walk(dfd, '', present)
        if set(present) != set(listed) | {SUMMARY}:
            raise ValueError('export file set differs from its inventory (extra or missing)')
        total = 0
        blobs = {}
        for rel in sorted(listed):
            data = _read_nofollow(dfd, rel, MAX_TOTAL)
            total += len(data)
            if total > MAX_TOTAL:
                raise ValueError('export byte ceiling')
            if len(data) != listed[rel]['bytes'] or hashlib.sha256(data).hexdigest() != listed[rel]['sha256']:
                raise ValueError('export file differs from inventory: ' + rel)
            blobs[rel] = data
        blobs[SUMMARY] = _read_nofollow(dfd, SUMMARY, 16 * 1024 ** 2)
    finally:
        os.close(dfd)
    fd = os.open(str(out_tar), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'wb') as fh:
        with tarfile.open(fileobj=fh, mode='w', format=tarfile.PAX_FORMAT) as tf:
            for rel in sorted(blobs):
                ti = tarfile.TarInfo(rel)
                ti.size, ti.mode, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = len(blobs[rel]), 0o644, 0, 0, 0, '', ''
                tf.addfile(ti, io.BytesIO(blobs[rel]))
        fh.flush()
        os.fsync(fh.fileno())
    digest = hashlib.sha256(Path(out_tar).read_bytes()).hexdigest()
    return {'files': len(blobs), 'bytes': total, 'tar_sha256': digest, 'complete_product_evidence': summary.get('complete_product_evidence')}
