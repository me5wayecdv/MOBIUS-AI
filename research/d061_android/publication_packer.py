"""HELD source: trusted-root packer turning the private 0700 final export into ONE deterministic, runner-readable tarball.

The runner-side artifact uploader then uploads only that single regular file. Nothing here chowns/chmods the export tree,
mounts anything, or widens runner access to the private directory. Not run, not wired into any workflow.

Honest limits: deadlines and caps are cooperative checks between filesystem operations (not a hard bound on a blocked
read); the tar is a fixture-evidence container, not a cryptographic attestation; the inventory is trusted only after it is
bound to the exact workflow/run identity AND every path falls in the exporter's fixed categories.
"""
import hashlib
import io
import json
import os
import re
import secrets
import stat
import tarfile
import time

from final_export import ROOT_FILES, ROOT_ATTEMPT, ROLE_FILES, ROLE_ATTEMPT, CONTROL_FILES, PUBLIC_FILES
from mobius.services.owned_android_fixture import REQUIRED, DIAGNOSTICS

APPROVED_FOR_EXECUTION = False
MAX_FILES = 512
MAX_DIRS = 64
MAX_DEPTH = 5
MAX_TOTAL = 64 * 1024 ** 2  # inventory bytes PLUS the summary, same ceiling as the exporter
MAX_TAR = MAX_TOTAL + 4 * 1024 ** 2
MAX_SECONDS = 60
SUMMARY = 'export-summary.json'
SUMMARY_KEYS = frozenset({'version', 'workflow_context', 'infrastructure_run_id', 'complete', 'complete_diagnostic_export',
                          'complete_product_evidence', 'published_status', 'diagnostic_partial_export', 'errors', 'role_absence',
                          'inventory', 'total_bytes', 'original_status_not_upgraded', 'private_candidates_exported',
                          'cooperative_export_budget_seconds', 'not_cryptographic_attestation'})
HEX64 = re.compile('[0-9a-f]{64}')
STORE_KEY = re.compile(r'product-store/apk/([0-9a-f]{2})/([0-9a-f]{64})\.apk')


def allowed_path(path):
    """Exporter's FIXED categories only; anything else is not an authorized export member."""
    if not isinstance(path, str) or not path or path != os.path.normpath(path) or path.startswith('/') or '//' in path:
        return False
    head, _, name = path.partition('/')
    if head == 'root':
        return name in ROOT_FILES or ROOT_ATTEMPT.fullmatch(name) is not None
    if head in ('runtime', 'control') and '/' not in name:
        return name in ROLE_FILES or ROLE_ATTEMPT.fullmatch(name) is not None or (head == 'control' and name in CONTROL_FILES | {'mobius.db'})
    if head == 'control':
        return name in CONTROL_FILES
    if head == 'runtime-originals':
        return name in REQUIRED | DIAGNOSTICS
    if head == 'public-snapshot':
        return name in PUBLIC_FILES
    if head == 'published-result':
        return name in REQUIRED | DIAGNOSTICS | {'result.json'}
    return STORE_KEY.fullmatch(path) is not None and STORE_KEY.fullmatch(path).group(1) == STORE_KEY.fullmatch(path).group(2)[:2]


def _trusted_dir(meta):
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0, os.geteuid()):
        raise ValueError('untrusted directory owner/type')
    if meta.st_mode & 0o022 and not (meta.st_mode & 0o1000 and meta.st_uid == 0):
        raise ValueError('group/world-writable directory without root sticky ownership')


def _open_anchored(path, *, final_private=False):
    """Every path component opened relative to the previous checked descriptor with O_NOFOLLOW; ancestors owner/mode checked."""
    path = os.path.abspath(os.fspath(path))
    parts = [p for p in path.split('/') if p]
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(parts):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            meta = os.fstat(child)
            try:
                _trusted_dir(meta)
                if final_private and index == len(parts) - 1 and meta.st_mode & 0o077:
                    raise ValueError('export root must be private (no group/world bits)')
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_regular(dirfd, rel, limit):
    """Anchored, O_NONBLOCK-before-fstat, regular owned single-link file, bounded EXACT-length read loop."""
    parts = rel.split('/')
    fd = dirfd
    opened = []
    try:
        for part in parts[:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            opened.append(fd)
        ffd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except BaseException:
        for o in opened:
            os.close(o)
        raise
    try:
        meta = os.fstat(ffd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_size > limit or meta.st_uid not in (0, os.geteuid())
                or meta.st_nlink != 1 or meta.st_mode & 0o022):
            raise ValueError('not a bounded owned immutable regular file: ' + rel)
        chunks, got = [], 0
        while got < meta.st_size:
            block = os.read(ffd, min(1048576, meta.st_size - got))
            if not block:
                raise ValueError('short read (file shrank): ' + rel)
            chunks.append(block)
            got += len(block)
        if os.read(ffd, 1):
            raise ValueError('file grew during read: ' + rel)
        return b''.join(chunks)
    finally:
        os.close(ffd)
        for o in opened:
            os.close(o)


def _walk(dirfd, prefix, out, counters, deadline, clock, depth=0):
    if depth > MAX_DEPTH:
        raise ValueError('export depth ceiling')
    with os.scandir(dirfd) as it:
        for e in it:
            if clock() > deadline:
                raise TimeoutError('cooperative packer deadline')
            st = os.stat(e.name, dir_fd=dirfd, follow_symlinks=False)
            rel = prefix + e.name
            if stat.S_ISDIR(st.st_mode):
                counters['dirs'] += 1
                if counters['dirs'] > MAX_DIRS:
                    raise ValueError('export directory ceiling')
                c = os.open(e.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirfd)
                try:
                    _walk(c, rel + '/', out, counters, deadline, clock, depth + 1)
                finally:
                    os.close(c)
            elif stat.S_ISREG(st.st_mode):
                out.append(rel)
                if len(out) > MAX_FILES + 1:
                    raise ValueError('export file ceiling')
            else:
                raise ValueError('non-regular entry in export: ' + rel)


class _HashingWriter:
    def __init__(self, fd):
        self.fd, self.h, self.n = fd, hashlib.sha256(), 0

    def write(self, data):
        view = memoryview(data)
        self.n += len(view)
        if self.n > MAX_TAR:
            raise ValueError('packed tar byte ceiling')
        self.h.update(view)
        while view:
            written = os.write(self.fd, view)
            if written <= 0:
                raise OSError('tar write made no progress')
            view = view[written:]
        return len(data)

    def tell(self):
        return self.n

    def flush(self):
        pass


def pack(export_dir, out_tar, *, expected_dirname, expected_workflow_context, expected_run_id, clock=time.monotonic):
    """Bind the export to the exact workflow/run, validate the closed summary and fixed path categories, verify every file
    against the ONCE-captured inventory, then publish one tar atomically (private temp, fchmod 0644, fsync, exclusive link)."""
    if not APPROVED_FOR_EXECUTION:
        raise RuntimeError('publication packer HELD')
    deadline = clock() + MAX_SECONDS
    export_dir = os.path.abspath(os.fspath(export_dir))
    if os.path.basename(export_dir) != expected_dirname:
        raise ValueError('export directory is not the exact workflow/run export')
    dfd = _open_anchored(export_dir, final_private=True)
    try:
        summary_bytes = _read_regular(dfd, SUMMARY, 16 * 1024 ** 2)  # captured ONCE; everything below derives from these bytes
        summary = json.loads(summary_bytes)
        if not isinstance(summary, dict) or set(summary) != SUMMARY_KEYS or summary['version'] != 'owned-final-export/1':
            raise ValueError('closed export summary required')
        if (summary['workflow_context'], summary['infrastructure_run_id']) != (expected_workflow_context, expected_run_id):
            raise ValueError('summary belongs to a different workflow/run')
        if summary['private_candidates_exported'] is not False or summary['original_status_not_upgraded'] is not True:
            raise ValueError('summary does not describe an allowlisted export')
        inv = summary['inventory']
        if not isinstance(inv, list) or len(inv) > MAX_FILES:
            raise ValueError('bounded inventory list required')
        listed, declared = {}, 0
        for row in inv:
            if (not isinstance(row, dict) or set(row) != {'path', 'bytes', 'sha256'} or not allowed_path(row['path'])
                    or type(row['bytes']) is not int or not 0 <= row['bytes'] <= 16 * 1024 ** 2
                    or not isinstance(row['sha256'], str) or HEX64.fullmatch(row['sha256']) is None or row['path'] in listed):
                raise ValueError('inventory row outside the exporter fixed categories or schema')
            m = STORE_KEY.fullmatch(row['path'])
            if m and m.group(2) != row['sha256']:
                raise ValueError('product-store object name must equal its sha256')
            declared += row['bytes']
            if declared + len(summary_bytes) > MAX_TOTAL:
                raise ValueError('declared export bytes ceiling (summary included)')
            listed[row['path']] = row
        present, counters = [], {'dirs': 0}
        _walk(dfd, '', present, counters, deadline, clock)
        if set(present) != set(listed) | {SUMMARY} or len(present) != len(set(present)):
            raise ValueError('export file set differs from its inventory (extra or missing)')
        blobs = {}
        for rel in sorted(listed):
            if clock() > deadline:
                raise TimeoutError('cooperative packer deadline')
            data = _read_regular(dfd, rel, listed[rel]['bytes'])
            if len(data) != listed[rel]['bytes'] or hashlib.sha256(data).hexdigest() != listed[rel]['sha256']:
                raise ValueError('export file differs from inventory: ' + rel)
            blobs[rel] = data
        blobs[SUMMARY] = summary_bytes
    finally:
        os.close(dfd)
    product = (summary['complete_product_evidence'] is True and summary['complete_diagnostic_export'] is True
               and summary['published_status'] == 'passed')
    out_tar = os.path.abspath(os.fspath(out_tar))
    parent_fd = _open_anchored(os.path.dirname(out_tar))
    leaf = os.path.basename(out_tar)
    temp = '.%s.%s.partial' % (leaf, secrets.token_hex(8))
    try:
        try:
            os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError('one-shot publication destination exists')
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            writer = _HashingWriter(fd)
            with tarfile.open(fileobj=writer, mode='w', format=tarfile.PAX_FORMAT) as tf:
                for rel in sorted(blobs):
                    ti = tarfile.TarInfo(rel)
                    ti.size, ti.mode, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = len(blobs[rel]), 0o644, 0, 0, 0, '', ''
                    tf.addfile(ti, io.BytesIO(blobs[rel]))
            os.fchmod(fd, 0o644)  # umask-independent: runner-readable by explicit descriptor mode
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(temp, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)  # exclusive: fails if it exists
        os.fsync(parent_fd)
    finally:
        try:
            os.unlink(temp, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)
    return {'files': len(blobs), 'bytes': sum(len(b) for b in blobs.values()), 'tar_bytes': writer.n,
            'tar_sha256': writer.h.hexdigest(), 'diagnostic_only': not product, 'product_evidence_export': product}
