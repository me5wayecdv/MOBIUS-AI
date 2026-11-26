"""HELD source-only pinned-image content producer for the Docker backend. Executes nothing, calls no docker.

Input is a `docker save` archive FILE (the owner writes it with `docker save -o` under an RLIMIT_FSIZE ceiling; see docker_owner).
Grounding chain: image ID = sha256 of the config JSON; the config carries rootfs.diff_ids; every layer is streamed through a hash and must
equal its diff_id (uncompressed layers only; anything else is rejected, not guessed). Layers are then evaluated into the FINAL filesystem.

Bounds are checked BEFORE reads: archive size, outer member count and names (duplicates rejected), metadata sizes (manifest/config), layer
count and size, per-layer member count, name/link lengths, per-file and total content bytes. Layers are STREAMED (tar `r|`), never held in memory.

Evaluation is faithful for the supported shapes and CONSERVATIVELY REJECTS the rest: any entry whose ancestor is missing, a symlink or a
non-directory is rejected (symlink-parent traversal is not modeled); a non-directory replacing a directory drops the old descendants; hardlinks
snapshot their target's content AT APPLY TIME (a later replacement of the target does not change the older link); devices/fifos are rejected.
Not modeled (stated, not claimed): xattrs, capabilities, hardlink inode sharing counts, timestamps, sparse files, pax-only attributes.
The inventory carries package paths: private, never a public artifact.
"""
import hashlib
import json
import posixpath
import tarfile

APPROVED_FOR_EXECUTION = False
LIMITS = {'archive': 12 * 1024**3, 'outer_members': 400, 'meta': 4 * 1024**2, 'layers': 128, 'layer_bytes': 8 * 1024**3,
          'layer_members': 400000, 'name': 4096, 'file': 512 * 1024**2, 'total': 8 * 1024**3, 'entries': 1000000}


class ClosureError(ValueError):
    pass


def _clean(name, lim):
    if not isinstance(name, str) or len(name) > lim['name']: raise ClosureError('name length')
    n = name[2:] if name.startswith('./') else name
    n = n.rstrip('/')
    if n in ('', '.'): return '/'
    if n.startswith('/') or any(part in ('..', '', '.') for part in n.split('/')): raise ClosureError('unsafe path')
    return '/' + n


class _Hashing:
    """File-like wrapper that hashes every byte the tar reader consumes and counts them."""
    def __init__(self, f, cap): self.f, self.h, self.n, self.cap = f, hashlib.sha256(), 0, cap
    def read(self, size=-1):
        d = self.f.read(size)
        self.n += len(d)
        if self.n > self.cap: raise ClosureError('layer over limit')
        self.h.update(d); return d
    def drain(self):
        while self.read(1 << 20): pass


def _under(p, root):
    return p == root or p.startswith(root.rstrip('/') + '/')


def raw_tar_guard(f, total_bytes, lim, outer=False):
    """Fixed 512-byte headers only, before tarfile sees anything. Reject extensions BEFORE their declared payload can be allocated.
    No PAX (including xattrs/capabilities), GNU longname/longlink/sparse, base-256 numeric fields or unknown types. Constant buffer.
    Input is seekable and caller-bounded. We reject trailing nonzero bytes, truncated bodies and noncanonical end markers."""
    start = f.tell(); offset = 0; count = 0
    maximum = lim['outer_members'] if outer else lim['layer_members']
    while offset + 512 <= total_bytes:
        h = f.read(512); offset += 512
        if len(h) != 512: raise ClosureError('truncated raw header')
        if h == bytes(512):
            # Only zero padding may follow the first end marker.
            while offset < total_bytes:
                d = f.read(min(65536, total_bytes-offset)); offset += len(d)
                if not d or any(d): raise ClosureError('nonzero or truncated tar trailer')
            f.seek(start); return
        count += 1
        if count > maximum: raise ClosureError('raw member count')
        if h[156:157] not in (b'0', b'\0', b'1', b'2', b'5'): raise ClosureError('PAX/GNU/sparse/unknown extension rejected before allocation')
        if outer and h[156:157] not in (b'0', b'\0', b'5'): raise ClosureError('outer member type')
        rawsize = h[124:136].strip(b'\0 ')
        if any(c not in b'01234567' for c in rawsize): raise ClosureError('non-octal size unsupported')
        n = int(rawsize or b'0',8)
        cap = lim['layer_bytes'] if outer else lim['file']
        if n > cap: raise ClosureError('raw member size')
        if h[156:157] not in (b'0',b'\0') and n != 0: raise ClosureError('non-file payload unsupported')
        name = h[:100].split(b'\0')[0]; prefix = h[345:500].split(b'\0')[0]; link = h[157:257].split(b'\0')[0]
        if len(name)+len(prefix)+1 > lim['name'] or len(link) > lim['name']: raise ClosureError('raw name length')
        padded = (n+511)//512*512
        if offset+padded > total_bytes: raise ClosureError('raw body outside archive')
        f.seek(padded,1); offset += padded
    raise ClosureError('tar end marker missing')


def _outer_index(tf, lim):
    idx = {}
    while True:
        m = tf.next()
        if m is None: break
        if len(idx) >= lim['outer_members']: raise ClosureError('outer member count')
        if not m.isreg() and not m.isdir(): raise ClosureError('outer archive member type')
        if m.name in idx: raise ClosureError('duplicate outer member')
        _clean(m.name, lim)
        idx[m.name] = m
    return idx


def inventory_from_save_file(path, image_id, limits=None):
    try:
        return _inventory(path, image_id, limits)
    except (tarfile.TarError, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, EOFError) as e:
        if isinstance(e, ClosureError): raise
        raise ClosureError('archive malformed or unsupported: ' + type(e).__name__)


def _inventory(path, image_id, limits=None):
    lim = {**LIMITS, **(limits or {})}
    import os
    if not isinstance(image_id, str) or not image_id.startswith('sha256:') or len(image_id) != 71: raise ClosureError('image id')
    if os.path.getsize(path) > lim['archive']: raise ClosureError('archive over limit')
    with open(path, 'rb') as raw:
        raw_tar_guard(raw, os.path.getsize(path), lim, outer=True)
    with tarfile.open(path, 'r:') as tf:
        idx = _outer_index(tf, lim)
        def small(name):
            m = idx.get(name)
            if m is None or not m.isreg() or m.size > lim['meta']: raise ClosureError('metadata member missing or over limit')
            return tf.extractfile(m).read()
        manifest = json.loads(small('manifest.json'))
        if not isinstance(manifest, list) or len(manifest) != 1 or not isinstance(manifest[0], dict): raise ClosureError('exactly one image required')
        cfg_name, layers = manifest[0].get('Config'), manifest[0].get('Layers')
        cfg = small(cfg_name)
        if 'sha256:' + hashlib.sha256(cfg).hexdigest() != image_id: raise ClosureError('config digest does not equal image id')
        diff_ids = json.loads(cfg).get('rootfs', {}).get('diff_ids')
        if (not isinstance(layers, list) or not layers or len(layers) > lim['layers'] or not isinstance(diff_ids, list) or len(diff_ids) != len(layers)
                or len(set(layers)) != len(layers)): raise ClosureError('layer/diff_id mismatch')
        fs = {}; budget = {'total': 0, 'entries': 0}
        for name, diff in zip(layers, diff_ids):
            m = idx.get(name)
            if m is None or not m.isreg() or m.size > lim['layer_bytes']: raise ClosureError('layer missing or over limit')
            raw_tar_guard(tf.extractfile(m), m.size, lim)
            _apply_layer(fs, tf.extractfile(m), diff, lim, budget)
    return {p: dict(e) for p, e in fs.items()}


def _apply_layer(fs, raw, diff, lim, budget):
    hr = _Hashing(raw, lim['layer_bytes'])
    entries = []; opaque = []; whiteouts = []; count = 0
    with tarfile.open(fileobj=hr, mode='r|') as lt:
        for m in lt:
            count += 1
            if count > lim['layer_members']: raise ClosureError('layer member count')
            if len(m.linkname or '') > lim['name']: raise ClosureError('link length')
            base = posixpath.basename(m.name.rstrip('/')); parent = posixpath.dirname(m.name.rstrip('/'))
            if base == '.wh..wh..opq': opaque.append(_clean(parent, lim) if parent else '/'); continue
            if base.startswith('.wh.'): whiteouts.append(_clean(posixpath.join(parent, base[4:]), lim)); continue
            e = {'mode': m.mode & 0o7777, 'uid': m.uid, 'gid': m.gid}
            if m.isdir(): e['type'] = 'dir'
            elif m.isreg():
                if m.size > lim['file']: raise ClosureError('file over limit')
                budget['total'] += m.size
                if budget['total'] > lim['total']: raise ClosureError('total over limit')
                h = hashlib.sha256(); n = 0; f = lt.extractfile(m)
                while True:
                    c = f.read(1 << 20)
                    if not c: break
                    n += len(c); h.update(c)
                e.update(type='file', size=n, sha256=h.hexdigest())
            elif m.issym(): e.update(type='symlink', link=m.linkname)
            elif m.islnk(): e.update(type='hardlink', link=_clean(m.linkname, lim))
            else: raise ClosureError('unsupported member type')
            entries.append((_clean(m.name, lim), e))
    hr.drain()
    if 'sha256:' + hr.h.hexdigest() != diff: raise ClosureError('layer is not the config diff_id (compressed layers unsupported)')
    for root in opaque:
        for p in [p for p in fs if p != root and _under(p, root)]: del fs[p]
    for w in whiteouts:
        for p in [p for p in fs if _under(p, w)]: del fs[p]
    for path, e in entries:
        budget['entries'] += 1
        if budget['entries'] > lim['entries']: raise ClosureError('entry count')
        if path != '/':
            parent = posixpath.dirname(path) or '/'
            if parent != '/' and (fs.get(parent) or {}).get('type') != 'dir': raise ClosureError('ancestor missing, symlink or non-directory (not modeled)')
        old = fs.get(path)
        if old is not None and old['type'] == 'dir' and e['type'] != 'dir':
            for p in [p for p in fs if p != path and _under(p, path)]: del fs[p]
        if e['type'] == 'hardlink':
            t = fs.get(e['link'])
            if t is None or t['type'] not in ('file', 'hardlink'): raise ClosureError('hardlink target missing or not a regular file')
            e = {**e, 'size': t['size'], 'sha256': t['sha256']}    # snapshot at apply time
        fs[path] = e


def lock_rows(inventory):
    """Canonical typed rows compared by docker_lifecycle.inventory_matches. The lock itself must be produced independently of the
    acquisition it checks (reviewed at image build); this only canonicalizes."""
    return [{'path': p, **inventory[p]} for p in sorted(inventory)]
