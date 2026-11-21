"""HELD source-only pinned-image content producer for the Docker backend. Executes nothing, calls no docker.

Input is the bytes of a `docker save` archive (the owner would obtain it from the daemon; acquisition is NOT implemented here).
Grounding chain: the image ID is sha256 of the image config JSON; the config carries rootfs.diff_ids; each layer tar is hashed and
must equal its diff_id. So the file inventory is bound to the image ID, not to a name or a supplied dictionary. Layers are applied in
order with OCI/Docker whiteout semantics to give the FINAL filesystem (path, type, mode, uid/gid, size, sha256 or link target).
Only regular files, directories, symlinks and hardlinks are admitted; devices/fifos, absolute or traversing paths, and over-limit
archives are rejected. Inventory paths carry package paths, so it is private, never a public artifact.
"""
import hashlib
import io
import json
import posixpath
import tarfile

APPROVED_FOR_EXECUTION = False
MAX_MEMBERS = 400000
MAX_FILE = 512 * 1024**2
MAX_TOTAL = 8 * 1024**3
MAX_LAYERS = 128


class ClosureError(ValueError):
    pass


def _clean(name):
    n = name[2:] if name.startswith('./') else name
    n = n.rstrip('/')
    if n in ('', '.'): return '/'
    if n.startswith('/') or any(part in ('..', '', '.') for part in n.split('/')): raise ClosureError('unsafe path')
    return '/' + n


def _read_member(tf, m, limit):
    f = tf.extractfile(m)
    h = hashlib.sha256(); n = 0
    while True:
        c = f.read(1 << 20)
        if not c: break
        n += len(c)
        if n > limit: raise ClosureError('file over limit')
        h.update(c)
    return h.hexdigest()


def _outer(save_bytes, limit=MAX_TOTAL):
    tf = tarfile.open(fileobj=io.BytesIO(save_bytes), mode='r:')
    members = {m.name: m for m in tf.getmembers() if m.isreg()}
    return tf, members


def inventory_from_save(save_bytes, image_id):
    """Returns {path: entry} for the final filesystem of the image whose ID is `image_id` (sha256:<hex>)."""
    if not isinstance(image_id, str) or not image_id.startswith('sha256:'): raise ClosureError('image id')
    tf, files = _outer(save_bytes)
    def get(name):
        if name not in files: raise ClosureError('archive member missing')
        return tf.extractfile(files[name]).read()
    manifest = json.loads(get('manifest.json'))
    if not isinstance(manifest, list) or len(manifest) != 1: raise ClosureError('exactly one image required')
    cfg_name, layers = manifest[0].get('Config'), manifest[0].get('Layers')
    cfg = get(cfg_name)
    if 'sha256:' + hashlib.sha256(cfg).hexdigest() != image_id: raise ClosureError('config digest does not equal image id')
    diff_ids = json.loads(cfg).get('rootfs', {}).get('diff_ids')
    if not isinstance(layers, list) or not layers or len(layers) > MAX_LAYERS or not isinstance(diff_ids, list) or len(diff_ids) != len(layers):
        raise ClosureError('layer/diff_id mismatch')
    fs = {}; total = 0; count = 0
    for name, diff in zip(layers, diff_ids):
        raw = get(name)
        if 'sha256:' + hashlib.sha256(raw).hexdigest() != diff: raise ClosureError('layer is not the config diff_id (compressed layers unsupported)')
        lt = tarfile.open(fileobj=io.BytesIO(raw), mode='r:')
        layer = {}; opaque = set(); whiteouts = set()
        for m in lt.getmembers():
            count += 1
            if count > MAX_MEMBERS: raise ClosureError('member count')
            base = posixpath.basename(m.name.rstrip('/'))
            parent = posixpath.dirname(m.name.rstrip('/'))
            if base == '.wh..wh..opq': opaque.add(_clean(parent) if parent else '/'); continue
            if base.startswith('.wh.'):
                whiteouts.add(_clean(posixpath.join(parent, base[4:]))); continue
            path = _clean(m.name)
            e = {'mode': m.mode & 0o7777, 'uid': m.uid, 'gid': m.gid}
            if m.isdir(): e['type'] = 'dir'
            elif m.isreg():
                if m.size > MAX_FILE: raise ClosureError('file over limit')
                total += m.size
                if total > MAX_TOTAL: raise ClosureError('total over limit')
                e.update(type='file', size=m.size, sha256=_read_member(lt, m, MAX_FILE))
            elif m.issym(): e.update(type='symlink', link=m.linkname)
            elif m.islnk(): e.update(type='hardlink', link=_clean(m.linkname))
            else: raise ClosureError('unsupported member type')
            layer[path] = e
        def under(p, root):
            return p == root or p.startswith(root.rstrip('/') + '/')
        for root in opaque:
            for p in [p for p in fs if p != root and under(p, root)]: del fs[p]
        for w in whiteouts:
            for p in [p for p in fs if under(p, w)]: del fs[p]
        fs.update(layer)
    out = {}
    for p, e in fs.items():
        if e['type'] == 'hardlink':
            t = fs.get(e['link'])
            if t is None or t['type'] != 'file': raise ClosureError('hardlink target missing or not a regular file')
            e = {**e, 'size': t['size'], 'sha256': t['sha256']}
        out[p] = e
    return out


def lock_rows(inventory):
    """Closure-lock rows in the canonical typed form compared by docker_lifecycle.inventory_matches. The lock must be committed/reviewed
    independently of this function's output at acquisition time; this only canonicalizes."""
    return [{'path': p, **inventory[p]} for p in sorted(inventory)]
