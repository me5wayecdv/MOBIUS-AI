"""Shared fixed-wire contract. No imports of third-party packages."""
import hashlib
import json
import os
from pathlib import Path


def atomic_json(path, value):
    path = Path(path)
    tmp = path.with_name('.' + path.name + '.tmp')
    with tmp.open('x') as f:
        json.dump(value, f, sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def append_record(path, value):
    path = Path(path)
    records = json.loads(path.read_text()) if path.exists() else []
    value = dict(value, sequence=len(records)+1)
    records.append(value)
    atomic_json(path, records)
    return value


def canonical(method, path, headers, body, policy):
    pairs = [(k.decode('ascii') if isinstance(k,bytes) else k,
              v.decode('ascii') if isinstance(v,bytes) else v) for k,v in headers]
    lower = [(k.lower(),v) for k,v in pairs]
    keys = [k for k,v in lower]
    if len(set(keys)) != len(keys):raise ValueError('duplicate_header')
    if set(keys) != {'host','accept','x-d061-nonce'}:raise ValueError('header_set')
    if any(len(k)>64 or len(v)>256 or '\r' in v or '\n' in v for k,v in lower):
        raise ValueError('header_bound')
    values = dict(lower)
    if values['host'] != '127.0.0.1:'+str(policy['origin_port']):raise ValueError('authority')
    if values['accept'] != 'application/json' or values['x-d061-nonce'] != policy['nonce']:
        raise ValueError('safe_header_value')
    if method != 'GET' or path != '/receipt?nonce='+policy['nonce'] or body != b'':
        raise ValueError('fixed_request')
    # Header-name case/order are transport incidental. Preserve raw pairs beside
    # canonical value so information is not silently discarded as evidence.
    return {'method':method,'path':path,'headers':sorted(lower),'body_bytes':0,
            'body_sha256':hashlib.sha256(body).hexdigest()}
