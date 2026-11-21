"""Bounded allowlisted collector; validate paths before every read."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from lifecycle import lexical

if len(sys.argv)!=4:raise SystemExit('usage: collect.py RAW_ROOT NEW_SAFE_DIR COMMAND_RC')
raw=lexical(sys.argv[1],leaf_missing=True)
safe=lexical(sys.argv[2],leaf_missing=True)
safe.mkdir(mode=0o755,parents=False,exist_ok=False)
allowed=(
 'activation-record.json','workflow-command.json','install-command.json','fixture-command.json',
 'outer-child.json','emergency-cleanup.json','install.log','fixture.log',
 'runtime-record.json','staging-manifest.json','fixture/host-before.json','fixture/host-after.json',
 'fixture/namespace-setup.json','fixture/namespace-supervisor.json','fixture/wrapper-lifecycle.json','fixture/wrapper-cleanup.json',
 'fixture/evidence/policy.json','fixture/evidence/owned-listeners.json','fixture/evidence/initial.native',
 'fixture/evidence/capture-digest.json','fixture/evidence/backend-receipts.json','fixture/evidence/native-events.json',
 'fixture/evidence/replay-enqueued.json','fixture/evidence/replay-started.json','fixture/evidence/replay-completed.json',
 'fixture/evidence/addon-final.json','fixture/evidence/addon-failures.json','fixture/evidence/backend-failures.json',
 'fixture/evidence/driver-cleanup.json','fixture/evidence/driver-failure.json',
 'fixture/evidence/proxy.log','fixture/evidence/origin.log','fixture/evidence/origin.crt')
report={'command_rc':int(sys.argv[3]),'copied':[],'missing':[],'errors':[]}
required=set()
mode=None

def read(relative):
    path=lexical(raw/relative)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        info=os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>4*1024*1024:raise RuntimeError('file type/size')
        data=f.read(4*1024*1024+1)
    if len(data)>4*1024*1024:raise RuntimeError('read size')
    return data

try:
    mode=json.loads(read('activation-record.json'))['mode']
    if mode not in ('install_only','positive_fixture'):raise ValueError('unknown mode')
    report['mode']=mode
except BaseException as e:
    report['errors'].append({'stage':'validated_mode','class':type(e).__name__})
if report['command_rc']==0 and mode is not None:
    try:
        required.update(('activation-record.json','runtime-record.json','workflow-command.json',
                         'install-command.json','staging-manifest.json','emergency-cleanup.json'))
        emergency=json.loads(read('emergency-cleanup.json'))
        if not emergency['complete'] or emergency['errors']:raise RuntimeError('emergency incomplete')
        if mode=='positive_fixture':
            wrapper=json.loads(read('fixture/wrapper-cleanup.json'))
            driver=json.loads(read('fixture/evidence/driver-cleanup.json'))
            if not wrapper['complete'] or wrapper['errors'] or driver['errors']:
                raise RuntimeError('cleanup incomplete')
            required.update(('fixture-command.json','fixture/wrapper-cleanup.json','fixture/namespace-setup.json',
                'fixture/evidence/driver-cleanup.json','fixture/evidence/candidate-result.json',
                'fixture/evidence/initial.native','fixture/evidence/capture-digest.json',
                'fixture/evidence/backend-receipts.json','fixture/evidence/native-events.json',
                'fixture/evidence/replay-enqueued.json','fixture/evidence/replay-started.json',
                'fixture/evidence/replay-completed.json','fixture/evidence/addon-final.json'))
            allowed+=('fixture/evidence/candidate-result.json',)
    except BaseException as e:report['errors'].append({'stage':'required_evidence','class':type(e).__name__})
total=0
for relative in allowed:
    try:
        data=read(relative)
        total+=len(data)
        if total>32*1024*1024:raise RuntimeError('total evidence bound')
        dest=safe/relative
        dest.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(0o644)
        report['copied'].append({'path':relative,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)})
    except FileNotFoundError:report['missing'].append(relative)
    except BaseException as e:report['errors'].append({'path':relative,'class':type(e).__name__})
copied={item['path'] for item in report['copied']}
if required-copied:report['errors'].append({'stage':'required_copied','missing':sorted(required-copied)})
report['success']=report['command_rc']==0 and not report['errors'] and mode in ('install_only','positive_fixture')
if not report['success']:(safe/'fixture/evidence/candidate-result.json').unlink(missing_ok=True)
(safe/'collector-summary.json').write_text(json.dumps(report,sort_keys=True)+'\n')
(safe/'collector-summary.json').chmod(0o644)
if report['errors']:raise SystemExit(1)
