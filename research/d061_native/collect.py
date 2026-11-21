"""Allowlisted failure-safe collector. Never recurse into fixture output."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

if len(sys.argv)!=4:raise SystemExit('usage: collect.py RAW_ROOT NEW_SAFE_DIR COMMAND_RC')
raw,safe=(Path(x).resolve() for x in sys.argv[1:3])
safe.mkdir(mode=0o755,parents=False,exist_ok=False)
allowed=(
 'activation-record.json','workflow-command.json','install.log','fixture.log',
 'runtime-record.json','staging-manifest.json','host-before.json','host-after.json',
 'namespace-setup.json','wrapper-cleanup.json',
 'evidence/policy.json','evidence/owned-listeners.json','evidence/initial.native',
 'evidence/capture-digest.json','evidence/backend-receipts.json','evidence/native-events.json',
 'evidence/replay-enqueued.json','evidence/replay-started.json','evidence/replay-completed.json',
 'evidence/addon-final.json','evidence/addon-failures.json','evidence/backend-failures.json',
 'evidence/driver-cleanup.json','evidence/driver-failure.json',
 'evidence/proxy.log','evidence/origin.log','evidence/origin.crt')
allowed=tuple(('fixture/'+x if x.startswith(('host-','namespace-','wrapper-','evidence/')) else x) for x in allowed)
report={'command_rc':int(sys.argv[3]),'copied':[],'missing':[],'errors':[]}
if report['command_rc']==0:
    try:
        mode=json.loads((raw/'activation-record.json').read_text())['mode']
        report['mode']=mode
        required=['activation-record.json','runtime-record.json','workflow-command.json','staging-manifest.json']
        if mode=='positive_fixture':
            wrapper=json.loads((raw/'fixture/wrapper-cleanup.json').read_text())
            if not wrapper['complete'] or wrapper['errors']:raise RuntimeError('wrapper not complete')
            required+=['fixture/wrapper-cleanup.json','fixture/evidence/driver-cleanup.json','fixture/evidence/candidate-result.json']
            allowed+=('fixture/evidence/candidate-result.json',)
        for name in required:
            if not (raw/name).is_file():raise RuntimeError('required evidence missing: '+name)
    except BaseException as e:report['errors'].append({'stage':'required_evidence','class':type(e).__name__})
total=0
for relative in allowed:
    path=raw/relative
    try:
        if not path.exists():
            report['missing'].append(relative)
            continue
        # Reject a symlink at every component, not just the basename.
        current=raw
        if raw.is_symlink():raise RuntimeError('raw root symlink')
        for component in Path(relative).parts:
            current=current/component
            if current.is_symlink():raise RuntimeError('symlink source')
        info=path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size>4*1024*1024:raise RuntimeError('file type/size')
        data=path.read_bytes()
        total+=len(data)
        if total>32*1024*1024:raise RuntimeError('total evidence bound')
        dest=safe/relative
        dest.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(0o644)
        report['copied'].append({'path':relative,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)})
    except BaseException as e:report['errors'].append({'path':relative,'class':type(e).__name__})
report['success']=report['command_rc']==0 and not report['errors']
(safe/'collector-summary.json').write_text(json.dumps(report,sort_keys=True)+'\n')
(safe/'collector-summary.json').chmod(0o644)
if report['errors']:raise SystemExit(1)
