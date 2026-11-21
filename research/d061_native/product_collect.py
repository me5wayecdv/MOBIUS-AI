"""Independent bounded recovery collector. No raw recursive upload, no keys/home."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sqlite3
import re

from lifecycle import lexical


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--product-root',type=Path,required=True)
    p.add_argument('--tls-root',type=Path,required=True)
    p.add_argument('--control',type=Path,required=True)
    p.add_argument('--safe',type=Path,required=True)
    a=p.parse_args()
    a.safe.mkdir(mode=0o755,exist_ok=False)
    report={'copied':[],'missing':[],'errors':[],'full_original_archive':False,'bounded_recovery_only':True}
    files=('outer-child.json','emergency-cleanup.json','workflow-command.json','host-failure.json','fixture.log',
        'fixture/host-before.json','fixture/host-after.json','fixture/namespace-supervisor.json','fixture/namespace-setup.json',
        'fixture/wrapper-lifecycle.json','fixture/wrapper-cleanup.json','fixture/evidence/native-proof.json',
        'fixture/evidence/binding.json','fixture/evidence/policy.json','fixture/evidence/initial.native',
        'fixture/evidence/capture-digest.json','fixture/evidence/backend-receipts.json','fixture/evidence/native-events.json',
        'fixture/evidence/replay-enqueued.json','fixture/evidence/replay-started.json','fixture/evidence/replay-completed.json',
        'fixture/evidence/addon-final.json','fixture/evidence/addon-failures.json','fixture/evidence/backend-failures.json',
        'fixture/evidence/driver-cleanup.json','fixture/evidence/driver-failure.json','fixture/evidence/origin.log',
        'fixture/evidence/proxy.log','fixture/evidence/tls-untrusted-proxy-pending.json','fixture/evidence/tls-untrusted-proxy-final.json')
    control_files=('staging.json','workflow-intent.json','product-launch-intent.json','tls-launch-intent.json',
        'product-absence.json','tls-absence.json','product-return.json','tls-return.json','setup/approved-plan.json',
        'setup/fixture-provenance.json','journey/execute-response.json','journey/api-readback.json',
        'journey/report.md','journey/journey-summary.json','mobius.db')
    total=0
    def copy(root,name,prefix,expected_sha=None):
        nonlocal total
        try:
            path=lexical(root/name)
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                meta=os.fstat(stream.fileno())
                if not stat.S_ISREG(meta.st_mode) or meta.st_size>4*1024*1024:raise ValueError('file bound')
                data=stream.read(4*1024*1024+1)
            if len(data)>4*1024*1024 or total+len(data)>32*1024*1024:raise ValueError('recovery total bound')
            if expected_sha is not None and hashlib.sha256(data).hexdigest()!=expected_sha:raise ValueError('original object digest mismatch')
            total+=len(data)
            destination=a.safe/prefix/name;destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes(data);destination.chmod(0o644)
            report['copied'].append({'path':prefix+'/'+name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
        except FileNotFoundError:report['missing'].append(prefix+'/'+name)
        except Exception as exc:report['errors'].append({'path':prefix+'/'+name,'class':type(exc).__name__})
    for prefix,root in (('product',a.product_root/'raw'),('tls',a.tls_root)):
        for name in files:copy(root,name,prefix)
    for name in control_files:copy(a.control,name,'control')
    # Only evidence objects from the new disposable case. Never recurse raw
    # artifact trees, import old PoC blobs, or include the large public APK.
    try:
        plan=json.loads((a.control/'setup/approved-plan.json').read_text())
        database=lexical(a.control/'mobius.db')
        connection=sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True)
        try:
            rows=connection.execute('SELECT id,object_key,sha256,byte_size FROM evidence WHERE investigation_id=?',
                (plan['investigation_id'],)).fetchall()
        finally:connection.close()
        report['product_evidence']=[]
        for evidence_id,key,digest,size in rows:
            if not re.fullmatch(r'apk/[0-9a-f]{2}/[0-9a-f]{64}\.apk',key) or key!=('apk/'+digest[:2]+'/'+digest+'.apk'):
                raise ValueError('unexpected original evidence object key')
            if not isinstance(size,int) or size>4*1024*1024:raise ValueError('original evidence size bound')
            copy(a.control/'artifacts',key,'product-store',expected_sha=digest)
            report['product_evidence'].append({'id':evidence_id,'key':key,'sha256':digest,'bytes':size})
    except FileNotFoundError:report['missing'].append('product-store/not-created')
    except Exception as exc:report['errors'].append({'stage':'product-originals','class':type(exc).__name__})
    # Claim only recovery coverage, never cleanup or product-run success.
    (a.safe/'recovery-summary.json').write_text(json.dumps(report,sort_keys=True))
    if report['errors']:raise SystemExit(1)

if __name__=='__main__':main()
