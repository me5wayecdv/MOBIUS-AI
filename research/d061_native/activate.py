"""Held workflow orchestrator. Review install and positive modes independently."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import signal
from cleanup import attempt, error_record, ordinary_signals_ignored
from lifecycle import identity, parent_death, lexical
from wire import atomic_json

ALLOW_INSTALL_ONLY = True
ALLOW_POSITIVE_FIXTURE = True

def main():
    if len(sys.argv)!=4:raise SystemExit('usage: activate.py MODE NEW_RAW_ROOT WHEELHOUSE')
    mode,raw,wheelhouse=sys.argv[1],lexical(sys.argv[2],leaf_missing=True),lexical(sys.argv[3])
    if mode not in ('install_only','positive_fixture'):raise RuntimeError('unknown mode')
    if not ALLOW_INSTALL_ONLY:raise SystemExit('INSTALL MODE HELD: exact review required')
    if mode=='positive_fixture' and not ALLOW_POSITIVE_FIXTURE:raise SystemExit('POSITIVE RUNTIME HELD')
    if os.geteuid()!=0:raise RuntimeError('ephemeral CI root orchestrator required')
    source=Path(__file__).resolve().parent
    raw.mkdir(mode=0o700,exist_ok=False)
    stage=Path('/opt/d061-reviewed-source')
    stage.mkdir(mode=0o755,exist_ok=False)
    manifest=[]
    names=('installer.py','wrapper.py','driver.py','origin.py','addon.py','wire.py','cleanup.py',
           'lifecycle.py','emergency.py','wheel-lock.json','requirements.lock','bootstrap-lock.json')
    for name in names:
        content=(source/name).read_bytes()
        manifest.append({'path':name,'sha256':hashlib.sha256(content).hexdigest()})
        if name=='installer.py' or mode=='positive_fixture' and name in ('wrapper.py','driver.py'):
            text=content.decode()
            marker='APPROVED_FOR_EXECUTION = False'
            if text.count(marker)!=1:raise RuntimeError('unexpected activation source')
            text=text.replace(marker,'APPROVED_FOR_EXECUTION = True')
            ast.parse(text)
            content=text.encode()
        (stage/name).write_bytes(content)
        (stage/name).chmod(0o644)
    manifest_record={'mode':mode,'reviewed_checkout_sha':os.environ.get('D061_REVIEWED_SHA'),
                     'source_files':manifest,'staged_dir':str(stage),'no_product_changes':True}
    (raw/'activation-record.json').write_text(json.dumps(manifest_record,sort_keys=True)+'\n')
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','HOME':'/nonexistent',
         'ImageOS':os.environ.get('ImageOS',''),'ImageVersion':os.environ.get('ImageVersion','')}
    def interrupted(signum,frame):raise SystemExit(128+signum)
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
    def command(argv,name):
        # Budget: wrapper max host snapshot140 + child75 + teardown8 +
        # post snapshot140 + IO overhead <400; outer deadline420 then a
        # bounded30-second graceful cleanup before identity-coupled kill.
        budget=420 if name=='fixture' else 270
        record={'mode':mode,'stage':name,'argv':argv,'rc':None,'error':None,'cleanup_errors':[]}
        child=None
        original=None
        try:
            atomic_json(raw/'workflow-command.json',record)
            with (raw/(name+'.log')).open('xb') as log:
                child=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=log,
                    stderr=subprocess.STDOUT,close_fds=True,start_new_session=True,
                    preexec_fn=parent_death(os.getpid(),signal.SIGTERM))
                record['identity']=identity(child.pid)
                atomic_json(raw/'outer-child.json',dict(record['identity'],stage=name))
                record['rc']=child.wait(timeout=budget)
            if record['rc']:raise subprocess.CalledProcessError(record['rc'],argv)
        except BaseException as e:
            original=e
            record['error']=error_record(e)
        finally:
            with ordinary_signals_ignored():
                errors=record['cleanup_errors']
                if child is not None and child.poll() is None:
                    attempt(errors,'outer_TERM',lambda:os.kill(child.pid,signal.SIGTERM))
                    attempt(errors,'outer_grace_wait',lambda:child.wait(timeout=30))
                    if child.poll() is None:
                        # Wrapper death causes namespace-unshare SIGKILL via
                        # prctl PDEATHSIG, then unshare kills its namespace PID1.
                        attempt(errors,'outer_KILL',lambda:child.kill())
                        attempt(errors,'outer_reap',lambda:child.wait(timeout=8))
                record['rc']=None if child is None else child.poll()
                attempt(errors,'command_summary',lambda:atomic_json(raw/'workflow-command.json',record))
                attempt(errors,'stage_summary',lambda:atomic_json(raw/(name+'-command.json'),record))
        if original is not None:raise original
        if record['cleanup_errors']:raise RuntimeError('outer cleanup incomplete')
    shutil.copyfile(wheelhouse/'staging-manifest.json',raw/'staging-manifest.json')
    command([sys.executable,str(stage/'installer.py'),str(wheelhouse)],'install')
    shutil.copyfile('/opt/d061-runtime/runtime-record.json',raw/'runtime-record.json')
    if mode=='positive_fixture':
        command([sys.executable,str(stage/'wrapper.py'),'--source',str(stage),
            '--runtime','/opt/d061-runtime','--base-prefix',sys.base_prefix,
            '--output',str(raw/'fixture')],'fixture')

if __name__=='__main__':main()
