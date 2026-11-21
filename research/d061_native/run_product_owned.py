"""HELD workflow-owned fixed command supervisor, independent of product host."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from cleanup import attempt,ordinary_signals_ignored
from lifecycle import identity,lexical,parent_death
from wire import atomic_json

APPROVED_FOR_EXECUTION = False


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD: exact workflow supervisor review required')
    p=argparse.ArgumentParser()
    p.add_argument('--mode',choices=['product','tls'],required=True)
    p.add_argument('--control',type=Path,required=True)
    p.add_argument('--product-root',type=Path,required=True)
    p.add_argument('--tls-root',type=Path,required=True)
    a=p.parse_args()
    if os.geteuid()!=0:raise RuntimeError('ephemeral workflow root supervisor required')
    stage=Path('/opt/d061-reviewed-source')
    control=lexical(a.control)
    for root,prefix in ((a.product_root,'d061-product-'),(a.tls_root,'d061-tls-')):
        root=lexical(root)
        if root.parent!=Path('/opt') or not root.name.startswith(prefix):raise ValueError('unexpected exact workflow root')
    if a.mode=='product':
        argv=[sys.executable,str(stage/'product_http_journey.py'),'--db',str(control/'mobius.db'),
            '--artifacts',str(control/'artifacts'),'--plan',str(control/'setup/approved-plan.json'),
            '--host-root',str(a.product_root),'--output',str(control/'journey')]
        budget=330
    else:
        argv=[sys.executable,str(stage/'tls_wrapper.py'),'--source',str(stage),'--runtime','/opt/d061-runtime',
            '--base-prefix',sys.base_prefix,'--output',str(a.tls_root/'fixture')]
        budget=420
    intent={'mode':a.mode,'argv':argv,'supervisor_identity':identity(os.getpid()),
        'product_root':str(a.product_root),'tls_root':str(a.tls_root),'launched':False,
        'stage':'launch_intent','errors':[],'rc':None}
    record=control/(a.mode+'-launch-intent.json')
    atomic_json(record,intent)
    child=None;original=None
    def interrupted(signum,frame):raise SystemExit(128+signum)
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,interrupted)
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','HOME':'/nonexistent'}
    try:
        with (control/(a.mode+'.log')).open('xb') as log:
            child=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                close_fds=True,start_new_session=True,preexec_fn=parent_death(os.getpid(),signal.SIGTERM))
            intent.update(launched=True,stage='child_started',child_identity=identity(child.pid))
            atomic_json(record,intent)
            if a.mode=='tls':atomic_json(a.tls_root/'outer-child.json',intent['child_identity'])
            intent['rc']=child.wait(timeout=budget)
            if intent['rc']:raise RuntimeError('actual '+a.mode+' command failed')
    except BaseException as exc:original=exc
    finally:
        with ordinary_signals_ignored():
            if child is not None and child.poll() is None:
                attempt(intent['errors'],'TERM',lambda:os.killpg(child.pid,signal.SIGTERM))
                attempt(intent['errors'],'grace_wait',lambda:child.wait(timeout=20))
                if child.poll() is None:attempt(intent['errors'],'KILL',lambda:os.killpg(child.pid,signal.SIGKILL))
                attempt(intent['errors'],'reap',lambda:child.wait(timeout=5))
            intent['rc']=None if child is None else child.poll()
            intent['original_error_class']=None if original is None else type(original).__name__
            intent['stage']='command_returned'
            atomic_json(control/(a.mode+'-return.json'),intent)
    if original is not None:raise original
    if intent['errors']:raise RuntimeError('workflow supervisor cleanup failed')

if __name__=='__main__':main()
