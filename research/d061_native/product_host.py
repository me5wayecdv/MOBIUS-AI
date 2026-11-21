"""HELD trusted ephemeral-CI implementation of product host seam.

Never constructed by an API request/env. No sudo/elevation. Same fixed wrapper
and isolated runtime must already have been separately reviewed/staged by host.
Do not run until exact source plus integration workflow are reviewed.
"""
import json
import hashlib
import os
import stat
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

from cleanup import attempt, ordinary_signals_ignored
from lifecycle import identity, lexical, parent_death
from wire import atomic_json
from mobius.services.native_local_fixture import NativeFixtureOutput

APPROVED_FOR_EXECUTION = False

def bounded_read(path, *, limit=4*1024*1024):
    # Reject links/non-regular files and oversize lengths before reading any data.
    path=lexical(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_size>limit:
            raise RuntimeError('product artifact type/size bound')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            data=stream.read(limit+1)
        if len(data)>limit:raise RuntimeError('product artifact grew beyond bound')
        return data
    finally:os.close(fd)

class PreparedCIHost:
    VERSION='mobius-native-ci-host/0.1.0-preparation'

    def __init__(self, run_root):
        # Exact workflow-owned root, never request-selected or name-discovered.
        self.run_root=Path(run_root)

    def __call__(self, request, *, cancel_check=None):
        if not APPROVED_FOR_EXECUTION:raise RuntimeError('product host execution HELD')
        if os.geteuid()!=0:raise RuntimeError('ephemeral CI host only, no API elevation')
        from dataclasses import asdict
        root=lexical(self.run_root)
        if root.parent!=Path('/opt') or not root.name.startswith('d061-product-'):
            raise RuntimeError('exact disposable workflow run root required')
        if any(root.iterdir()):raise RuntimeError('product workflow root must start empty')
        raw=root/'raw'
        raw.mkdir(mode=0o700)
        binding=root/'binding.json'
        atomic_json(binding,asdict(request))
        argv=[sys.executable,'/opt/d061-reviewed-source/wrapper.py',
              '--source','/opt/d061-reviewed-source','--runtime','/opt/d061-runtime',
              '--base-prefix',sys.base_prefix,'--output',str(raw/'fixture'),
              '--binding',str(binding)]
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','HOME':'/nonexistent'}
        child=None
        failure_code=None
        started=time.monotonic()
        original=None
        command={'argv':argv,'rc':None,'errors':[]}
        def interrupted(signum,frame):raise SystemExit(128+signum)
        old_handlers={sig:signal.signal(sig,interrupted) for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP)}
        try:
            with (raw/'fixture.log').open('xb') as log:
                child=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=log,
                    stderr=subprocess.STDOUT,close_fds=True,start_new_session=True,
                    preexec_fn=parent_death(os.getpid(),signal.SIGTERM))
                atomic_json(raw/'outer-child.json',dict(identity(child.pid),stage='product_fixture'))
                while child.poll() is None:
                    if cancel_check is not None and cancel_check():
                        failure_code='host_cancelled'
                        raise RuntimeError('product host cancellation requested')
                    if time.monotonic()-started>=request.budget_seconds:
                        failure_code='host_timeout'
                        raise TimeoutError('approved operation budget exceeded')
                    time.sleep(0.1)
                command['rc']=child.returncode
            if command['rc']:raise RuntimeError('product fixture failed')
        except BaseException as e:
            original=e
            failure_code=failure_code or 'host_failed'
        finally:
            with ordinary_signals_ignored():
                teardown_deadline=time.monotonic()+request.teardown_seconds
                remaining=lambda:max(0.1,teardown_deadline-time.monotonic())
                if child is not None and child.poll() is None:
                    attempt(command['errors'],'TERM',lambda:child.terminate())
                    attempt(command['errors'],'grace_wait',lambda:child.wait(timeout=min(5,remaining())))
                    if child.poll() is None:
                        attempt(command['errors'],'KILL',lambda:child.kill())
                        attempt(command['errors'],'reap',lambda:child.wait(timeout=min(3,remaining())))
                command['rc']=None if child is None else child.poll()
                if original is not None:command['original_error']=type(original).__name__
                def emergency_cleanup():
                    emergency=subprocess.run([sys.executable,'/opt/d061-reviewed-source/emergency.py',str(raw)],
                        env=env,stdin=subprocess.DEVNULL,close_fds=True,timeout=remaining())
                    if emergency.returncode:raise RuntimeError('emergency_failed')
                attempt(command['errors'],'emergency',emergency_cleanup)
                attempt(command['errors'],'command_summary',lambda:atomic_json(raw/'workflow-command.json',command))
            for sig,handler in old_handlers.items():signal.signal(sig,handler)
        if command['errors']:failure_code='host_cleanup_failed'
        # Retain partial original allowlisted failure evidence rather than
        # losing a failed host leg or manufacturing a passed PoCRun.
        names=('native-proof.json','initial.native','capture-digest.json','backend-receipts.json','native-events.json',
               'replay-enqueued.json','replay-started.json','replay-completed.json','addon-final.json',
               'driver-cleanup.json','binding.json','policy.json','proxy.log','origin.log')
        artifacts={}
        collection_errors=[]
        collected_bytes=0
        def collect(name,path):
            nonlocal collected_bytes
            try:
                remaining_budget=min(32*1024*1024,request.max_output_bytes)-collected_bytes
                if remaining_budget<=0:raise RuntimeError('approved original artifact budget exhausted')
                content=bounded_read(path,limit=min(4*1024*1024,remaining_budget))
                collected_bytes+=len(content)
                artifacts[name]=content
            except Exception as exc:
                collection_errors.append({'name':name,'class':type(exc).__name__})
        collect('binding.json',binding)
        collect('workflow-command.json',raw/'workflow-command.json')
        for name in names:
            path=raw/'fixture/evidence'/name
            if path.exists():collect(name,path)
        for name,path in (('wrapper-cleanup.json',raw/'fixture/wrapper-cleanup.json'),
                          ('emergency-cleanup.json',raw/'emergency-cleanup.json')):
            if path.exists():collect(name,path)
        if collection_errors:failure_code='host_collection_failed'
        if failure_code:
            atomic_json(raw/'host-failure.json',{'code':failure_code,
                'original':None if original is None else {'class':type(original).__name__},
                'collection_errors':collection_errors,'command':command,'elapsed_seconds':time.monotonic()-started,
                'approved_operation_seconds':request.budget_seconds,'approved_teardown_seconds':request.teardown_seconds})
            # Diagnostic uses the preapproved failed-attempt reserve, not the
            # original artifact allowance. Full product total is checked before storage.
            artifacts['host-failure.json']=bounded_read(raw/'host-failure.json')
        safe=root/'safe'
        safe.mkdir(mode=0o700)
        copied=[]
        total=0
        for name,content in artifacts.items():
            if len(content)>4*1024*1024:raise RuntimeError('product artifact bound')
            total+=len(content)
            if total>32*1024*1024:raise RuntimeError('product evidence budget')
            path=safe/name
            with path.open('xb') as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            actual=bounded_read(path)
            digest=hashlib.sha256(actual).hexdigest()
            if actual!=content:raise RuntimeError('copied artifact mismatch')
            copied.append({'path':name,'sha256':digest,'bytes':len(actual)})
        summary={'command_rc':command['rc'],'success':not bool(failure_code),'errors':command['errors'],
                 'mode':'product_positive_fixture','copied':copied,
                 'binding':asdict(request)}
        atomic_json(safe/'collector-summary.json',summary)
        artifacts['collector-summary.json']=bounded_read(safe/'collector-summary.json')
        return NativeFixtureOutput(request,artifacts,(self.VERSION,'mitmproxy/12.3.1'),
            'failed' if failure_code else 'passed',failure_code)
