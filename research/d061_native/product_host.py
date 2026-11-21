"""HELD trusted ephemeral-CI implementation of product host seam.

Never constructed by an API request/env. No sudo/elevation. Same fixed wrapper
and isolated runtime must already have been separately reviewed/staged by host.
Do not run until exact source plus integration workflow are reviewed.
"""
import json
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

from cleanup import attempt, ordinary_signals_ignored
from lifecycle import identity, lexical, parent_death
from wire import atomic_json
from mobius.services.native_local_fixture import NativeFixtureOutput

APPROVED_FOR_EXECUTION = False

class PreparedCIHost:
    VERSION='mobius-native-ci-host/0.1.0-preparation'

    def __call__(self, request):
        if not APPROVED_FOR_EXECUTION:raise RuntimeError('product host execution HELD')
        if os.geteuid()!=0:raise RuntimeError('ephemeral CI host only, no API elevation')
        from dataclasses import asdict
        root=Path(tempfile.mkdtemp(prefix='d061-product-',dir='/opt'))
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
        original=None
        command={'argv':argv,'rc':None,'errors':[]}
        try:
            with (raw/'fixture.log').open('xb') as log:
                child=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=log,
                    stderr=subprocess.STDOUT,close_fds=True,start_new_session=True,
                    preexec_fn=parent_death(os.getpid(),signal.SIGTERM))
                atomic_json(raw/'outer-child.json',dict(identity(child.pid),stage='product_fixture'))
                command['rc']=child.wait(timeout=420)
            if command['rc']:raise RuntimeError('product fixture failed')
        except BaseException as e:original=e
        finally:
            with ordinary_signals_ignored():
                if child is not None and child.poll() is None:
                    attempt(command['errors'],'TERM',lambda:child.terminate())
                    attempt(command['errors'],'grace_wait',lambda:child.wait(timeout=30))
                    if child.poll() is None:
                        attempt(command['errors'],'KILL',lambda:child.kill())
                        attempt(command['errors'],'reap',lambda:child.wait(timeout=8))
                command['rc']=None if child is None else child.poll()
                if original is not None:command['original_error']=type(original).__name__
                atomic_json(raw/'workflow-command.json',command)
                # Exact existing emergency path, not broad process discovery.
                emergency=subprocess.run([sys.executable,'/opt/d061-reviewed-source/emergency.py',str(raw)],
                    env=env,stdin=subprocess.DEVNULL,close_fds=True,timeout=30)
                if emergency.returncode:command['errors'].append('emergency_failed')
        if original is not None:raise original
        if command['errors']:raise RuntimeError('product host cleanup failed')
        # Only reviewed named original blobs cross the typed host seam.
        names=('initial.native','capture-digest.json','backend-receipts.json','native-events.json',
               'replay-enqueued.json','replay-started.json','replay-completed.json','addon-final.json',
               'driver-cleanup.json','binding.json','policy.json','proxy.log','origin.log')
        artifacts={name:lexical(raw/'fixture/evidence'/name).read_bytes() for name in names}
        for name in ('wrapper-cleanup.json',):artifacts[name]=lexical(raw/'fixture'/name).read_bytes()
        artifacts['emergency-cleanup.json']=lexical(raw/'emergency-cleanup.json').read_bytes()
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
            actual=path.read_bytes()
            digest=hashlib.sha256(actual).hexdigest()
            if actual!=content:raise RuntimeError('copied artifact mismatch')
            copied.append({'path':name,'sha256':digest,'bytes':len(actual)})
        summary={'command_rc':command['rc'],'success':True,'errors':[],
                 'mode':'product_positive_fixture','copied':copied,
                 'binding':asdict(request)}
        atomic_json(safe/'collector-summary.json',summary)
        artifacts['collector-summary.json']=(safe/'collector-summary.json').read_bytes()
        return NativeFixtureOutput(request,artifacts,(self.VERSION,'mitmproxy/12.3.1'))
