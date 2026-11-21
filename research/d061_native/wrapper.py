#!/usr/bin/env python3
"""HELD root CI supervisor, anonymous net/mount/PID jail, no network targets.

Preparation only. Requires separate exact source/toolchain review and explicit
source activation. Never run on an owner's workstation or production host.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import resource
import subprocess
import sys
import tempfile

APPROVED_FOR_EXECUTION = False
CLEAN = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','HOME':'/nonexistent'}

def run(argv):
    subprocess.run(argv,env=CLEAN,stdin=subprocess.DEVNULL,close_fds=True,check=True,timeout=10)

def inside(root, source, runtime, base_prefix):
    # This branch is PID1 in fresh anonymous PID/net/mount namespaces.
    run(['/usr/bin/mount','--make-rprivate','/'])
    def bind(src, target):
        dest=root/str(target).lstrip('/')
        if Path(src).is_dir():dest.mkdir(parents=True,exist_ok=True)
        else:
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.touch(exist_ok=True)
        run(['/usr/bin/mount','--bind',str(src),str(dest)])
        run(['/usr/bin/mount','-o','remount,bind,ro,nosuid,nodev',str(dest)])
    for name in ('usr','bin','sbin','lib','lib64'):
        src=Path('/'+name)
        if src.is_symlink():(root/name).symlink_to(os.readlink(src))
        elif src.exists():bind(src,'/'+name)
    if not str(base_prefix).startswith('/usr/'):
        bind(base_prefix,base_prefix)
    bind(runtime,'/opt/d061-runtime')
    bind(source,'/fixture')
    if Path('/etc/ssl/certs').exists():bind('/etc/ssl/certs','/etc/ssl/certs')
    if Path('/etc/ssl/openssl.cnf').exists():bind('/etc/ssl/openssl.cnf','/etc/ssl/openssl.cnf')
    for name in ('null','urandom','random'):
        dest=root/'dev'/name
        dest.parent.mkdir(exist_ok=True)
        dest.touch()
        # Device nodes are single-purpose, not a shared /dev broker tree.
        run(['/usr/bin/mount','--bind','/dev/'+name,str(dest)])
    (root/'proc').mkdir()
    run(['/usr/bin/mount','-t','proc','-o','nosuid,nodev,noexec','proc',str(root/'proc')])
    (root/'tmp').mkdir(mode=0o1777)
    (root/'work').mkdir(mode=0o700)
    run(['/usr/bin/mount','-t','tmpfs','-o','size=64m,mode=1777,nosuid,nodev','tmpfs',str(root/'tmp')])
    # Only /work persists; no host /home,/root,/run,/var,/tmp,/sys or sockets.
    bind_output = Path(os.environ['D061_WRAPPER_OUTPUT'])
    run(['/usr/bin/mount','--bind',str(bind_output),str(root/'work')])
    os.chown(bind_output,65534,65534)
    run(['/usr/sbin/ip','link','set','lo','up'])
    interfaces=Path('/proc/net/dev').read_text()
    if any(line.strip().split(':')[0]!='lo' for line in interfaces.splitlines()[2:]):
        raise RuntimeError('unexpected network interface')
    (bind_output/'namespace-setup.json').write_text(json.dumps({
        'netns':os.readlink('/proc/self/ns/net'),'pidns':os.readlink('/proc/self/ns/pid'),
        'interfaces':interfaces,'runtime':'/opt/d061-runtime','source':'/fixture'})+'\n')
    os.chown(bind_output/'namespace-setup.json',65534,65534)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
    resource.setrlimit(resource.RLIMIT_NPROC,(64,64))
    resource.setrlimit(resource.RLIMIT_AS,(1536*1024*1024,1536*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU,(60,60))
    resource.setrlimit(resource.RLIMIT_FSIZE,(32*1024*1024,32*1024*1024))
    root.chmod(0o755)
    os.closerange(3,65536)
    os.execve('/usr/sbin/chroot',['chroot',str(root),'/usr/bin/setpriv',
        '--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs',
        '--reuid=65534','--regid=65534','--clear-groups',
        '/opt/d061-runtime/venv/bin/python','/fixture/driver.py',
        '/work/evidence','/opt/d061-runtime/venv'],CLEAN)

def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD: reviewed source activation required')
    if os.geteuid()!=0:raise SystemExit('ephemeral isolated CI root supervisor required')
    p=argparse.ArgumentParser()
    p.add_argument('--source',required=True)
    p.add_argument('--runtime',required=True)
    p.add_argument('--base-prefix',required=True)
    p.add_argument('--output',required=True)
    p.add_argument('--inside')
    a=p.parse_args()
    source,runtime,base,output=(Path(x).resolve() for x in (a.source,a.runtime,a.base_prefix,a.output))
    if a.inside:
        inside(Path(a.inside),source,runtime,base)
        return
    if runtime!=Path('/opt/d061-runtime'):raise RuntimeError('exact staged runtime path required')
    if any(x.is_symlink() for x in (source,runtime,base)):raise RuntimeError('symlink input root')
    output.mkdir(mode=0o700,parents=False,exist_ok=False)
    root=Path(tempfile.mkdtemp(prefix='d061-jail-',dir='/opt'))
    # No open namespace, host service or credential descriptors survive exec.
    env=dict(CLEAN,D061_WRAPPER_OUTPUT=str(output))
    child=None
    status={'complete':False,'errors':[]}
    def interrupted(signum,frame):raise SystemExit(128+signum)
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,interrupted)
    try:
        child=subprocess.Popen(['/usr/bin/unshare','--net','--mount','--pid','--fork',
            '--kill-child=SIGKILL',sys.executable,str(Path(__file__).resolve()),
            '--source',str(source),'--runtime',str(runtime),'--base-prefix',str(base),
            '--output',str(output),'--inside',str(root)],
            env=env,stdin=subprocess.DEVNULL,close_fds=True,start_new_session=True)
        rc=child.wait(timeout=75)
        status['exit_code']=rc
        if rc:raise RuntimeError('fixture namespace failed')
    finally:
        if child is not None and child.poll() is None:
            # Killing unshare's child PID1 kills all members of that PID
            # namespace, including nested namespaces and new process groups.
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:status['errors'].append('namespace_wait_timeout')
        status['namespace_supervisor_exited']=child is not None and child.poll() is not None
        if not status['namespace_supervisor_exited']:status['errors'].append('namespace_unreaped')
        # Anonymous namespace, no persistent named netns. Mounts disappear when
        # last namespace member dies. Keep evidence, delete signing material even
        # when driver was killed before its finally block.
        import shutil
        for key in (output/'evidence'/'origin.key',):
            key.unlink(missing_ok=True)
        home=output/'evidence'/'home'
        if home.exists():shutil.rmtree(home)
        shutil.rmtree(root)
        status['complete']=not status['errors']
        (output/'wrapper-cleanup.json').write_text(json.dumps(status,sort_keys=True)+'\n')
    if not status['complete']:raise RuntimeError('wrapper cleanup incomplete')

if __name__=='__main__':main()
