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
from cleanup import attempt, error_record, ordinary_signals_ignored
from wire import atomic_json
from lifecycle import parent_death, identity

APPROVED_FOR_EXECUTION = False
CLEAN = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','HOME':'/nonexistent'}

def run(argv):
    subprocess.run(argv,env=CLEAN,stdin=subprocess.DEVNULL,close_fds=True,check=True,timeout=10)

def snapshot():
    commands=[
      ['/usr/sbin/ip','-j','-d','link','show'],
      ['/usr/sbin/ip','-j','address','show'],
      ['/usr/sbin/ip','-4','-j','route','show','table','all'],
      ['/usr/sbin/ip','-6','-j','route','show','table','all'],
      ['/usr/sbin/ip','-4','-j','rule','show'],
      ['/usr/sbin/ip','-6','-j','rule','show'],
      ['/usr/sbin/iptables-save'], ['/usr/sbin/ip6tables-save'],
      ['/usr/sbin/nft','list','ruleset'],
      ['/usr/bin/unshare','--version'], ['/usr/bin/setpriv','--version'],
      ['/usr/bin/mount','--version'], ['/usr/sbin/ip','-Version'],
      ['/usr/bin/openssl','version','-a']]
    result={'commands':[],'namespaces':{name:os.readlink('/proc/self/ns/'+name) for name in ('net','pid','mnt','user')},
            'status':Path('/proc/self/status').read_text()}
    for argv in commands:
        p=subprocess.run(argv,env=CLEAN,stdin=subprocess.DEVNULL,close_fds=True,
                         capture_output=True,text=True,timeout=10)
        result['commands'].append({'argv':argv,'rc':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
    return result

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
    topology=snapshot()
    topology.update({'interfaces':interfaces,'runtime':'/opt/d061-runtime','source':'/fixture',
        'effective_launch':['/usr/sbin/chroot',str(root),'/usr/bin/setpriv',
        '--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs',
        '--reuid=65534','--regid=65534','--clear-groups','/opt/d061-runtime/venv/bin/python',
        '/fixture/driver.py','/work/evidence','/opt/d061-runtime/venv'],
        'environment':CLEAN,'limits':{'cpu_seconds':60,'address_space_bytes':1536*1024*1024,
        'open_files':128,'processes':64,'file_bytes':32*1024*1024,'core':0}})
    atomic_json(bind_output/'namespace-setup.json',topology)
    if any(row['rc'] for row in topology['commands']):raise RuntimeError('namespace snapshot incomplete')
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
    p.add_argument('--binding')
    a=p.parse_args()
    source,runtime,base,output=(Path(x).resolve() for x in (a.source,a.runtime,a.base_prefix,a.output))
    if a.inside:
        inside(Path(a.inside),source,runtime,base)
        return
    if runtime!=Path('/opt/d061-runtime'):raise RuntimeError('exact staged runtime path required')
    if any(x.is_symlink() for x in (source,runtime,base)):raise RuntimeError('symlink input root')
    output.mkdir(mode=0o700,parents=False,exist_ok=False)
    if a.binding:
        from lifecycle import lexical
        binding_path=lexical(a.binding)
        binding=json.loads(binding_path.read_text())
        if binding.get('profile')!='trusted-local-positive-v1' or binding.get('traffic_source')!='owned-stdlib-loopback-client-not-apk':
            raise RuntimeError('fixed product fixture binding required')
        atomic_json(output/'binding.json',binding)
        os.chmod(output/'binding.json',0o644)
    root=Path(tempfile.mkdtemp(prefix='d061-jail-',dir='/opt'))
    # No open namespace, host service or credential descriptors survive exec.
    env=dict(CLEAN,D061_WRAPPER_OUTPUT=str(output))
    atomic_json(output/'wrapper-lifecycle.json',{'wrapper_identity':identity(os.getpid()),'jail_root':str(root)})
    child=None
    status={'complete':False,'errors':[]}
    def interrupted(signum,frame):raise SystemExit(128+signum)
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,interrupted)
    original=None
    try:
        atomic_json(output/'host-before.json',snapshot())
        child=subprocess.Popen(['/usr/bin/unshare','--net','--mount','--pid','--fork',
            '--kill-child=SIGKILL',sys.executable,str(Path(__file__).resolve()),
            '--source',str(source),'--runtime',str(runtime),'--base-prefix',str(base),
            '--output',str(output),'--inside',str(root)],
            env=env,stdin=subprocess.DEVNULL,close_fds=True,start_new_session=True,
            preexec_fn=parent_death(os.getpid()))
        atomic_json(output/'namespace-supervisor.json',identity(child.pid))
        rc=child.wait(timeout=75)
        status['exit_code']=rc
        if rc:raise RuntimeError('fixture namespace failed')
    except BaseException as e:
        original=e
        status['original_error']=error_record(e)
    finally:
        with ordinary_signals_ignored():
            errors=status['errors']
            if child is not None and child.poll() is None:
                attempt(errors,'kill_namespace_group',lambda:os.killpg(child.pid,signal.SIGKILL))
            if child is not None:attempt(errors,'reap_namespace_supervisor',lambda:child.wait(timeout=5))
            status['namespace_supervisor_exited']=child is not None and child.poll() is not None
            if not status['namespace_supervisor_exited']:errors.append({'stage':'namespace','class':'unreaped'})
            # Verify no host-visible process still holds the created netns.
            def remaining_members():
                setup=json.loads((output/'namespace-setup.json').read_text())
                inode=setup['namespaces']['net']
                remaining=[]
                for path in Path('/proc').glob('[0-9]*/ns/net'):
                    try:
                        if os.readlink(path)==inode:remaining.append(str(path))
                    except FileNotFoundError:pass
                return remaining
            if (output/'namespace-setup.json').exists():
                status['remaining_namespace_members']=attempt(errors,'verify_no_namespace_members',remaining_members)
                if status['remaining_namespace_members']!=[]:errors.append({'stage':'namespace','class':'members_unresolved'})
            else:errors.append({'stage':'namespace','class':'setup_evidence_missing'})
            import shutil
            attempt(errors,'remove_origin_key',lambda:(output/'evidence'/'origin.key').unlink(missing_ok=True))
            home=output/'evidence'/'home'
            if home.exists():attempt(errors,'remove_private_home',lambda:shutil.rmtree(home))
            if root.exists():attempt(errors,'remove_jail_root',lambda:shutil.rmtree(root))
            status['private_keys_absent']=not ((output/'evidence'/'origin.key').exists() or home.exists())
            status['jail_root_absent']=not root.exists()
            if not status['private_keys_absent'] or not status['jail_root_absent']:
                errors.append({'stage':'sanitize','class':'incomplete'})
            attempt(errors,'host_after',lambda:atomic_json(output/'host-after.json',snapshot()))
            status['complete']=not errors and original is None
            if not status['complete']:
                attempt(errors,'invalidate_candidate',lambda:(output/'evidence'/'candidate-result.json').unlink(missing_ok=True))
            attempt(errors,'write_wrapper_summary',lambda:atomic_json(output/'wrapper-cleanup.json',status))
    if original is not None:
        if status['errors']:original.add_note('Cleanup errors retained in wrapper-cleanup.json: '+repr(status['errors']))
        raise original
    if status['errors']:raise RuntimeError('wrapper cleanup incomplete')

if __name__=='__main__':main()
