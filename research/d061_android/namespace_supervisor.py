"""HELD no-uplink Android namespace supervisor source.

No package/toolchain binary is run by importing this module. Runtime closure and
contained_driver are deliberately unresolved. A source gate cannot grant owner
permission and this module is NOT registered in a workflow or product adapter.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

APPROVED_FOR_EXECUTION = False
CLEAN = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','HOME':'/nonexistent'}
UID = 65534
ENTRYPOINT = '/fixture/contained_driver.py'


def sha256(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):h.update(block)
    return h.hexdigest()


def lexical(path):
    path=Path(os.path.abspath(path))
    for component in (path,*path.parents):
        if component.is_symlink():raise ValueError('no symlink source component')
    return path


def validate_manifest(lock):
    if lock.get('status')!='EXACT_REVIEWED_ANDROID_CLOSURE':
        raise ValueError('unresolved reviewed runtime closure')
    rows=lock.get('files',[])
    if not rows or len(rows)>50000:raise ValueError('bounded complete file closure required')
    seen=set();total=0
    for row in rows:
        name=row.get('destination','');dest=PurePosixPath(name)
        if not dest.is_absolute() or '..' in dest.parts or str(dest)!=name:
            raise ValueError('canonical absolute closure destination')
        if not name.startswith(('/usr/','/lib/','/lib64/','/bin/','/sbin/','/opt/android/','/runtime/','/fixture/','/etc/')):
            raise ValueError('closure destination outside read-only allowlist')
        if name in seen:raise ValueError('duplicate closure destination')
        seen.add(name)
        size=row.get('size')
        if type(size) is not int or size<0 or size>4*1024**3:raise ValueError('closure size bound')
        total+=size
        if total>12*1024**3:raise ValueError('total closure size bound')
        digest=row.get('sha256','')
        if len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):raise ValueError('closure SHA256 required')
        if row.get('mode') not in (0o444,0o555):raise ValueError('immutable regular file mode required')
    required={ENTRYPOINT,'/runtime/bin/python','/usr/bin/setpriv'}
    if not required.issubset(seen):raise ValueError('reviewed driver/Python/setpriv closure required')
    return rows


def copy_closure(root,source,lock):
    # Copy verified bytes, not a broad host /usr, home, /dev or /run bind. Root is
    # fresh and every ancestor is created here, never a caller-populated tree.
    source=lexical(source)
    for row in validate_manifest(lock):
        relative=PurePosixPath(row['source'])
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('closure source path')
        original=lexical(source/str(relative));meta=original.stat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_size!=row['size'] or sha256(original)!=row['sha256']:
            raise ValueError('closure source identity mismatch')
        target=root/row['destination'].lstrip('/')
        target.parent.mkdir(parents=True,exist_ok=True)
        with original.open('rb') as src,target.open('xb') as dst:
            shutil.copyfileobj(src,dst,1048576)
        if target.stat().st_size!=row['size'] or sha256(target)!=row['sha256']:
            raise ValueError('copied closure identity mismatch')
        target.chmod(row['mode'])


def command(argv,*,timeout=10):
    # Fixed reviewed supervisor utilities only; no shell and no input content.
    subprocess.run(argv,env=CLEAN,stdin=subprocess.DEVNULL,close_fds=True,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=timeout)


def atomic_json(path,data):
    temporary=path.with_suffix('.partial')
    with temporary.open('x') as out:json.dump(data,out,sort_keys=True)
    temporary.replace(path)


def topology():
    links=Path('/proc/net/dev').read_text()
    if [x.strip().split(':')[0] for x in links.splitlines()[2:]]!=['lo']:
        raise RuntimeError('no-uplink topology violated')
    routes=Path('/proc/net/route').read_text()
    if any(line.split()[1]=='00000000' for line in routes.splitlines()[1:]):
        raise RuntimeError('default route prohibited')
    return {'namespaces':{x:os.readlink('/proc/self/ns/'+x) for x in ('net','mnt','pid','user')},
        'interfaces':links,'routes4':routes,'routes6':Path('/proc/net/ipv6_route').read_text(),
        'status':Path('/proc/self/status').read_text(),
        'fds':{p.name:os.readlink(p) for p in Path('/proc/self/fd').iterdir() if p.exists()}}


def inside(root,output,kvm_gid,expected_host_netns):
    # Entered as namespace PID1 through unshare --fork. Only root provisioning
    # remains privileged; the driver, build, emulator, ADB and all peers run as
    # UID65534 with one explicit primary KVM group and no supplementary groups.
    if os.getpid()!=1 or os.readlink('/proc/self/ns/net')==expected_host_netns:
        raise RuntimeError('fresh anonymous PID/net namespace required')
    command(['/usr/bin/mount','--make-rprivate','/'])
    command(['/usr/sbin/ip','link','set','lo','up'])
    for name in ('tmp','run','dev/shm','home/fixture','work','proc'):(root/name).mkdir(parents=True,exist_ok=True)
    root.chmod(0o755)
    command(['/usr/bin/mount','--bind',str(root),str(root)])
    command(['/usr/bin/mount','-o','remount,bind,ro,nosuid,nodev',str(root)])
    for name,size,mode in [('tmp','256m','1777'),('run','16m','755'),('dev/shm','512m','1777'),('home/fixture','4g','700')]:
        command(['/usr/bin/mount','-t','tmpfs','-o','size='+size+',mode='+mode+',nosuid,nodev','tmpfs',str(root/name)])
    os.chown(root/'home/fixture',UID,kvm_gid)
    # Output alone persists. Its private mutable owner cannot alter root-owned
    # read-only source/runtime closure. No descriptor to an external host broker.
    work=output/'work';work.mkdir(mode=0o700,exist_ok=False)
    os.chown(work,UID,kvm_gid)
    command(['/usr/bin/mount','--bind',str(work),str(root/'work')])
    command(['/usr/bin/mount','-t','proc','-o','nosuid,nodev,noexec','proc',str(root/'proc')])
    for name in ('null','random','urandom','kvm'):
        command(['/usr/bin/mount','--bind','/dev/'+name,str(root/'dev'/name)])
    atomic_json(output/'namespace-setup.json',topology())
    child=None;result={'complete':False}
    try:
        def child_setup():
            os.chroot(root);os.chdir('/work')
            resource.setrlimit(resource.RLIMIT_CORE,(0,0))
            resource.setrlimit(resource.RLIMIT_NOFILE,(512,512))
            resource.setrlimit(resource.RLIMIT_NPROC,(512,512))
            resource.setrlimit(resource.RLIMIT_CPU,(300,300))
            resource.setrlimit(resource.RLIMIT_AS,(8*1024**3,8*1024**3))
            resource.setrlimit(resource.RLIMIT_FSIZE,(4*1024**3,4*1024**3))
            os.closerange(3,1048576)
        argv=['/usr/bin/setpriv','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',
            '--no-new-privs','--reuid='+str(UID),'--regid='+str(kvm_gid),'--clear-groups',
            '/runtime/bin/python',ENTRYPOINT,'/work']
        env={'PATH':'/opt/android/platform-tools:/runtime/bin:/usr/bin:/bin','HOME':'/home/fixture',
            'ANDROID_USER_HOME':'/home/fixture','TMPDIR':'/tmp','LANG':'C.UTF-8',
            'ADB_SERVER_SOCKET':'tcp:127.0.0.1:5037','ADB_MDNS_AUTO_CONNECT':'0'}
        child=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,close_fds=True,preexec_fn=child_setup)
        result['driver_pid_namespace']=child.pid
        result['driver_rc']=child.wait(timeout=420)
        result['complete']=result['driver_rc']==0
    finally:
        # PID1 exits after writing result. Kernel PID-namespace teardown then
        # kills any descendants, even if emulator/ADB daemonized into a new group.
        if child is not None and child.poll() is None:
            child.kill();child.wait(timeout=5)
        atomic_json(output/'namespace-driver-result.json',result)
    if not result['complete']:raise RuntimeError('contained driver failed')


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD exact closure/driver/lifecycle/source review required')
    if os.geteuid()!=0:raise SystemExit('trusted disposable CI root supervisor only')
    p=argparse.ArgumentParser();p.add_argument('--closure-root',type=Path,required=True)
    p.add_argument('--closure-lock',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--inside',type=Path);p.add_argument('--host-netns');p.add_argument('--kvm-gid',type=int)
    a=p.parse_args()
    if a.inside:
        inside(a.inside,a.output,a.kvm_gid,a.host_netns);return
    if lexical(a.closure_root)!=Path('/opt/d061-android-closure'):
        raise ValueError('exact reviewed disposable closure staging root required')
    closure_meta=a.closure_root.stat()
    if closure_meta.st_uid!=0 or stat.S_IMODE(closure_meta.st_mode)&0o022:
        raise ValueError('root-owned non-writable closure staging root required')
    output=lexical(a.output)
    if output.parent!=Path('/opt') or not output.name.startswith('d061-owned-android-'):
        raise ValueError('exact workflow-owned disposable output required')
    output.mkdir(mode=0o700,exist_ok=False)
    kvm=Path('/dev/kvm').stat()
    if not stat.S_ISCHR(kvm.st_mode) or (os.major(kvm.st_rdev),os.minor(kvm.st_rdev))!=(10,232):
        raise ValueError('exact KVM device identity required')
    if kvm.st_uid!=0 or kvm.st_gid==0 or stat.S_IMODE(kvm.st_mode)!=0o660:
        raise ValueError('reviewable root-owned KVM group/permissions required, no mutation')
    root=Path(tempfile.mkdtemp(prefix='d061-owned-android-jail-',dir='/opt'));child=None;failed=None
    cleanup={'complete':False,'errors':[],'jail':str(root)}
    def interrupt(sig,frame):raise SystemExit(128+sig)
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,interrupt)
    try:
        lock_path=lexical(a.closure_lock)
        if lock_path.stat().st_size>16*1024**2:raise ValueError('closure lock size bound')
        copy_closure(root,a.closure_root,json.loads(lock_path.read_text()))
        for name in ('null','random','urandom','kvm'):
            (root/'dev').mkdir(exist_ok=True);(root/'dev'/name).touch(exist_ok=False)
        atomic_json(output/'host-before.json',topology_host(kvm,lock_path))
        owner_pid=os.getpid()
        def parent_death():
            libc=ctypes.CDLL(None,use_errno=True)
            if libc.prctl(1,signal.SIGKILL,0,0,0)!=0:raise OSError(ctypes.get_errno(),'parent-death setup')
            if os.getppid()!=owner_pid:os._exit(125)
        child=subprocess.Popen(['/usr/bin/unshare','--net','--mount','--pid','--fork','--kill-child=SIGKILL',
            sys.executable,str(Path(__file__).resolve()),'--closure-root',str(a.closure_root),
            '--closure-lock',str(lock_path),'--output',str(output),'--inside',str(root),
            '--host-netns',os.readlink('/proc/self/ns/net'),'--kvm-gid',str(kvm.st_gid)],
            env=CLEAN,stdin=subprocess.DEVNULL,close_fds=True,start_new_session=True,preexec_fn=parent_death)
        rc=child.wait(timeout=480)
        cleanup['rc']=rc
        if rc:raise RuntimeError('namespace supervisor failed')
    except BaseException as error:
        failed=error;cleanup['original_error']=type(error).__name__
    finally:
        for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
        if child is not None and child.poll() is None:
            try:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=10)
            except BaseException as error:cleanup['errors'].append(type(error).__name__)
        setup=output/'namespace-setup.json'
        if not setup.exists():cleanup['errors'].append('namespace_identity_unverified')
        else:
            recorded=json.loads(setup.read_text())['namespaces']
            remaining=[]
            # Mount namespace handles matter independently of network membership.
            # A process may have unshared one namespace while retaining another.
            for kind in ('net','mnt','pid'):
                for path in Path('/proc').glob('[0-9]*/ns/'+kind):
                    try:
                        if os.readlink(path)==recorded[kind]:remaining.append(str(path))
                    except FileNotFoundError:pass
                    except PermissionError:cleanup['errors'].append('namespace_membership_unreadable')
            cleanup['remaining_namespace_members']=remaining
            if remaining:cleanup['errors'].append('namespace_members_remain')
        # Never recursively delete a possibly still-mounted root. The private
        # mount namespace must already be gone and no netns holder may remain.
        if not cleanup['errors']:
            try:shutil.rmtree(root)
            except BaseException as error:cleanup['errors'].append(type(error).__name__)
        cleanup['jail_absent']=not root.exists()
        cleanup['complete']=failed is None and not cleanup['errors'] and cleanup['jail_absent']
        atomic_json(output/'wrapper-cleanup.json',cleanup)
    if failed:raise failed
    if not cleanup['complete']:raise RuntimeError('namespace cleanup incomplete')


def topology_host(kvm,lock):
    return {'host_namespaces':{x:os.readlink('/proc/self/ns/'+x) for x in ('net','mnt','pid')},
        'closure_lock_sha256':sha256(lock),'kvm':{'major':10,'minor':232,'uid':kvm.st_uid,'gid':kvm.st_gid,
        'mode':stat.S_IMODE(kvm.st_mode)},'execution_result':False}


if __name__=='__main__':main()
