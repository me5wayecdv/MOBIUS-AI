"""HELD, unwired, NEVER RUN: smallest benign host-primitive probe (F1 + one natural F2).

Establishes, on a disposable root-capable Linux host and only if it is ever authorized,
four separate observations: cgroup limit readback, PID-namespace creation, natural exit of
`sleep 1`, and bounded cleanup absence. No SDK/JDK, APK, member reads, model, network, KVM,
pressure, cancel injection or owner SIGKILL. Denials are failures, never capability passes.
Parent death is NOT handled here: a separate disposable-host teardown/evidence owner is a
precondition (see INTERFACE_SPEC.md section F). Output is a closed record only; this module
prints nothing and never touches stdout/stderr text from children.
"""
import ctypes,hashlib,os,re,select,signal,subprocess,sys,time

APPROVED_FOR_EXECUTION=False
CHECKS=('limit_readback','pidns_create','child_exit','cleanup_absence')
LIMITS={'pids.max':'16','memory.max':str(64*1024**2),'cpu.max':'20000 100000'}
NEEDED_CONTROLLERS={'pids','memory','cpu'}
RUN_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}')
CLONE_NEWPID=0x20000000
DEADLINE_S=10.0


def envelope(run_id,source_sha,sleep_sha):
    if not (isinstance(run_id,str) and RUN_ID.fullmatch(run_id)):raise ValueError('canonical run id required')
    for h in (source_sha,sleep_sha):
        if not (isinstance(h,str) and re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}',h)):raise ValueError('pinned hex identity required')
    return {'run_id':run_id,'source_sha':source_sha,'sleep_sha256':sleep_sha,'probe':'host_primitive_v1'}


def run(ops,env):
    """Pure sequence over an injected ops object so the order is testable without a host.
    Returns {'envelope':env,'results':[{check,ok,errno}x4]}. Every check appears exactly once;
    a failed earlier check marks later ones ok False errno -1 (not run)."""
    res={c:{'check':c,'ok':False,'errno':-1} for c in CHECKS}
    leaf=None;child=None
    def fail(c,e):res[c]={'check':c,'ok':False,'errno':e if isinstance(e,int) and 0<=e<=4095 else 0}
    try:
        try:ops.require_controllers(NEEDED_CONTROLLERS)       # no parent mutation: must already be enabled
        except OSError as e:fail('limit_readback',e.errno);raise StopIteration
        try:leaf=ops.make_leaf(env['run_id'])                 # exclusive mkdir of one unique leaf
        except OSError as e:fail('limit_readback',e.errno);raise StopIteration
        try:
            for k,v in LIMITS.items():ops.write(leaf,k,v)
            ok=all(ops.read(leaf,k)==v for k,v in LIMITS.items())   # read back BEFORE any member joins
        except OSError as e:fail('limit_readback',e.errno);raise StopIteration
        if not ok:fail('limit_readback',0);raise StopIteration
        res['limit_readback']={'check':'limit_readback','ok':True,'errno':0}
        try:child=ops.spawn_gated()                           # blocked child, not yet in leaf, not yet unshared
        except OSError as e:fail('pidns_create',e.errno);raise StopIteration
        try:
            ops.join(leaf,child)                              # child joins exact leaf BEFORE it may unshare/start sleep
            ops.verify_member(leaf,child)
            ops.release_gate(child)
            r=ops.unshare_result(child,DEADLINE_S)            # 0 or errno from the child's own unshare
        except OSError as e:fail('pidns_create',e.errno);raise StopIteration
        if r!=0:fail('pidns_create',r);raise StopIteration
        res['pidns_create']={'check':'pidns_create','ok':True,'errno':0}
        code=ops.wait_exit(child,DEADLINE_S)                  # natural exit under a monotonic deadline; None on deadline
        res['child_exit']={'check':'child_exit','ok':code==0,'errno':0}
    except StopIteration:pass
    finally:
        clean=False
        try:clean=ops.cleanup(leaf,child)                      # live parent only: leaf kill, reap, absence, own-leaf rmdir
        except OSError as e:fail('cleanup_absence',e.errno)
        else:res['cleanup_absence']={'check':'cleanup_absence','ok':bool(clean),'errno':0}
    return {'envelope':env,'results':[res[c] for c in CHECKS]}


class RealOps:
    """Real primitives. Constructor refuses unless the parent is an exact canonical cgroup2 path.
    Untested in the sandbox (no root cgroup host); only the pure sequence above is unit tested."""
    def __init__(self,parent,sleep_path,sleep_sha256):
        if not (isinstance(parent,str) and re.fullmatch(r'/sys/fs/cgroup(/[A-Za-z0-9_.-]+){0,6}',parent)) or '..' in parent:raise ValueError('canonical cgroup parent required')
        self.parent=parent;self.sleep_fd=os.open(sleep_path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
        h=hashlib.sha256()
        while d:=os.read(self.sleep_fd,1048576):h.update(d)
        os.lseek(self.sleep_fd,0,0)
        if h.hexdigest()!=sleep_sha256:raise ValueError('sleep executable differs from pinned identity')
        self.leaf_fd=None;self.proc=None;self.pidfd=None
    def _rd(self,name):
        fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=self.leaf_fd)
        try:return os.read(fd,4096).decode().strip()
        finally:os.close(fd)
    def require_controllers(self,need):
        with open(self.parent+'/cgroup.subtree_control') as f:enabled=set(f.read().split())
        if not need<=enabled:raise OSError(95,'controllers not already enabled in parent subtree_control')
    def make_leaf(self,run_id):
        path='%s/mobius-probe-%s'%(self.parent,run_id);os.mkdir(path,0o700)
        self.path=path;self.leaf_fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW);return path
    def write(self,leaf,name,val):
        fd=os.open(name,os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=self.leaf_fd)
        try:os.write(fd,val.encode())
        finally:os.close(fd)
    def read(self,leaf,name):return self._rd(name)
    def spawn_gated(self):
        code=("import os,sys,ctypes\n"
              "os.read(0,1)\n"
              "if ctypes.CDLL(None,use_errno=True).unshare(%d)!=0:\n"
              "    os.write(1,b'E%%d\\n'%%ctypes.get_errno());os._exit(3)\n"
              "os.write(1,b'U0\\n');pid=os.fork()\n"
              "if pid==0:\n"
              "    os.execv('/proc/self/fd/%d',['sleep','1'])\n"
              "_,st=os.waitpid(pid,0);os._exit(0 if os.WIFEXITED(st) and os.WEXITSTATUS(st)==0 else 1)\n")%(CLONE_NEWPID,self.sleep_fd)
        self.proc=subprocess.Popen([sys.executable,'-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            pass_fds=(self.sleep_fd,),close_fds=True,env={})
        self.pidfd=os.pidfd_open(self.proc.pid);return self.proc.pid
    def join(self,leaf,pid):self.write(leaf,'cgroup.procs',str(pid))
    def verify_member(self,leaf,pid):
        with open('/proc/%d/cgroup'%pid) as f:
            if not f.read().strip().endswith(self.path[len('/sys/fs/cgroup'):]):raise OSError(1,'child not in exact leaf')
    def release_gate(self,pid):self.proc.stdin.write(b'x');self.proc.stdin.close()
    def unshare_result(self,pid,deadline):
        if not select.select([self.proc.stdout],[],[],deadline)[0]:raise OSError(110,'unshare deadline')
        line=os.read(self.proc.stdout.fileno(),16)
        if line.startswith(b'U0'):return 0
        m=re.fullmatch(rb'E(\d{1,4})\n',line)
        return int(m.group(1)) if m else 1
    def wait_exit(self,pid,deadline):
        try:return self.proc.wait(timeout=deadline)
        except subprocess.TimeoutExpired:return None
    def cleanup(self,leaf,child):
        ok=True
        if self.proc is not None:
            if self.proc.poll() is None:
                try:self.write(leaf,'cgroup.kill','1')
                except OSError:
                    try:signal.pidfd_send_signal(self.pidfd,signal.SIGKILL)   # held direct child only
                    except OSError:pass
            try:self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:ok=False
            self.proc.stdout.close()
        if self.leaf_fd is not None:
            try:
                ok=ok and self._rd('cgroup.procs')=='' and 'populated 0' in self._rd('cgroup.events')
                if ok:os.rmdir(self.path)
            finally:
                os.close(self.leaf_fd);self.leaf_fd=None
        if self.pidfd is not None:os.close(self.pidfd);self.pidfd=None
        return ok


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('held: probe run not authorized')
