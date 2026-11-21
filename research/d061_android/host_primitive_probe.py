"""HELD, unwired, NEVER RUN: smallest benign host-primitive probe (F1 + one natural F2).

Establishes, on a disposable root-capable Linux host and only if it is ever authorized,
four separate observations: cgroup limit readback, PID-namespace creation, natural exit of
`sleep 1`, and bounded cleanup absence. No SDK/JDK, APK, member reads, model, network, KVM,
pressure, cancel injection or owner SIGKILL. Denials are failures, never capability passes.
Parent death is NOT handled here: a separate disposable-host teardown/evidence owner is a
precondition (see INTERFACE_SPEC.md section F). Output is a closed record only; this module
prints nothing and never touches stdout/stderr text from children.
"""
import hashlib,os,re,select,signal,stat,subprocess,sys,time

APPROVED_FOR_EXECUTION=False
CHECKS=('limit_readback','pidns_create','child_exit','cleanup_absence')
LIMITS={'pids.max':'16','memory.max':str(64*1024**2),'cpu.max':'20000 100000'}
NEEDED_CONTROLLERS={'pids','memory','cpu'}
RUN_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}')
CLONE_NEWPID=0x20000000
DEADLINE_S=10.0   # ONE total monotonic budget for join..exit; cleanup has its own bounded budget
CLEANUP_S=5.0
MAX_SLEEP_BYTES=16*1024**2


def envelope(run_id,source_commit,sleep_sha256):
    """source_commit is a 40-hex git commit; sleep_sha256 is a 64-hex file digest. Separate types."""
    if not (isinstance(run_id,str) and RUN_ID.fullmatch(run_id)):raise ValueError('canonical run id required')
    if not (isinstance(source_commit,str) and re.fullmatch('[0-9a-f]{40}',source_commit)):raise ValueError('40-hex git commit required')
    if not (isinstance(sleep_sha256,str) and re.fullmatch('[0-9a-f]{64}',sleep_sha256)):raise ValueError('64-hex sha256 required')
    return {'run_id':run_id,'source_commit':source_commit,'sleep_sha256':sleep_sha256,'probe':'host_primitive_v1'}


def run(ops,env,*,clock=time.monotonic):
    """Pure sequence over an injected ops object. Every check appears exactly once; a failed
    earlier check leaves later ones ok False errno -1. Unexpected exceptions become a closed
    failure of the current stage; cleanup always runs once, under its own bounded budget.
    pidns_create means ONLY: the child's unshare(CLONE_NEWPID) returned 0 and the parent saw the
    child's pid_for_children namespace identity differ from its own. Grandchild PID1 membership and
    namespace-wide absence are NOT verified."""
    res={c:{'check':c,'ok':False,'errno':-1} for c in CHECKS}
    leaf=None;child=None;stage='limit_readback'
    deadline=clock()+DEADLINE_S
    def left():return max(0.0,deadline-clock())
    def fail(c,e):res[c]={'check':c,'ok':False,'errno':e if isinstance(e,int) and 0<=e<=4095 else 0}
    try:
        try:
            ops.require_controllers(NEEDED_CONTROLLERS)
            leaf=ops.make_leaf(env['run_id'])
            for k,v in LIMITS.items():ops.write(leaf,k,v)
            ok=all(ops.read(leaf,k)==v for k,v in LIMITS.items())   # read back BEFORE any member joins
        except OSError as e:fail('limit_readback',e.errno);raise StopIteration
        if not ok:fail('limit_readback',0);raise StopIteration
        res['limit_readback']={'check':'limit_readback','ok':True,'errno':0}
        stage='pidns_create'
        try:
            child=ops.spawn_gated()
            ops.join(leaf,child)
            ops.verify_member(leaf,child)
            ops.release_gate(child)
            r=ops.unshare_result(child,left())
        except OSError as e:fail('pidns_create',e.errno);raise StopIteration
        if r!=0:fail('pidns_create',r);raise StopIteration
        res['pidns_create']={'check':'pidns_create','ok':True,'errno':0}
        stage='child_exit'
        code=ops.wait_exit(child,left())
        res['child_exit']={'check':'child_exit','ok':code==0,'errno':0}
    except StopIteration:pass
    except Exception:fail(stage,0)
    finally:
        try:clean=bool(ops.cleanup(leaf,child))
        except OSError as e:fail('cleanup_absence',e.errno)
        except Exception:fail('cleanup_absence',0)
        else:res['cleanup_absence']={'check':'cleanup_absence','ok':clean,'errno':0}
    return {'envelope':env,'results':[res[c] for c in CHECKS]}


def _ns_id(path):
    v=os.readlink(path)
    if not re.fullmatch(r'pid:\[\d{1,20}\]',v):raise OSError(22,'unexpected namespace link')
    return v


class RealOps:
    """Real primitives, UNTESTED against a real cgroup2 host (none in the sandbox). Branch tests use a
    fake directory tree. `trusted_uid` is 0 in production. Honest limits: cgroup2 is inferred from the
    interface files present in the held parent, not from the filesystem type."""
    def __init__(self,parent,sleep_path,sleep_sha256,*,trusted_uid=0):
        self.sleep_fd=None;self.parent_fd=None;self.leaf_fd=None;self.leaf_name=None;self.leaf_ident=None
        self.proc=None;self.pidfd=None;self.trusted_uid=trusted_uid
        if not (isinstance(parent,str) and re.fullmatch(r'/sys/fs/cgroup(/[A-Za-z0-9_.-]+){0,6}',parent)) or '..' in parent.split('/'):raise ValueError('canonical cgroup parent required')
        self.parent_rel=parent[len('/sys/fs/cgroup'):] or '/'
        try:
            self._open_sleep(sleep_path,sleep_sha256)
            self._open_parent(parent)
        except BaseException:
            self.close();raise
    def _trusted(self,st,*,dir_ok):
        if st.st_uid!=self.trusted_uid or st.st_mode&0o022:raise ValueError('trusted owner and non-writable-by-others required')
    def _open_sleep(self,path,sha):
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
        self.sleep_fd=fd;st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size>MAX_SLEEP_BYTES or st.st_nlink<1:raise ValueError('bounded regular executable required')
        self._trusted(st,dir_ok=False)
        h=hashlib.sha256();n=0
        while d:=os.pread(fd,1048576,n):
            n+=len(d);h.update(d)
            if n>MAX_SLEEP_BYTES:raise ValueError('executable bound')
        if h.hexdigest()!=sha or n!=st.st_size:raise ValueError('sleep executable differs from pinned identity')
        st2=os.fstat(fd)
        if (st2.st_ino,st2.st_size,st2.st_mtime_ns,st2.st_ctime_ns)!=(st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns):raise ValueError('executable changed while hashed')
    def _open_parent(self,parent):
        root=getattr(self,'_root','/')
        cur=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        try:
            for part in [x for x in parent.split('/') if x]:
                nxt=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY|os.O_CLOEXEC,dir_fd=cur);os.close(cur);cur=nxt
                self._trusted(os.fstat(cur),dir_ok=True)
            for need in ('cgroup.controllers','cgroup.subtree_control'):
                os.close(os.open(need,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=cur))
            self.parent_fd=cur;cur=None
        finally:
            if cur is not None:os.close(cur)
    def _rd(self,name,fd=None):
        f=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=self.leaf_fd if fd is None else fd)
        try:return os.read(f,4096).decode().strip()
        finally:os.close(f)
    def require_controllers(self,need):
        enabled=set(self._rd('cgroup.subtree_control',self.parent_fd).split())
        if not need<=enabled:raise OSError(95,'controllers not already enabled in parent subtree_control')
    def make_leaf(self,run_id):
        name='mobius-probe-%s'%run_id
        os.mkdir(name,0o700,dir_fd=self.parent_fd)
        self.leaf_name=name                       # acquired state recorded BEFORE any further fallible step
        self.leaf_fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=self.parent_fd)
        st=os.fstat(self.leaf_fd);self.leaf_ident=(st.st_dev,st.st_ino)
        self.leaf_rel=(self.parent_rel.rstrip('/')+'/'+name)
        return name
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
        self.pidfd=os.pidfd_open(self.proc.pid)   # a failure here leaves proc recorded; cleanup() always handles it
        return self.proc.pid
    def join(self,leaf,pid):self.write(leaf,'cgroup.procs',str(pid))
    def verify_member(self,leaf,pid):
        with open('/proc/%d/cgroup'%pid) as f:lines=f.read().splitlines()
        if lines!=['0::'+self.leaf_rel]:raise OSError(1,'child not exactly in the leaf')
    def release_gate(self,pid):
        self.proc.stdin.write(b'x');self.proc.stdin.flush();self.proc.stdin.close()
    def unshare_result(self,pid,budget):
        if not select.select([self.proc.stdout],[],[],budget)[0]:raise OSError(110,'unshare deadline')
        line=os.read(self.proc.stdout.fileno(),16)
        if line.startswith(b'U0'):
            if _ns_id('/proc/%d/ns/pid_for_children'%pid)==_ns_id('/proc/self/ns/pid'):return 1   # unshare "succeeded" but no new namespace seen
            return 0
        m=re.fullmatch(rb'E(\d{1,4})\n',line)
        return int(m.group(1)) if m else 1
    def wait_exit(self,pid,budget):
        try:return self.proc.wait(timeout=budget)
        except subprocess.TimeoutExpired:return None
    def _kill_direct(self):
        if self.proc is None or self.proc.poll() is not None:return
        try:
            if self.pidfd is not None:signal.pidfd_send_signal(self.pidfd,signal.SIGKILL)
            else:self.proc.kill()
        except OSError:
            try:self.proc.kill()
            except OSError:pass
    def cleanup(self,leaf,child):
        """Both obligations are separate: (1) the held direct child is always killed if still live, whether or
        not cgroup.kill worked; (2) the leaf must be empty before it is removed. True only if both hold."""
        ok=True
        try:
            if self.leaf_fd is not None and self.proc is not None and self.proc.poll() is None:
                try:self.write(leaf,'cgroup.kill','1')
                except OSError:pass
            self._kill_direct()
            if self.proc is not None:
                for pipe in (self.proc.stdin,self.proc.stdout):
                    try:
                        if pipe is not None:pipe.close()
                    except OSError:pass
                try:self.proc.wait(timeout=CLEANUP_S)
                except subprocess.TimeoutExpired:ok=False
            if self.leaf_fd is not None:
                try:
                    empty=self._rd('cgroup.procs')=='' and 'populated 0' in self._rd('cgroup.events').splitlines()
                    st=os.stat(self.leaf_name,dir_fd=self.parent_fd,follow_symlinks=False)
                    if (st.st_dev,st.st_ino)!=self.leaf_ident:raise OSError(1,'leaf identity changed')
                    if not empty:ok=False
                    else:os.rmdir(self.leaf_name,dir_fd=self.parent_fd)
                except OSError:ok=False
        finally:self.close()
        return ok
    def close(self):
        for attr in ('pidfd','leaf_fd','parent_fd','sleep_fd'):
            fd=getattr(self,attr,None)
            if fd is not None:
                try:os.close(fd)
                except OSError:pass
                setattr(self,attr,None)


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('held: probe run not authorized')
