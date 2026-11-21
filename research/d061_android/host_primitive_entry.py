"""HELD entrypoint for the benign F1 + natural-F2 host primitive check. Unwired, not registered.

Mechanical flags are necessary gates, never authority. This module runs nothing unless a reviewed
commit sets APPROVED_FOR_EXECUTION True here, in host_primitive_probe and in audience_gate, and no
argument, environment value, repository text or workflow input can set them.

Source binding (same-bytes): the repo is realpath-resolved and this file must live at
<repo>/research/d061_android. The repo, research dirs and the three module files must be owned by the
trusted uid, not symlinks and not group/other-writable. Each module's git blob id is computed from the
bytes this process READ and compared with `git rev-parse HEAD:<path>` (measured HEAD, clean tree).
host_primitive_probe and audience_gate are then compiled and executed FROM THOSE SAME BYTES, never
imported by name from sys.path. This entry file's own bytes are checked the same way but it is
already running, so that check is best-effort. root vs the runner user is not a security boundary on a
runner with passwordless sudo; the binding protects provenance and accidents, not a malicious sudoer.

Measured here and placed in the envelope by this module (never taken from arguments):
  source_commit  git HEAD of the clean, trusted-owned checkout (fixed /usr/bin/git, empty environment)
  runner_image   ImageOS/ImageVersion labels (a label, not an attestation)

Output: ONE private local file via audience_gate.publish_private under /run/d061-hp-<run_id>, a
directory this process creates itself (mkdir 0700, exclusive) under the root-owned /run. It vanishes
with the VM, so it is NOT a retained or retrievable route. The entry's logic prints nothing (it exits via os._exit); Python parse/startup and top-level imports of this file run before its catch and are not covered. There is no public
fallback. A result that was never committed is dropped. A COMMITTED result is never dropped or
reported as ordinary success when publication flags are incomplete (exit 4).

Exit codes: 0 all checks ok and publication complete; 1 a check failed; 2 refused, startup or setup
error; 3 publish failed before commit; 4 committed but publication flags incomplete. Job conclusion
and any retained log are separate signals whose audience is unresolved.

Claims: no intentional workload network (child env empty, no connection made); that is NOT network
isolation. Probe cleanup is live-owner cleanup only; failure stays False/UNVERIFIED. Provider
decommissioning after the job is the independent fallback, with no attested timing.
"""
import argparse,hashlib,os,re,stat,subprocess,sys,types

APPROVED_FOR_EXECUTION=False
GIT='/usr/bin/git'
RC_OK,RC_CHECK_FAILED,RC_REFUSED,RC_PUBLISH_FAILED,RC_INCOMPLETE=0,1,2,3,4
MODULES=('host_primitive_entry','host_primitive_probe','audience_gate')
REL='research/d061_android'


class Refused(Exception):pass


def _git(repo,*a,git=GIT,runner=subprocess.run):
    r=runner([git,'-C',repo]+list(a),env={},capture_output=True,timeout=20,check=False)
    if r.returncode!=0:raise Refused('git measurement failed')
    return r.stdout.decode('ascii','replace').strip()


def measure_commit(repo,*,git=GIT,runner=subprocess.run):
    head=_git(repo,'rev-parse','HEAD',git=git,runner=runner)
    if not re.fullmatch('[0-9a-f]{40}',head):raise Refused('measured HEAD is not a 40-hex commit')
    if _git(repo,'status','--porcelain','--untracked-files=all',git=git,runner=runner)!='':raise Refused('checkout is not clean')
    return head


def blob_id(data):return hashlib.sha1(b'blob %d\0'%len(data)+data).hexdigest()


def _trusted(st,uid):
    return st.st_uid==uid and not st.st_mode&0o022


def load_bound(repo,*,entry_path=None,trusted_uid=0,git=GIT,runner=subprocess.run):
    """Returns {name:(path,bytes)} for the three modules, each verified against HEAD of `repo`."""
    repo=os.path.realpath(repo)
    here=os.path.dirname(os.path.realpath(entry_path or __file__))
    if here!=repo+'/'+REL:raise Refused('entry is not inside the measured repository')
    for p in (repo,repo+'/research',here):
        st=os.lstat(p)
        if not stat.S_ISDIR(st.st_mode) or not _trusted(st,trusted_uid):raise Refused('untrusted directory ownership or mode')
    out={}
    for name in MODULES:
        path=here+'/'+name+'.py'
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or not _trusted(st,trusted_uid):raise Refused('untrusted module ownership or mode')
            chunks=[]
            while True:
                b=os.read(fd,1<<20)
                if not b:break
                chunks.append(b)
            data=b''.join(chunks)
        finally:os.close(fd)
        if _git(repo,'rev-parse','HEAD:%s/%s.py'%(REL,name),git=git,runner=runner)!=blob_id(data):raise Refused('module bytes differ from HEAD')
        out[name]=(path,data)
    return out


def exec_module(name,path,data):
    m=types.ModuleType(name);m.__file__=path
    exec(compile(data,path,'exec'),m.__dict__)
    return m


def measure_runner_image(environ):
    os_,ver=environ.get('ImageOS',''),environ.get('ImageVersion','')
    lab=r'[A-Za-z0-9._-]{1,40}'
    if not (re.fullmatch(lab,os_) and re.fullmatch(lab,ver)):raise Refused('runner image labels not observed')
    return '%s/%s'%(os_,ver)


def parse(argv):
    class Quiet(argparse.ArgumentParser):
        def error(self,message):raise Refused('closed arguments required')   # no usage text to stderr/logs
    ap=Quiet(add_help=False,allow_abbrev=False)
    for a in ('expected-commit','sleep-path','sleep-sha256','parent','run-id','route-evidence-ref','repo'):ap.add_argument('--'+a,required=True)
    return ap.parse_args(argv)


def _make_dest(path,uid):
    parent=os.path.dirname(path)
    st=os.lstat(parent)
    if not stat.S_ISDIR(st.st_mode) or not _trusted(st,uid):raise Refused('untrusted destination parent')
    os.mkdir(path,0o700)   # exclusive: an existing name is refused, never adopted
    st=os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077:raise Refused('destination not private')


def main(argv=None,*,environ=None,loader=None,measure=None,entry_path=None,trusted_uid=0,dest_parent='/run'):
    """Returns an exit code; never prints. `loader`/`measure` are injection points for tests only."""
    ops=None;result=None;plan=None;ag=None
    try:
        if APPROVED_FOR_EXECUTION is not True:return RC_REFUSED
        environ=os.environ if environ is None else environ
        a=parse(sys.argv[1:] if argv is None else argv)
        if not re.fullmatch('[0-9a-f]{40}',a.expected_commit):raise Refused('expected commit must be 40-hex')
        head=(measure or measure_commit)(a.repo)
        if head!=a.expected_commit:raise Refused('measured commit differs from expected')
        if loader is not None:hp,ag=loader()
        else:
            src=load_bound(a.repo,entry_path=entry_path,trusted_uid=trusted_uid)
            hp=exec_module('host_primitive_probe',*src['host_primitive_probe'])
            ag=exec_module('audience_gate',*src['audience_gate'])
        if not (hp.APPROVED_FOR_EXECUTION is True and ag.APPROVED_FOR_EXECUTION is True):raise Refused('held')
        image=measure_runner_image(environ)
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}',a.run_id):raise Refused('run id')
        dest='%s/d061-hp-%s'%(dest_parent,a.run_id)
        plan={'route':'local_private_file','destination':ag.canonical_path(dest),'content_class':'host_primitive_result','declared_retention_days':1,'route_evidence_ref':a.route_evidence_ref}
        ag.check_plan(plan)
        env=hp.envelope(a.run_id,head,a.sleep_sha256,image)
        _make_dest(dest,trusted_uid)
        ops=hp.RealOps(a.parent,a.sleep_path,a.sleep_sha256)
        result=hp.run(ops,env)
    except BaseException:
        rc=RC_REFUSED if result is None and ops is None else RC_CHECK_FAILED
        if ops is not None:
            try:ops.close()
            except BaseException:pass
        return rc
    try:ops.close()
    except BaseException:pass
    try:
        pub=ag.publish_private(plan,'host-primitive-%s.json'%a.run_id,result)
    except BaseException:
        return RC_PUBLISH_FAILED
    ok=(isinstance(pub,dict) and pub.get('committed') is True and pub.get('temp_removed') is True and pub.get('temp_fd_close_ok') is True
        and pub.get('dir_fd_close_ok') is True and pub.get('durable_dir_fsync') is True)
    if not ok:return RC_INCOMPLETE
    return RC_OK if all(r['ok'] for r in result['results']) else RC_CHECK_FAILED


if __name__=='__main__':
    try:rc=main()
    except BaseException:rc=RC_REFUSED
    os._exit(rc)
