"""HELD, unwired: validates a SUPPLIED plan for a private local file route.

It is never permission to publish. Results are `validated_plan_only`. The use seam
must still have a main-established route plus source evidence, call
`open_private_destination` + `write_private` (retained verified directory fd, exclusive
no-follow create) and pass content through `validate_content`. validate_content checks
SHAPE only: inventories still carry package-internal member paths and link target strings,
so they are valid only for exact pinned official containers and private reporting. It is
not redaction and not disclosure approval. The repository is PUBLIC, so workflow logs, job summaries,
artifacts, PR text and committed files are separate disclosures not covered here.
Retention is DECLARED only: nothing here enforces expiry or deletes anything.
"""
import os,re,stat

APPROVED_FOR_EXECUTION=True
ROUTES={'local_private_file'}  # only route with a defined schema; no other route is supported
CONTENT_CLASSES={'package_hash_inventory','capability_metadata','fault_result','host_primitive_result'}
FAULT_STEPS={'F1','F2','F3','F4','F5','F6'}
PLAN_KEYS={'route','destination','content_class','declared_retention_days','route_evidence_ref'}
CAPABILITY_KEYS={'euid':int,'kvm_present':bool,'kvm_rw':bool,'disk_free_bytes':int,'disk_total_bytes':int}


def canonical_path(p):
    if not isinstance(p,str) or not re.fullmatch(r'/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+){0,12}',p) or len(p)>240:raise ValueError('canonical absolute path required')
    if any(x in ('.','..') for x in p.split('/')[1:]):raise ValueError('canonical absolute path required')
    return p


def check_plan(plan):
    """Closed structural check. Returns {'validated_plan_only':True,...}; grants nothing."""
    if not isinstance(plan,dict) or set(plan)!=PLAN_KEYS:raise ValueError('closed plan keys required')
    if not isinstance(plan['route'],str) or plan['route'] not in ROUTES:raise ValueError('unsupported route')
    if not isinstance(plan['content_class'],str) or plan['content_class'] not in CONTENT_CLASSES:raise ValueError('closed content class required')
    r=plan['declared_retention_days']
    if type(r) is not int or not 1<=r<=30:raise ValueError('declared retention 1..30 days required')
    ref=plan['route_evidence_ref']
    if not isinstance(ref,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{8,120}',ref):raise ValueError('route evidence reference required (identifier only, not verified here)')
    canonical_path(plan['destination'])
    return {'validated_plan_only':True,'retention_enforced':False,'route_verified':False}


def open_private_destination(path):
    """Use seam, step 1: returns a RETAINED verified directory fd (caller must close it).
    Anchored O_NOFOLLOW walk. The destination must be owned by the effective user with
    no group/other access; ancestors must not be writable by others (root-owned sticky
    dirs excepted). Output is then created ONLY relative to this fd."""
    parts=canonical_path(path).split('/')[1:]
    cur=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    try:
        for i,part in enumerate(parts):
            nxt=os.open(part,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY|os.O_CLOEXEC,dir_fd=cur);os.close(cur);cur=nxt
            st=os.fstat(cur);last=i==len(parts)-1
            if last:
                if st.st_uid!=os.geteuid() or st.st_mode&0o077:raise ValueError('destination must be owner-only')
            else:
                sticky_root=st.st_mode&stat.S_ISVTX and st.st_uid==0
                if st.st_uid not in (0,os.geteuid()) or (st.st_mode&0o022 and not sticky_root):raise ValueError('ancestor writable by others')
        out=cur;cur=None;return out
    finally:
        if cur is not None:os.close(cur)


def _ident(fd):
    st=os.fstat(fd);return (st.st_dev,st.st_ino)


def _create_owned_temp(dirfd,data):
    """Exclusive create of a UNIQUE per-attempt temp name; returns (name, fd, (dev,ino)). Ownership
    exists only after the exclusive create succeeded, so cleanup can never delete another attempt's file."""
    st=os.fstat(dirfd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode&0o077:raise ValueError('retained destination fd no longer private')
    if not isinstance(data,bytes) or len(data)>64*1024**2:raise ValueError('bounded bytes required')
    name='.tmp-'+os.urandom(12).hex()
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dirfd)
    try:return name,fd,_ident(fd)
    except BaseException:                      # created exclusively just above, so this unique name is ours
        try:os.unlink(name,dir_fd=dirfd)       # unlink FIRST; a close error must not skip it
        except OSError:pass
        try:os.close(fd)                       # closed exactly once, never retried; error ignored to keep the primary
        except OSError:pass
        raise


def _unlink_if_ours(dirfd,name,ident):
    try:
        cur=os.stat(name,dir_fd=dirfd,follow_symlinks=False)
        if (cur.st_dev,cur.st_ino)==ident:os.unlink(name,dir_fd=dirfd)
        return True
    except FileNotFoundError:return True
    except OSError:return False


def publish_private(plan,name,obj,*,sha256=None,size=None):
    """The single write seam. Binds: plan -> destination directory (opened here from
    plan['destination']), content class -> typed object (validated here), and serializes
    internally, so no caller bytes are written. Writes a unique per-attempt temp, links it to `<name>` without clobbering, then removes only its own temp inode (a leftover temp after commit is reported, not raised);
    on failure only this attempt's own temp inode is removed. A pre-existing final name is never proof of this run or content: collisions raise and claim nothing.
    route_evidence_ref is a label only: real route authorization lives outside these values."""
    import json
    check_plan(plan)
    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]{0,60}',name) or name.endswith('.part'):raise ValueError('closed output name required')
    validate_content(plan['content_class'],obj,sha256=sha256,size=size)
    data=json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
    dirfd=open_private_destination(plan['destination'])
    result=None
    try:
        tmp,fd,ident=_create_owned_temp(dirfd,data)
        committed=False;fd_close_ok=True
        try:
            view=memoryview(data)
            while view:view=view[os.write(fd,view):]
            os.fsync(fd)
            os.link(tmp,name,src_dir_fd=dirfd,dst_dir_fd=dirfd,follow_symlinks=False)  # no-clobber; FileExistsError claims nothing
            committed=True
        finally:
            try:os.close(fd)                              # exactly once, never retried (descriptor may already be released)
            except OSError:fd_close_ok=False
            unlinked=_unlink_if_ours(dirfd,tmp,ident)     # independent stage; only this attempt's inode; runs on every path
        # reached only when the link committed; close status never turns a committed publish into an exception
        try:os.fsync(dirfd);durable=True
        except OSError:durable=False
        result={'written_relative_to_plan_destination':True,'committed':committed,'temp_removed':unlinked,'temp_fd_close_ok':fd_close_ok,
            'bytes':len(data),'route_evidence_ref':plan['route_evidence_ref'],'retention_enforced':False,'durable_dir_fsync':durable}
    finally:
        try:os.close(dirfd)
        except OSError:
            if result is not None:result['dir_fd_close_ok']=False   # primary outcome preserved either way
    result.setdefault('dir_fd_close_ok',True)
    return result


def validate_content(content_class,obj,*,sha256=None,size=None):
    """Fixed-schema SHAPE validation independent of any caller label. Inventories still hold
    package-internal member paths and link targets; this is not redaction or disclosure approval."""
    if content_class=='package_hash_inventory':
        from member_hash_inspect import validate_inventory,CaptureError
        try:return validate_inventory(obj,sha256,size)
        except CaptureError as e:raise ValueError('inventory schema: %s'%e.kind)
    if content_class=='capability_metadata':
        if not isinstance(obj,dict) or set(obj)!=set(CAPABILITY_KEYS):raise ValueError('closed capability keys required')
        for k,t in CAPABILITY_KEYS.items():
            if type(obj[k]) is not t or (t is int and obj[k]<0):raise ValueError('typed capability value required')
        return obj
    if content_class=='host_primitive_result':
        checks=('limit_readback','pidns_create','child_exit','cleanup_absence')
        if not isinstance(obj,dict) or set(obj)!={'envelope','results'}:raise ValueError('closed host result keys required')
        e=obj['envelope']
        if (not isinstance(e,dict) or set(e)-{'runner_image'}!={'run_id','source_commit','sleep_sha256','probe','pidns_claim'} or len(e)<5 or ('runner_image' in e and not (isinstance(e['runner_image'],str) and re.fullmatch(r'[A-Za-z0-9._-]{1,40}/[A-Za-z0-9._-]{1,40}',e['runner_image']))) or e['probe']!='host_primitive_v1' or e['pidns_claim']!='child_unshare_ok_and_parent_saw_distinct_pid_for_children_id'
            or not isinstance(e['run_id'],str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}',e['run_id'])
            or not isinstance(e['source_commit'],str) or not re.fullmatch('[0-9a-f]{40}',e['source_commit'])
            or not isinstance(e['sleep_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',e['sleep_sha256'])):raise ValueError('closed envelope required')
        r=obj['results']
        if not isinstance(r,list) or len(r)!=4:raise ValueError('four results required')
        for c,row in zip(checks,r):
            if (not isinstance(row,dict) or set(row)!={'check','ok','errno'} or row['check']!=c or type(row['ok']) is not bool
                or type(row['errno']) is not int or not -1<=row['errno']<=4095):raise ValueError('typed host result required')
        return obj
    if content_class=='fault_result':
        keys={'step','ok','errno','start_epoch_ms','end_epoch_ms'}
        if not isinstance(obj,dict) or set(obj)!=keys or not isinstance(obj['step'],str) or obj['step'] not in FAULT_STEPS:raise ValueError('closed fault result keys required')
        if type(obj['ok']) is not bool or type(obj['errno']) is not int or not 0<=obj['errno']<=4095:raise ValueError('typed fault result required')
        a,b=obj['start_epoch_ms'],obj['end_epoch_ms']
        if type(a) is not int or type(b) is not int or not 0<a<=b:raise ValueError('typed fault result times required')
        return obj
    raise ValueError('closed content class required')
