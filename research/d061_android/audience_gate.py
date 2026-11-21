"""HELD, unwired: validates a SUPPLIED plan for a private local file route.

It is never permission to publish. Results are `validated_plan_only`. The use seam
must still have a main-established route plus source evidence, call
`verify_private_destination` at write time, and pass content through
`validate_content`. The repository is PUBLIC, so workflow logs, job summaries,
artifacts, PR text and committed files are separate disclosures not covered here.
Retention is DECLARED only: nothing here enforces expiry or deletes anything.
"""
import os,re,stat

APPROVED_FOR_EXECUTION=False
ROUTES={'local_private_file'}  # only route with a defined schema; no other route is supported
CONTENT_CLASSES={'package_hash_inventory','capability_metadata'}
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


def verify_private_destination(path):
    """Use-time check: anchored no-follow traversal; the destination directory must be
    owned by the effective user with no group/other access; ancestors must not be
    writable by others (root-owned sticky dirs excepted)."""
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
        return True
    finally:os.close(cur)


def validate_content(content_class,obj,*,sha256=None,size=None):
    """Fixed-schema validation independent of any caller label. No free text passes."""
    if content_class=='package_hash_inventory':
        from member_hash_inspect import validate_inventory,CaptureError
        try:return validate_inventory(obj,sha256,size)
        except CaptureError as e:raise ValueError('inventory schema: %s'%e.kind)
    if content_class=='capability_metadata':
        if not isinstance(obj,dict) or set(obj)!=set(CAPABILITY_KEYS):raise ValueError('closed capability keys required')
        for k,t in CAPABILITY_KEYS.items():
            if type(obj[k]) is not t or (t is int and obj[k]<0):raise ValueError('typed capability value required')
        return obj
    raise ValueError('closed content class required')
