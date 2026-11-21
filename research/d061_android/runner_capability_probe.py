"""HELD, unwired: READ-ONLY metadata observation of a Linux host.

Reads euid, /dev/kvm stat plus access(2), cgroup v2 text files, userns/AppArmor
sysctls and disk usage. It does NOT test sudo, cgroup delegation or writability,
KVM ioctls, namespace creation or containment; those need a separately reviewed
benign probe. Writes nothing, spawns nothing, no network, no downloads.
"""
import json,os,shutil,stat,sys

APPROVED_FOR_EXECUTION=False


def read(path,limit=4096):
    try:
        with open(path,'rb') as f:return f.read(limit).decode('utf-8','replace').strip()
    except OSError as e:return 'unavailable:%s'%e.errno


def probe(root='/'):
    p=lambda x:os.path.join(root,x.lstrip('/'))
    try:
        s=os.stat(p('dev/kvm'));kvm={'present':True,'chardev':stat.S_ISCHR(s.st_mode),'mode':oct(s.st_mode&0o7777),'uid':s.st_uid,'gid':s.st_gid,
            'rw_for_effective_user':os.access(p('dev/kvm'),os.R_OK|os.W_OK)}
    except OSError as e:kvm={'present':False,'errno':e.errno}
    du=shutil.disk_usage(p('/'))
    return {'euid':os.geteuid(),'kvm':kvm,
        'cgroup_v2':{'controllers':read(p('sys/fs/cgroup/cgroup.controllers')),'subtree_control':read(p('sys/fs/cgroup/cgroup.subtree_control')),
            'self':read(p('proc/self/cgroup'))},
        'userns_max':read(p('proc/sys/user/max_user_namespaces')),
        'apparmor_userns_restrict':read(p('proc/sys/kernel/apparmor_restrict_unprivileged_userns')),
        'disk_free_bytes':du.free,'disk_total_bytes':du.total,
        'claims':'observed metadata of this host at read time only; no sudo, delegation, KVM-function, containment, fault or Android capability established'}


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('held: probe run not authorized')
    json.dump(probe(),sys.stdout,sort_keys=True)


if __name__=='__main__':main()
