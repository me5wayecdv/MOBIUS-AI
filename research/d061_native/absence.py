"""Independent read-only final absence check for one exact disposable run root."""
import json
import os
from pathlib import Path
import sys

from lifecycle import identity, lexical
from wire import atomic_json


def inspect(raw):
    raw=lexical(raw,leaf_missing=True)
    errors=[]
    report={'errors':errors,'checked_identities':[],'private_keys_absent':True,
            'homes_absent':True,'recorded_jail_absent':True}
    if raw.exists():
        for relative in ('outer-child.json','fixture/namespace-supervisor.json'):
            path=raw/relative
            if not path.exists():continue
            try:
                value=json.loads(lexical(path).read_text())
                pid=value['pid']
                if type(pid) is not int or pid<=1:raise ValueError('unsafe recorded identity')
                try:now=identity(pid)
                except (FileNotFoundError,ProcessLookupError):now=None
                same=now is not None and all(now.get(k)==value[k] for k in ('pid','starttime','boot_id'))
                report['checked_identities'].append({'source':relative,'same_identity_alive':same})
                if same:errors.append('recorded_process_remains:'+relative)
            except Exception as exc:errors.append('identity_check:'+relative+':'+type(exc).__name__)
        for relative,field in (('fixture/evidence/origin.key','private_keys_absent'),
                               ('fixture/evidence/home','homes_absent')):
            if (raw/relative).exists() or (raw/relative).is_symlink():
                report[field]=False
                errors.append('sensitive_path_remains:'+relative)
        snapshot=raw/'fixture/namespace-setup.json'
        report['remaining_namespace_members']=[]
        if snapshot.exists():
            try:
                spaces=json.loads(lexical(snapshot).read_text())['namespaces']
                expected={name:spaces[name] for name in ('net','pid','mnt')}
                if any(value==os.readlink('/proc/self/ns/'+name) for name,value in expected.items()):
                    raise ValueError('private namespace record matches host namespace')
                for proc in Path('/proc').iterdir():
                    if not proc.name.isdigit():continue
                    for name,value in expected.items():
                        try:matches=os.readlink(proc/'ns'/name)==value
                        except (FileNotFoundError,ProcessLookupError):continue
                        if matches:
                            report['remaining_namespace_members'].append({'pid':int(proc.name),'namespace':name})
                if report['remaining_namespace_members']:errors.append('private_namespace_members_remain')
            except Exception as exc:errors.append('namespace_check:'+type(exc).__name__)
        lifecycle=raw/'fixture/wrapper-lifecycle.json'
        if lifecycle.exists():
            try:
                value=json.loads(lexical(lifecycle).read_text())
                jail=lexical(value['jail_root'],leaf_missing=True)
                if jail.parent!=Path('/opt') or not jail.name.startswith('d061-jail-'):
                    raise ValueError('not exact recorded jail path')
                if jail.exists():
                    report['recorded_jail_absent']=False
                    errors.append('recorded_jail_remains')
                mounts=Path('/proc/self/mountinfo').read_text().splitlines()
                if any(line.split()[4]==str(jail) or line.split()[4].startswith(str(jail)+'/') for line in mounts):
                    errors.append('recorded_jail_mount_remains')
            except Exception as exc:errors.append('jail_check:'+type(exc).__name__)
    report['complete']=not errors
    return report


def main():
    if len(sys.argv)!=3:raise SystemExit('usage: absence.py EXACT_RAW_ROOT REPORT_PATH')
    report=inspect(Path(sys.argv[1]))
    atomic_json(Path(sys.argv[2]),report)
    if report['errors']:raise SystemExit(1)

if __name__=='__main__':main()
