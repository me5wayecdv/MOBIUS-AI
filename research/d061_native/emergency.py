"""Always-run identity-scoped emergency cleanup, never adopts by name/prefix."""
import json
from pathlib import Path
import shutil
import sys

from cleanup import attempt, ordinary_signals_ignored
from lifecycle import lexical, terminate_identity
from wire import atomic_json

if len(sys.argv)!=2:raise SystemExit('usage: emergency.py EXACT_RAW_ROOT')
raw=lexical(sys.argv[1],leaf_missing=True)
if not raw.exists():raise SystemExit(0)
errors=[]
report={'errors':errors,'terminated':[]}
with ordinary_signals_ignored():
    for relative in ('outer-child.json','fixture/namespace-supervisor.json'):
        path=raw/relative
        def stop(path=path):
            lexical(path)
            value=json.loads(path.read_text())
            record={k:value[k] for k in ('pid','starttime','boot_id')}
            if type(record['pid']) is not int or record['pid']<=1:raise ValueError('unsafe process identity')
            report['terminated'].append({'source':str(path.relative_to(raw)),
                                        'result':terminate_identity(record)})
        if path.exists():attempt(errors,'identity_stop:'+relative,stop)
    # These exact directories belong only to this run's fresh lexical root.
    key=raw/'fixture/evidence/origin.key'
    def remove_key():
        lexical(key)
        key.unlink()
    if key.exists():attempt(errors,'key_sanitize',remove_key)
    home=raw/'fixture/evidence/home'
    def remove_home():
        lexical(home)
        shutil.rmtree(home)
    if home.exists():attempt(errors,'home_sanitize',remove_home)
    lifecycle=raw/'fixture/wrapper-lifecycle.json'
    def remove_jail():
        lexical(lifecycle)
        value=json.loads(lifecycle.read_text())
        jail=lexical(value['jail_root'],leaf_missing=True)
        if jail.parent!=Path('/opt') or not jail.name.startswith('d061-jail-'):
            raise ValueError('not exact recorded jail path')
        if jail.exists():shutil.rmtree(jail)
    if lifecycle.exists():attempt(errors,'recorded_jail_remove',remove_jail)
    if errors:
        candidate=raw/'fixture/evidence/candidate-result.json'
        attempt(errors,'invalidate_candidate',lambda:candidate.unlink(missing_ok=True))
    report['complete']=not errors
    attempt(errors,'emergency_summary',lambda:atomic_json(raw/'emergency-cleanup.json',report))
if errors:raise SystemExit(1)
