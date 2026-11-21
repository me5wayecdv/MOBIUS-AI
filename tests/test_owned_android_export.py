"""Held exporter/manifest source tests with tmp dirs and mocks only, no Android/SDK/network."""
from pathlib import Path
from types import SimpleNamespace as NS
import hashlib
import importlib
import json
import os
import sys
import pytest

ROOT = Path(__file__).parents[1] / 'research/d061_android'
sys.path.insert(0, str(ROOT))
fe = importlib.import_module('final_export')
pem = importlib.import_module('product_export_manifest')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def test_exporter_and_manifest_are_held_by_default():
    assert fe.APPROVED_FOR_EXECUTION is False
    with pytest.raises(RuntimeError):
        fe.export('/x', '/y', owner={'root': '/x'})
    with pytest.raises(SystemExit):
        fe.main()


def _plan(apk):
    return NS(id='poc_A1', investigation_id='scn_B2', target_sha256=sha(apk))


def _ready(apk):
    return {'run_id': 'r1', 'provisioning_id': 'p1', 'apk_sha256': sha(apk)}


def test_manifest_build_and_validation_roundtrip():
    apk = b'apk-bytes'
    store = {sha(apk): apk}
    row = NS(investigation_id='scn_B2', sha256=sha(apk), byte_size=len(apk), object_key='apk/%s/%s.apk' % (sha(apk)[:2], sha(apk)))
    rep = b'report'
    store[sha(rep)] = rep
    rrow = NS(investigation_id='scn_B2', sha256=sha(rep), byte_size=len(rep), object_key='apk/%s/%s.apk' % (sha(rep)[:2], sha(rep)))
    m = pem.build([row, rrow], store.get, ready=_ready(apk), plan=_plan(apk), run={'plan_id': 'poc_A1', 'run_id': 'pcr_C3'},
        report_sha256=sha(rep), run_row=NS(id='pcr_C3', plan_id='poc_A1', investigation_id='scn_B2'))
    owner = {'run_id': 'r1', 'provisioning_id': 'p1'}
    assert {o['sha256'] for o in fe.object_rows(m, owner)} == {sha(apk), sha(rep)}
    with pytest.raises(ValueError):
        fe.object_rows(m, {'run_id': 'other', 'provisioning_id': 'p1'})
    with pytest.raises(ValueError):
        fe.object_rows({**m, 'extra': 1}, owner)
    with pytest.raises(ValueError):
        fe.object_rows({**m, 'objects': [{'sha256': sha(b'z'), 'bytes': 1}]}, owner)  # APK absent


def test_manifest_refuses_cross_case_noncanonical_and_tampered_objects():
    apk = b'apk-bytes'
    good = NS(investigation_id='scn_B2', sha256=sha(apk), byte_size=len(apk), object_key='apk/%s/%s.apk' % (sha(apk)[:2], sha(apk)))
    store_rep = b'rep'
    rrow = NS(investigation_id='scn_B2', sha256=sha(store_rep), byte_size=3, object_key='apk/%s/%s.apk' % (sha(store_rep)[:2], sha(store_rep)))
    kw = dict(ready=_ready(apk), plan=_plan(apk), run={'plan_id': 'poc_A1', 'run_id': 'pcr_C3'}, report_sha256=sha(store_rep),
        run_row=NS(id='pcr_C3', plan_id='poc_A1', investigation_id='scn_B2'))
    lk = {sha(apk): apk, sha(store_rep): store_rep}
    assert pem.build([good, rrow], lk.get, **kw)['report_sha256'] == sha(store_rep)
    with pytest.raises(ValueError):
        pem.build([good], lk.get, **kw)  # report object absent from inventory
    with pytest.raises(ValueError):
        pem.build([good, rrow], lk.get, **{**kw, 'run_row': NS(id='pcr_C3', plan_id='poc_A1', investigation_id='scn_other')})
    with pytest.raises(ValueError):
        pem.build([good, rrow], lk.get, **{**kw, 'run_row': None})
    with pytest.raises(ValueError):
        pem.build([NS(**{**good.__dict__, 'investigation_id': 'scn_other'}), rrow], lk.get, **kw)
    with pytest.raises(ValueError):
        pem.build([NS(**{**good.__dict__, 'object_key': '../x'}), rrow], lk.get, **kw)
    with pytest.raises(ValueError):
        pem.build([good, rrow], {sha(apk): b'tampered', sha(store_rep): store_rep}.get, **kw)
    with pytest.raises(ValueError):
        pem.build([good, rrow], lk.get, **{**kw, 'run': {'plan_id': 'zzz', 'run_id': 'pcr_C3'}})


def test_export_copies_only_allowlist_and_keeps_failed_absence(tmp_path, monkeypatch):
    old = os.umask(0o077)
    try:
        monkeypatch.setattr(fe, 'APPROVED_FOR_EXECUTION', True)
        root = tmp_path / 'root'
        (root / 'runtime').mkdir(parents=True)
        (root / 'control' / 'work').mkdir(parents=True)
        (root / 'outer-owner-result.json').write_text('{}')
        (root / 'secret.key').write_text('PRIVATE')
        (root / 'runtime-launch-intent.json').write_text('{}')
        (root / 'runtime' / 'namespace-setup.json').write_text('{}')
        (root / 'control' / 'work' / 'mobius.db').write_bytes(b'db')
        (root / 'control' / 'work' / 'mobius.db-wal').write_bytes(b'wal')
        owner = {'root': str(root), 'run_id': 'r1', 'provisioning_id': 'p1', 'workflow_context': 'ctx'}

        def unproven(output, stage, record_name):
            raise RuntimeError('absence unproven')
        dest = tmp_path / 'out'
        res = fe.export(root, dest, owner=owner, absence_checker=unproven)
        assert res['complete'] is False
        assert res['role_absence'] == {'runtime': 'unverified', 'control': 'unverified'}
        assert res['original_status_not_upgraded'] and res['private_candidates_exported'] is False
        paths = {r['path'] for r in res['inventory']}
        assert 'root/outer-owner-result.json' in paths and 'runtime/namespace-setup.json' in paths
        assert not any('secret.key' in p or 'mobius.db' in p for p in paths)  # no payload while absence unverified
        assert (dest / 'export-summary.json').exists()
    finally:
        os.umask(old)


def test_export_db_sidecars_not_called_coherent(tmp_path, monkeypatch):
    old = os.umask(0o077)
    try:
        monkeypatch.setattr(fe, 'APPROVED_FOR_EXECUTION', True)
        root = tmp_path / 'root'
        work = root / 'control' / 'work'
        work.mkdir(parents=True)
        (root / 'runtime').mkdir()
        (work / 'mobius.db').write_bytes(b'db')
        (work / 'mobius.db-wal').write_bytes(b'wal')
        owner = {'root': str(root), 'run_id': 'r1', 'provisioning_id': 'p1', 'workflow_context': 'ctx'}
        res = fe.export(root, tmp_path / 'out', owner=owner, absence_checker=lambda *a, **k: None)
        assert any(e.get('class') == 'DatabaseSidecarsUnresolved' for e in res['errors'])
        assert res['complete'] is False
        assert 'control/mobius.db' not in {r['path'] for r in res['inventory']}
    finally:
        os.umask(old)


def test_control_driver_writes_export_manifest_after_report_before_result():
    text = (ROOT / 'control_driver.py').read_text()
    a = text.index("write(work/'report.md'")
    b = text.index("product_export_manifest.prepare")
    c = text.index("json_write(work/'export-manifest.json'")
    d = text.index("json_write(work/'control-result.json'")
    assert a < b < c < d
    assert 'APPROVED_FOR_EXECUTION' in text and 'APPROVED_FOR_EXECUTION=False' in text.replace(' ', '')


def test_manifest_prepare_against_real_db_and_store(ctx, session, store, future_iso):
    from mobius.adapters.models import EvidenceRow
    from mobius.services.intake import IntakeService
    from conftest import make_apk
    apk = make_apk()
    intake = IntakeService(session, store)
    app, _ = intake.create_application(apk, "o.apk", uploaded_by="u")
    auth = intake.create_authorization(apk_sha256=app.sha256, target_package="com.example", scope_text="Static analysis of the supplied artefact only.", statement="s",
        max_intensity=2, granted_by="u", expires_at=future_iso)
    inv = intake.create_investigation(application_id=app.id, authorization_id=auth.id, objective="Owned fixture export manifest test.", intensity=0, created_by="u")
    data = b'{"evidence": 1}'
    key, size = ctx.store.put(data)
    session.add(EvidenceRow(id='ev_x', investigation_id=inv.id, kind='k', sha256=sha(data), object_key=key,
        byte_size=size, truncated=False, redacted=True, summary='s', produced_by='t', created_at=future_iso))
    report = b'# report'
    rkey, rsize = ctx.store.put(report)
    session.add(EvidenceRow(id='ev_r', investigation_id=inv.id, kind='report', sha256=sha(report), object_key=rkey,
        byte_size=rsize, truncated=False, redacted=True, summary='r', produced_by='t', created_at=future_iso))
    from mobius.adapters.models import PoCRunRow
    session.add(PoCRunRow(id='pcr_C3', investigation_id=inv.id, plan_id='poc_A1', authorization_id=auth.id,
        target_sha256=app.sha256, status='passed', exit_status='0', input_sha256='0' * 64, output_sha256='1' * 64,
        input_json={}, output_json={}, started_at=future_iso, finished_at=future_iso, duration_ms=1, created_at=future_iso))
    session.commit()
    plan = NS(id='poc_A1', investigation_id=inv.id, target_sha256=app.sha256)
    m = pem.prepare(ctx, ready={'run_id': 'r1', 'provisioning_id': 'p1', 'apk_sha256': app.sha256}, plan=plan,
        run={'plan_id': 'poc_A1', 'run_id': 'pcr_C3'}, report_sha256=sha(report))
    assert {o['sha256'] for o in m['objects']} == {sha(data), app.sha256, sha(report)}
    with pytest.raises(ValueError):
        pem.prepare(ctx, ready={'run_id': 'r1', 'provisioning_id': 'p1', 'apk_sha256': app.sha256}, plan=plan,
            run={'plan_id': 'poc_A1', 'run_id': 'pcr_C3'}, report_sha256=sha(b'other report'))
    with pytest.raises(ValueError):
        pem.prepare(ctx, ready={'run_id': 'r1', 'provisioning_id': 'p1', 'apk_sha256': app.sha256},
            plan=NS(id='poc_A1', investigation_id='scn_notit', target_sha256=app.sha256),
            run={'plan_id': 'poc_A1', 'run_id': 'pcr_C3'}, report_sha256=sha(report))
    assert fe.object_rows(m, {'run_id': 'r1', 'provisioning_id': 'p1'})


def test_export_empty_root_is_never_complete(tmp_path, monkeypatch):
    monkeypatch.setattr(fe, 'APPROVED_FOR_EXECUTION', True)
    root = tmp_path / 'root'
    root.mkdir()
    owner = {'root': str(root), 'run_id': 'r1', 'provisioning_id': 'p1', 'workflow_context': 'ctx'}
    res = fe.export(root, tmp_path / 'o', owner=owner, absence_checker=lambda *a, **k: None)
    assert res['complete'] is False and res['diagnostic_partial_export'] is True
    assert any(e['class'] == 'EmptyOrUnreachedRoot' for e in res['errors'])


def _wjson(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def _full_root(tmp_path, status='passed'):
    import sqlite3
    from mobius.services.owned_android_fixture import REQUIRED
    apk, rep, e1, e2 = b'apk', b'report', b'plan-evidence', b'result-evidence'
    root = tmp_path / 'root'
    work = root / 'control' / 'work'
    for name in ('outer-owner-intent.json', 'outer-owner-result.json', 'runtime-root-stage.json'):
        _wjson(root / name, {})
    for role in ('runtime', 'control'):
        for name in ('namespace-setup.json', 'namespace-driver-result.json', 'trusted-final-absence.json'):
            _wjson(root / role / name, {})
    for name in REQUIRED:
        (root / 'runtime/work/evidence').mkdir(parents=True, exist_ok=True)
        (root / 'runtime/work/evidence' / name).write_text('x')
        (root / 'control-in/result').mkdir(parents=True, exist_ok=True)
        (root / 'control-in/result' / name).write_text('x')
    _wjson(root / 'control-in/result/result.json', {})
    snap = root / 'control-in/snapshot'
    snap.mkdir(parents=True)
    (snap / 'owned-fixture.apk').write_bytes(apk)
    (snap / 'public-ca.der').write_bytes(b'ca')
    _wjson(snap / 'build-result.json', {})
    _wjson(snap / 'ready.json', {'run_id': 'r1', 'provisioning_id': 'p1', 'apk_sha256': sha(apk)})
    objs = {sha(x): x for x in (apk, rep, e1, e2)}
    for h, data in objs.items():
        d = work / 'store/apk' / h[:2]
        d.mkdir(parents=True, exist_ok=True)
        (d / (h + '.apk')).write_bytes(data)
    _wjson(work / 'control-privileges.json', {})
    _wjson(work / 'control-result.json', {'status': status, 'run_id': 'pcr_C3', 'plan_id': 'poc_A1', 'report_sha256': sha(rep)})
    _wjson(work / 'execute-response.json', {'body': {'run_id': 'pcr_C3', 'plan_id': 'poc_A1'}})
    _wjson(work / 'setup/approved-plan.json', {'id': 'poc_A1', 'investigation_id': 'scn_B2', 'target_sha256': sha(apk)})
    _wjson(work / 'setup/fixture-provenance.json', {})
    (work / 'report.md').write_bytes(rep)
    _wjson(work / 'api-readback.json', {'evidence': [
        {'evidence_id': 'ev1', 'sha256': sha(e1), 'bytes': len(e1)}, {'evidence_id': 'ev2', 'sha256': sha(e2), 'bytes': len(e2)}]})
    _wjson(work / 'export-manifest.json', {'version': 'owned-product-export/1', 'infrastructure_run_id': 'r1', 'provisioning_id': 'p1',
        'investigation_id': 'scn_B2', 'product_run_id': 'pcr_C3', 'plan_id': 'poc_A1', 'apk_sha256': sha(apk), 'report_sha256': sha(rep),
        'objects': [{'sha256': h, 'bytes': len(d)} for h, d in sorted(objs.items())]})
    db = sqlite3.connect(work / 'mobius.db')
    db.execute('create table poc_runs(id text, investigation_id text, plan_id text)')
    db.execute('create table evidence(id text, investigation_id text, sha256 text, byte_size int, object_key text)')
    db.execute('create table reports(investigation_id text, content_sha256 text, object_key text)')
    db.execute('create table poc_run_evidence(investigation_id text, run_id text, evidence_id text)')
    db.execute("insert into poc_runs values('pcr_C3','scn_B2','poc_A1')")
    for eid, data in (('ev1', e1), ('ev2', e2), ('ev_report', rep)):
        db.execute('insert into evidence values(?,?,?,?,?)', (eid, 'scn_B2', sha(data), len(data), 'apk/%s/%s.apk' % (sha(data)[:2], sha(data))))
    for eid in ('ev1', 'ev2'):
        db.execute('insert into poc_run_evidence values(?,?,?)', ('scn_B2', 'pcr_C3', eid))
    db.commit()
    db.close()
    owner = {'root': str(root), 'run_id': 'r1', 'provisioning_id': 'p1', 'workflow_context': 'ctx'}
    return root, work, owner


def _export(tmp_path, root, owner, monkeypatch):
    monkeypatch.setattr(fe, 'APPROVED_FOR_EXECUTION', True)
    old = os.umask(0o077)
    try:
        return fe.export(root, tmp_path / 'out', owner=owner, absence_checker=lambda *a, **k: None)
    finally:
        os.umask(old)


def test_export_complete_happy_path(tmp_path, monkeypatch):
    root, work, owner = _full_root(tmp_path)
    res = _export(tmp_path, root, owner, monkeypatch)
    assert res['errors'] == [] and res['complete'] is True and res['diagnostic_partial_export'] is False
    paths = {r['path'] for r in res['inventory']}
    assert 'control/mobius.db' in paths and 'control/report.md' in paths
    assert len([p for p in paths if p.startswith('product-store/')]) == 4


def test_export_failed_run_does_not_require_success_only_files(tmp_path, monkeypatch):
    root, work, owner = _full_root(tmp_path, status='failed')
    (work / 'report.md').unlink()
    (work / 'export-manifest.json').unlink()
    for f in (root / 'control-in/result').iterdir():
        if f.name != 'result.json':
            f.unlink()
    res = _export(tmp_path, root, owner, monkeypatch)
    assert not any(e['class'] == 'RequiredOriginalMissing' for e in res['errors'])
    assert res['original_status_not_upgraded'] is True


@pytest.mark.parametrize('mutate', ['report_bytes', 'db_run_case', 'missing_object', 'extra_manifest_object', 'readback_link',
                                    'db_evidence_missing_from_manifest', 'wrong_ready', 'apk_swap'])
def test_export_mismatches_fail_closed(tmp_path, monkeypatch, mutate):
    root, work, owner = _full_root(tmp_path)
    import sqlite3
    man = json.loads((work / 'export-manifest.json').read_text())
    if mutate == 'report_bytes':
        (work / 'report.md').write_bytes(b'changed')
    elif mutate == 'db_run_case':
        db = sqlite3.connect(work / 'mobius.db'); db.execute("update poc_runs set investigation_id='scn_X'"); db.commit(); db.close()
    elif mutate == 'missing_object':
        h = man['objects'][0]['sha256']
        (work / 'store/apk' / h[:2] / (h + '.apk')).unlink()
    elif mutate == 'extra_manifest_object':
        man['objects'].append({'sha256': 'f' * 64, 'bytes': 1}); _wjson(work / 'export-manifest.json', man)
    elif mutate == 'readback_link':
        rb = json.loads((work / 'api-readback.json').read_text()); rb['evidence'].pop(); _wjson(work / 'api-readback.json', rb)
    elif mutate == 'db_evidence_missing_from_manifest':
        man['objects'] = [o for o in man['objects'] if o['sha256'] != sha(b'result-evidence')]; _wjson(work / 'export-manifest.json', man)
    elif mutate == 'wrong_ready':
        _wjson(root / 'control-in/snapshot/ready.json', {'run_id': 'r1', 'provisioning_id': 'other', 'apk_sha256': sha(b'apk')})
    elif mutate == 'apk_swap':
        (root / 'control-in/snapshot/owned-fixture.apk').write_bytes(b'other')
    res = _export(tmp_path, root, owner, monkeypatch)
    assert res['complete'] is False and res['errors'], mutate


def test_export_reached_stage_missing_originals_are_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(fe, 'APPROVED_FOR_EXECUTION', True)
    root = tmp_path / 'root'
    (root / 'control' / 'work').mkdir(parents=True)
    (root / 'runtime').mkdir()
    (root / 'runtime' / 'namespace-setup.json').write_text('{}')
    owner = {'root': str(root), 'run_id': 'r1', 'provisioning_id': 'p1', 'workflow_context': 'ctx'}
    res = fe.export(root, tmp_path / 'o', owner=owner, absence_checker=lambda *a, **k: None)
    missing = {e.get('path') for e in res['errors'] if e['class'] == 'RequiredOriginalMissing'}
    assert 'root/outer-owner-result.json' in missing and 'control/control-result.json' in missing
    assert 'runtime/namespace-driver-result.json' in missing and 'public-snapshot/ready.json' in missing
    assert res['complete'] is False


def _wd():
    sys.path.insert(0, str(ROOT))
    return importlib.import_module('staging_watchdog')


PY = sys.executable


@pytest.fixture()
def wd(monkeypatch):
    mod = _wd()
    monkeypatch.setattr(mod, 'APPROVED_FOR_EXECUTION', True)
    monkeypatch.setattr(mod, 'POLL', 0.05)
    return mod


def _env(tmp_path):
    root = tmp_path / 'role'
    root.mkdir()
    rec = tmp_path / 'rec'
    rec.mkdir(mode=0o700)
    return root, rec, tmp_path / 'report.json'


def test_watchdog_is_held_by_default(tmp_path):
    mod = _wd()
    assert mod.APPROVED_FOR_EXECUTION is False
    with pytest.raises(RuntimeError):
        mod.supervise(['true'], tmp_path / 'r')
    with pytest.raises(RuntimeError):
        mod.recover(tmp_path, 'x')
    with pytest.raises(SystemExit):
        mod.main()


def test_watchdog_kills_hung_child_and_grandchild_and_verifies_group_absence(wd, tmp_path):
    root, rec, report = _env(tmp_path)
    code = 'import subprocess,time;subprocess.Popen(["sleep","60"]);time.sleep(60)'
    r = wd.supervise([PY, '-c', code], report, roots=[root], record_dir=rec, wall=0.5, attempt='a1')
    assert r['killed_reason'] == 'wall_clock' and r['complete'] is False and r['group_members_remaining'] == []
    names = sorted(p.name for p in rec.iterdir())
    assert names == ['stage-watchdog-intent-a1.json', 'stage-watchdog-progress-a1.json', 'stage-watchdog-result-a1.json']


def test_watchdog_oversize_growth_killed_and_root_quarantined(wd, tmp_path):
    root, rec, report = _env(tmp_path)
    code = 'import time,sys;open(sys.argv[1]+"/big","wb").write(b"x"*5000);time.sleep(60)'
    r = wd.supervise([PY, '-c', code, str(root)], report, roots=[root], record_dir=rec, wall=20, max_bytes=1000, attempt='a2')
    assert r['killed_reason'].startswith('output_scan') and r['complete'] is False
    assert r['root_dispositions'][0]['state'] == 'quarantined' and (tmp_path / 'role.failed-a2' / 'big').exists()


def test_watchdog_fast_exit0_cannot_bypass_final_scan_or_completion(wd, tmp_path):
    root, rec, report = _env(tmp_path)
    code = 'import sys;open(sys.argv[1]+"/big","wb").write(b"x"*5000)'
    r = wd.supervise([PY, '-c', code, str(root)], report, roots=[root], record_dir=rec, max_bytes=1000, attempt='a3')
    assert r['exit_code'] == 0 and r['complete'] is False and r['final_scan_error'] and r['root_dispositions'][0]['state'] == 'quarantined'


def test_watchdog_exit0_without_lock_or_report_is_not_complete(wd, tmp_path):
    root, rec, report = _env(tmp_path)
    r = wd.supervise([PY, '-c', 'pass'], report, roots=[root], record_dir=rec, attempt='a4')
    assert r['exit_code'] == 0 and r['complete'] is False
    assert r['closure_locks_present'] == {str(root): False} and r['report_file_present'] is False


def test_watchdog_complete_requires_exit0_lock_report_and_clean_scan(wd, tmp_path):
    root, rec, report = _env(tmp_path)
    code = 'import sys;open(sys.argv[1]+"/closure-lock.json","w").write("{}");open(sys.argv[2],"w").write("{}")'
    r = wd.supervise([PY, '-c', code, str(root), str(report)], report, roots=[root], record_dir=rec, attempt='a5')
    assert r['complete'] is True and r['root_dispositions'] == [] and r['final_scan']['files'] == 1 and root.exists()


def test_watchdog_cancellation_goes_through_same_kill_path(wd, tmp_path):
    from threading import Event, Timer
    root, rec, report = _env(tmp_path)
    cancel = Event()
    Timer(0.3, cancel.set).start()
    r = wd.supervise([PY, '-c', 'import time;time.sleep(60)'], report, roots=[root], record_dir=rec, cancel=cancel, attempt='a6')
    assert r['killed_reason'] == 'cancelled' and r['complete'] is False


def test_watchdog_parent_death_kills_child_via_pdeathsig(tmp_path):
    import subprocess as sp
    import time
    pidfile = tmp_path / 'child.pid'
    (tmp_path / 'sleeper.py').write_text("import os,time,sys\nopen(sys.argv[1],'w').write(str(os.getpid()))\ntime.sleep(60)\n")
    (tmp_path / 'parent.py').write_text(
        "import sys\nsys.path.insert(0,%r)\nimport staging_watchdog as w\nw.APPROVED_FOR_EXECUTION=True\n"
        "w.supervise([sys.executable,%r,%r],%r,roots=[],wall=60)\n"
        % (str(ROOT), str(tmp_path / 'sleeper.py'), str(pidfile), str(tmp_path / 'r.json')))
    p = sp.Popen([PY, str(tmp_path / 'parent.py')])
    for _ in range(100):
        if pidfile.exists() and pidfile.read_text():
            break
        time.sleep(0.05)
    child = int(pidfile.read_text())
    p.kill(); p.wait()
    for _ in range(100):
        if not (Path('/proc/%d' % child).exists() and wd_state(child) != 'Z'):
            break
        time.sleep(0.05)
    assert not Path('/proc/%d' % child).exists() or wd_state(child) == 'Z'


def wd_state(pid):
    try:
        return Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()[0]
    except FileNotFoundError:
        return 'Z'


def test_watchdog_recover_is_identity_bound_unique_and_preserves_originals(wd, tmp_path):
    import subprocess as sp
    root, rec, report = _env(tmp_path)
    (root / 'partial').write_text('x')
    child = sp.Popen([PY, '-c', 'import time;time.sleep(60)'], preexec_fn=os.setsid)
    ident = wd.process_identity(child.pid)
    (rec / 'stage-watchdog-intent-r1.json').write_text(json.dumps({'roots': [str(root)]}))
    (rec / 'stage-watchdog-progress-r1.json').write_text(json.dumps({'child_identity': ident, 'pgid': child.pid}))
    first = wd.recover(rec, 'r1')
    child.wait(timeout=5)
    assert first['child'] == 'identity_matched_group_killed' and first['group_members_remaining'] == []
    assert first['root_dispositions'][0]['state'] == 'quarantined'
    # reuse/stale: identity no longer live -> no signal; second recovery makes a distinct record
    (root.parent / 'role2').mkdir()
    (rec / 'stage-watchdog-intent-r2.json').write_text(json.dumps({'roots': [str(root.parent / 'role2')]}))
    (rec / 'stage-watchdog-progress-r2.json').write_text(json.dumps({'child_identity': ident, 'pgid': child.pid}))
    second = wd.recover(rec, 'r2')
    assert second['child'] == 'recorded_identity_not_live_no_signal'
    recs = sorted(p.name for p in rec.iterdir() if 'recovery' in p.name)
    assert len(recs) == 2 and (rec / 'stage-watchdog-intent-r1.json').exists()
    # an original result means no action
    (rec / 'stage-watchdog-result-r1.json').write_text('{}')
    assert wd.recover(rec, 'r1')['state'] == 'original_result_present_no_action'


def test_scan_counts_dirs_refuses_links_and_special_files(wd, tmp_path):
    for n in range(4):
        (tmp_path / ('d%d' % n)).mkdir()
    with pytest.raises(ValueError):
        wd.scan_roots([tmp_path], max_dirs=3)
    os.symlink('/etc', tmp_path / 'l')
    with pytest.raises(ValueError):
        wd.scan_roots([tmp_path])
    os.unlink(tmp_path / 'l')
    os.mkfifo(tmp_path / 'fifo')
    with pytest.raises(ValueError):
        wd.scan_roots([tmp_path])
    os.unlink(tmp_path / 'fifo')
    (tmp_path / 'a').write_text('1')
    (tmp_path / 'b').write_text('1')
    with pytest.raises(ValueError):
        wd.scan_roots([tmp_path], max_files=1)
    with pytest.raises(TimeoutError):
        wd.scan_roots([tmp_path], deadline=-1.0, clock=lambda: 0.0)
    assert wd.scan_roots([tmp_path / 'missing'])['absent_roots']


def test_watchdog_quarantines_partial_roots_only(tmp_path):
    wd = _wd()
    partial = tmp_path / 'runtime'
    (partial / 'sub').mkdir(parents=True)
    (partial / 'sub' / 'f').write_text('x')
    done = tmp_path / 'control'
    done.mkdir()
    (done / 'closure-lock.json').write_text('{}')
    link = tmp_path / 'link'
    os.symlink(partial, link)
    res = wd.quarantine_partial([partial, done, tmp_path / 'absent', link], 'aa')
    states = {Path(r['root']).name: r['state'] for r in res}
    assert states == {'runtime': 'quarantined', 'control': 'complete_lock_present_not_moved', 'absent': 'absent',
                      'link': 'refused_not_owned_directory'}
    assert (tmp_path / 'runtime.failed-aa' / 'sub' / 'f').read_text() == 'x' and not partial.exists()
    again = tmp_path / 'runtime'
    again.mkdir()
    assert wd.quarantine_partial([again], 'aa')[0]['state'] == 'refused_target_exists' and again.exists()
