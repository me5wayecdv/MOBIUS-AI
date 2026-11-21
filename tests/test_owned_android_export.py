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
    _wjson(root / 'control-in/result/result.json', {'status': status})
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
    _wjson(work / 'execute-response.json', {'body': {'run_id': 'pcr_C3', 'plan_id': 'poc_A1', 'status': status, 'evidence_ids': ['ev1', 'ev2']}})
    _wjson(work / 'setup/approved-plan.json', {'id': 'poc_A1', 'investigation_id': 'scn_B2', 'target_sha256': sha(apk)})
    _wjson(work / 'setup/fixture-provenance.json', {})
    (work / 'report.md').write_bytes(rep)
    _wjson(work / 'api-readback.json', {'run_id': 'pcr_C3', 'plan_id': 'poc_A1', 'investigation_id': 'scn_B2', 'status': status, 'evidence': [
        {'evidence_id': 'ev1', 'sha256': sha(e1), 'bytes': len(e1)}, {'evidence_id': 'ev2', 'sha256': sha(e2), 'bytes': len(e2)}]})
    _wjson(work / 'export-manifest.json', {'version': 'owned-product-export/1', 'infrastructure_run_id': 'r1', 'provisioning_id': 'p1',
        'investigation_id': 'scn_B2', 'product_run_id': 'pcr_C3', 'plan_id': 'poc_A1', 'apk_sha256': sha(apk), 'report_sha256': sha(rep),
        'objects': [{'sha256': h, 'bytes': len(d)} for h, d in sorted(objs.items())]})
    db = sqlite3.connect(work / 'mobius.db')
    db.execute('create table poc_runs(id text, investigation_id text, plan_id text, status text)')
    db.execute('create table evidence(id text, investigation_id text, sha256 text, byte_size int, object_key text)')
    db.execute('create table reports(investigation_id text, content_sha256 text, object_key text)')
    db.execute('create table poc_run_evidence(investigation_id text, run_id text, evidence_id text)')
    db.execute("insert into poc_runs values('pcr_C3','scn_B2','poc_A1',?)", (status,))
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
    assert res['complete_product_evidence'] is True and res['published_status'] == 'passed'
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
    assert res['complete_diagnostic_export'] is True and res['complete_product_evidence'] is False


@pytest.mark.parametrize('mutate', ['report_bytes', 'db_run_case', 'status_pub_passed_control_failed', 'status_control_missing', 'status_db_failed', 'status_pub_unknown', 'status_pub_failed_control_passed', 'status_readback_identity', 'status_execute_failed', 'status_pub_bogus', 'status_control_bogus', 'status_failed_path_execute_passed', 'status_failed_path_db_passed', 'missing_object', 'extra_manifest_object', 'readback_link',
                                    'db_evidence_missing_from_manifest', 'wrong_ready', 'apk_swap'])
def test_export_mismatches_fail_closed(tmp_path, monkeypatch, mutate):
    root, work, owner = _full_root(tmp_path)
    import sqlite3
    man = json.loads((work / 'export-manifest.json').read_text())
    if mutate == 'report_bytes':
        (work / 'report.md').write_bytes(b'changed')
    elif mutate == 'db_run_case':
        db = sqlite3.connect(work / 'mobius.db'); db.execute("update poc_runs set investigation_id='scn_X'"); db.commit(); db.close()
    elif mutate == 'status_pub_passed_control_failed':
        cr = json.loads((work / 'control-result.json').read_text()); cr['status'] = 'failed'; _wjson(work / 'control-result.json', cr)
    elif mutate == 'status_control_missing':
        cr = json.loads((work / 'control-result.json').read_text()); cr.pop('status'); _wjson(work / 'control-result.json', cr)
    elif mutate == 'status_db_failed':
        db = sqlite3.connect(work / 'mobius.db'); db.execute("update poc_runs set status='failed'"); db.commit(); db.close()
    elif mutate == 'status_pub_unknown':
        _wjson(root / 'control-in/result/result.json', {})
    elif mutate == 'status_pub_failed_control_passed':
        _wjson(root / 'control-in/result/result.json', {'status': 'failed'})
    elif mutate == 'status_readback_identity':
        rb = json.loads((work / 'api-readback.json').read_text()); rb['investigation_id'] = 'scn_other'; _wjson(work / 'api-readback.json', rb)
    elif mutate == 'status_execute_failed':
        ex = json.loads((work / 'execute-response.json').read_text()); ex['body']['status'] = 'failed'; _wjson(work / 'execute-response.json', ex)
    elif mutate == 'status_pub_bogus':
        _wjson(root / 'control-in/result/result.json', {'status': 'bogus'})
    elif mutate == 'status_control_bogus':
        _wjson(root / 'control-in/result/result.json', {'status': 'failed'})
        cr = json.loads((work / 'control-result.json').read_text()); cr['status'] = 'weird'; _wjson(work / 'control-result.json', cr)
    elif mutate == 'status_failed_path_execute_passed':
        _wjson(root / 'control-in/result/result.json', {'status': 'failed'})
        cr = json.loads((work / 'control-result.json').read_text()); cr['status'] = 'failed'; _wjson(work / 'control-result.json', cr)
    elif mutate == 'status_failed_path_db_passed':
        _wjson(root / 'control-in/result/result.json', {'status': 'timed_out'})
        cr = json.loads((work / 'control-result.json').read_text()); cr['status'] = 'timed_out'; _wjson(work / 'control-result.json', cr)
        ex = json.loads((work / 'execute-response.json').read_text()); ex['body']['status'] = 'timed_out'; _wjson(work / 'execute-response.json', ex)
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
    assert res['complete'] is False and res['errors'] and res['complete_product_evidence'] is False, mutate


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


def _lockset(tmp_path):
    """Production-shaped reviewed lock (validate_manifest + stage_role row schema) and per-role file payloads."""
    import hashlib
    import sys as _sys
    _sys.path.insert(0, str(ROOT))
    import namespace_supervisor as nsup
    files = {}
    lock = {'status': 'EXACT_REVIEWED_SIBLING_STAGE_LOCK', 'sdk_license_reviewed': True,
            'archives': [{'name': 'a.zip', 'bytes': 10, 'sha256': '0' * 64}], 'roles': {}}
    for role in ('runtime', 'control'):
        dests = [nsup.ROLES[role][1], '/runtime/bin/python', '/usr/bin/setpriv']
        rows, payload = [], []
        for dest in dests:
            data = (role + dest).encode()
            rel = dest.lstrip('/')
            rows.append({'destination': dest, 'source': rel, 'archive': 'a.zip', 'member': 'm/' + rel, 'size': len(data),
                         'sha256': hashlib.sha256(data).hexdigest(), 'mode': 0o444})
            payload.append((data, rel))
        files[role] = payload
        lock['roles'][role] = {'status': 'EXACT_REVIEWED_ANDROID_CLOSURE', 'files': rows}
    roots = {r: tmp_path / (r + '_closure') for r in files}
    lock_bytes = json.dumps(lock).encode()
    rec = tmp_path / 'rec'
    rec.mkdir(mode=0o700)
    report = tmp_path / 'report.json'
    return files, roots, lock, lock_bytes, hashlib.sha256(lock_bytes).hexdigest(), rec, report


STAGER_SRC = r'''
import hashlib, json, os, sys
mode = sys.argv[1]
spec = json.load(open(sys.argv[2]))
if mode == 'sleep':
    import time
    time.sleep(60)
if mode == 'hang':
    import subprocess, time
    subprocess.Popen(['sleep', '60'])
    time.sleep(60)
for role, rows in spec['roles'].items():
    root = spec['roots'][role]
    for row in rows:
        rel = row['rel']
        os.makedirs(os.path.join(root, os.path.dirname(rel)), exist_ok=True)
        data = bytes.fromhex(row['hex'])
        if mode == 'wrong_digest':
            data = b'X' * len(data)
        with open(os.path.join(root, rel), 'wb') as f:
            f.write(data)
        os.chmod(os.path.join(root, rel), 0o444)
    manifest = spec['lock']['roles'][role]
    with open(os.path.join(root, 'closure-lock.json'), 'w') as f:
        json.dump({'files': []} if mode == 'invalid_lock' else manifest, f)
    if mode == 'extra_file':
        open(os.path.join(root, 'extra'), 'w').write('x')
    if mode == 'grow':
        open(os.path.join(root, 'big'), 'wb').write(b'x' * 5000)
        import time; time.sleep(60)
if mode == 'exit_no_report':
    sys.exit(0)
results = [{'role': r, 'root': spec['roots'][r], 'file_count': len(spec['lock']['roles'][r]['files']), 'closure_sha256': hashlib.sha256(json.dumps(spec['lock']['roles'][r], sort_keys=True, separators=(',', ':')).encode()).hexdigest()} for r in spec['roots']]
json.dump({'results': results, 'no_code_executed': True}, open(spec['report'], 'w'))
'''


def _run(wd, tmp_path, mode, attempt, **kw):
    files, roots, lock, lock_bytes, lock_sha, rec, report = _lockset(tmp_path)
    spec = {'roots': {r: str(p) for r, p in roots.items()}, 'report': str(report), 'lock': lock,
            'roles': {r: [{'rel': rel, 'hex': b.hex()} for b, rel in rows] for r, rows in files.items()}}
    (tmp_path / 'spec.json').write_text(json.dumps(spec))
    (tmp_path / 'stager.py').write_text(STAGER_SRC)
    args = dict(role_roots=roots, lock_bytes=lock_bytes, expected_lock_sha256=lock_sha, record_dir=rec, attempt=attempt)
    args.update(kw)
    return wd.supervise([PY, str(tmp_path / 'stager.py'), mode, str(tmp_path / 'spec.json')], report, **args), roots, rec, report


def test_watchdog_is_held_by_default(tmp_path):
    mod = _wd()
    assert mod.APPROVED_FOR_EXECUTION is False
    with pytest.raises(RuntimeError):
        mod.supervise(['true'], tmp_path / 'r', role_roots={}, lock_bytes=b'', expected_lock_sha256='', record_dir=tmp_path)
    with pytest.raises(RuntimeError):
        mod.recover(tmp_path, 'x')
    with pytest.raises(SystemExit):
        mod.main()


def test_watchdog_complete_only_with_exact_reviewed_content(wd, tmp_path):
    r, roots, rec, report = _run(wd, tmp_path, 'ok', 'a1')
    assert r['complete'] is True and r['absence_verified'] and r['root_dispositions'] == []
    assert sorted(p.name for p in rec.iterdir()) == ['stage-watchdog-intent-a1.json', 'stage-watchdog-progress-a1.json', 'stage-watchdog-result-a1.json']


@pytest.mark.parametrize('mode', ['wrong_digest', 'invalid_lock', 'extra_file', 'exit_no_report'])
def test_watchdog_exit0_with_wrong_content_is_quarantined_after_absence(wd, tmp_path, mode):
    r, roots, rec, report = _run(wd, tmp_path, mode, 'b1')
    assert r['exit_code'] == 0 and r['complete'] is False and r['absence_verified'] is True
    assert r['final_validation_error']
    assert all(d['state'] == 'quarantined' for d in r['root_dispositions']) and not any(p.exists() for p in roots.values())


def test_watchdog_kills_hung_child_and_grandchild_with_verified_absence(wd, tmp_path):
    r, roots, rec, report = _run(wd, tmp_path, 'hang', 'c1', wall=0.5)
    assert r['killed_reason'] == 'wall_clock' and r['complete'] is False and r['absence_verified'] and r['session_members_remaining'] == []


def test_watchdog_growth_killed(wd, tmp_path):
    r, roots, rec, report = _run(wd, tmp_path, 'grow', 'c2', wall=20, max_bytes=1000)
    assert r['killed_reason'].startswith('output_scan') and r['complete'] is False and r['absence_verified']


def test_watchdog_refuses_wrong_lock_identity_and_preexisting_outputs(wd, tmp_path):
    files, roots, lock, lock_bytes, lock_sha, rec, report = _lockset(tmp_path)
    with pytest.raises(ValueError):
        wd.supervise(['true'], report, role_roots=roots, lock_bytes=lock_bytes, expected_lock_sha256='0' * 64, record_dir=rec)
    next(iter(roots.values())).mkdir()
    with pytest.raises(ValueError):
        wd.supervise(['true'], report, role_roots=roots, lock_bytes=lock_bytes, expected_lock_sha256=lock_sha, record_dir=rec)
    assert next(iter(roots.values())).exists() and not list(rec.iterdir())  # not adopted, not quarantined, no effect
    next(iter(roots.values())).rmdir()
    report.write_text('{}')
    with pytest.raises(ValueError):
        wd.supervise(['true'], report, role_roots=roots, lock_bytes=lock_bytes, expected_lock_sha256=lock_sha, record_dir=rec)


def test_watchdog_post_popen_setup_failure_is_stopped_and_recorded(wd, tmp_path, monkeypatch):
    def boom(pid):
        raise OSError('pidfd failed')
    monkeypatch.setattr(wd.os, 'pidfd_open', boom)
    r, roots, rec, report = _run(wd, tmp_path, 'sleep', 'd1')
    assert r['setup_error'].startswith('OSError') and r['complete'] is False and r['absence_verified'] is True
    assert any(p.name == 'stage-watchdog-result-d1.json' for p in rec.iterdir())


def test_watchdog_final_validation_is_deadline_bounded(wd, tmp_path):
    r, roots, rec, report = _run(wd, tmp_path, 'ok', 'e1', final_seconds=-1)
    assert r['complete'] is False and 'Timeout' in r['final_validation_error']


def test_watchdog_cancellation_goes_through_same_kill_path(wd, tmp_path):
    from threading import Event, Timer
    cancel = Event()
    Timer(0.3, cancel.set).start()
    r, roots, rec, report = _run(wd, tmp_path, 'hang', 'f1', cancel=cancel)
    assert r['killed_reason'] == 'cancelled' and r['absence_verified']


def test_watchdog_parent_death_kills_child_via_pdeathsig(tmp_path):
    import subprocess as sp
    import time
    pidfile = tmp_path / 'child.pid'
    files, roots, lock, lock_bytes, lock_sha, rec, report = _lockset(tmp_path)
    (tmp_path / 'sleeper.py').write_text("import os,time,sys\nopen(sys.argv[1],'w').write(str(os.getpid()))\ntime.sleep(60)\n")
    (tmp_path / 'lock.bin').write_bytes(lock_bytes)
    (tmp_path / 'parent.py').write_text(
        "import sys\nsys.path.insert(0,%r)\nimport staging_watchdog as w\nw.APPROVED_FOR_EXECUTION=True\n"
        "w.supervise([sys.executable,%r,%r],%r,role_roots={'runtime':%r,'control':%r},lock_bytes=open(%r,'rb').read(),expected_lock_sha256=%r,record_dir=%r,wall=60)\n"
        % (str(ROOT), str(tmp_path / 'sleeper.py'), str(pidfile), str(report), str(roots['runtime']), str(roots['control']), str(tmp_path / 'lock.bin'), lock_sha, str(rec)))
    p = sp.Popen([PY, str(tmp_path / 'parent.py')])
    for _ in range(100):
        if pidfile.exists() and pidfile.read_text():
            break
        time.sleep(0.05)
    child = int(pidfile.read_text())
    p.kill(); p.wait()
    for _ in range(100):
        if wd_state(child) == 'Z':
            break
        time.sleep(0.05)
    assert wd_state(child) == 'Z'


def wd_state(pid):
    try:
        return Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()[0]
    except FileNotFoundError:
        return 'Z'


def test_watchdog_recover_stable_pidfd_unique_and_no_mutation_when_unverified(wd, tmp_path):
    import subprocess as sp
    rec = tmp_path / 'rec'
    rec.mkdir(mode=0o700)
    root = tmp_path / 'role'
    root.mkdir()
    (root / 'partial').write_text('x')
    child = sp.Popen([PY, '-c', 'import time;time.sleep(60)'], preexec_fn=os.setsid)
    ident = wd.process_identity(child.pid)
    (rec / 'stage-watchdog-intent-r1.json').write_text(json.dumps({'roots': {'runtime': str(root)}}))
    (rec / 'stage-watchdog-progress-r1.json').write_text(json.dumps({'child_identity': ident, 'sid': ident['sid']}))
    first = wd.recover(rec, 'r1')
    assert child.poll() is None  # recovery never signals, even the authentic recorded leader
    child.kill(); child.wait(timeout=5)
    assert first['state'] == 'UNVERIFIED_no_persistent_containment_handle' and first['signals_sent'] == 0
    assert first['root_dispositions'][0]['state'] == 'UNVERIFIED_ABSENCE_NO_ROOT_MUTATION' and root.exists() and (root / 'partial').exists()
    # no progress record: UNVERIFIED and NO root mutation
    root2 = tmp_path / 'role2'
    root2.mkdir()
    (rec / 'stage-watchdog-intent-r2.json').write_text(json.dumps({'roots': {'runtime': str(root2)}}))
    second = wd.recover(rec, 'r2')
    assert second['state'] == 'UNVERIFIED_no_progress_record' and root2.exists()
    assert len([p for p in rec.iterdir() if 'recovery' in p.name]) == 2 and (rec / 'stage-watchdog-intent-r1.json').exists()
    (rec / 'stage-watchdog-result-r1.json').write_text('{}')
    assert wd.recover(rec, 'r1')['state'] == 'original_result_present_no_action'


def test_scan_counts_dirs_refuses_links_special_and_ancestor_symlinks(wd, tmp_path):
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
    real = tmp_path / 'real'
    real.mkdir()
    os.symlink(real, tmp_path / 'viasym')
    with pytest.raises(OSError):  # an ancestor component that is a symlink is refused, not followed
        wd.open_dir(tmp_path / 'viasym')


def test_watchdog_quarantine_is_anchored_and_never_overwrites(tmp_path):
    wd = _wd()
    partial = tmp_path / 'runtime'
    (partial / 'sub').mkdir(parents=True)
    (partial / 'sub' / 'f').write_text('x')
    link = tmp_path / 'link'
    os.symlink(partial, link)
    res = wd.quarantine_partial([partial, tmp_path / 'absent', link], 'aa')
    states = {Path(r['root']).name: r['state'] for r in res}
    assert states == {'runtime': 'quarantined', 'absent': 'absent', 'link': 'refused_not_owned_directory'}
    assert (tmp_path / 'runtime.failed-aa' / 'sub' / 'f').read_text() == 'x' and not partial.exists()
    again = tmp_path / 'runtime'
    again.mkdir()
    assert wd.quarantine_partial([again], 'aa')[0]['state'] == 'refused_target_exists' and again.exists()
    other = tmp_path / 'viasym2'
    os.symlink(tmp_path, other)
    assert wd.quarantine_partial([other / 'runtime'], 'bb')[0]['state'].startswith('refused_parent')


def _userns_ok():
    import subprocess as sp
    try:
        return sp.run(['unshare', '--user', '--map-root-user', '--pid', '--fork', '--kill-child', '--', 'true'],
                      capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


@pytest.mark.skipif(not _userns_ok(), reason='unprivileged user+PID namespaces unavailable')
def test_pid_namespace_kills_setsid_escapee_that_session_scan_alone_misses(wd, tmp_path):
    import time
    files, roots, lock, lock_bytes, lock_sha, rec, report = _lockset(tmp_path)
    esc = tmp_path / 'escapee.pid'
    (tmp_path / 'escapee.py').write_text("import os,sys,time\nos.setsid()\nopen(sys.argv[1],'w').write(str(os.getpid()))\ntime.sleep(60)\n")
    (tmp_path / 'stager.py').write_text(
        "import subprocess,sys,time\nsubprocess.Popen([sys.executable,%r,%r])\ntime.sleep(60)\n"
        % (str(tmp_path / 'escapee.py'), str(esc)))
    import threading
    from threading import Event
    cancel = Event()
    seen = {}

    def witness():
        # witnessed start: only cancel once the escapee has written its marker AND the recorded namespace has >=2 live members
        for _ in range(400):
            prog = rec / 'stage-watchdog-progress-ns1.json'
            if esc.exists() and prog.exists():
                di = json.loads(prog.read_text()).get('pid_namespace_dev_ino')
                if di and len(wd.ns_members(di, True)) >= 2:
                    seen['link'], seen['count'] = di, len(wd.ns_members(di, True))
                    cancel.set()
                    return
            time.sleep(0.05)
        cancel.set()
    t = threading.Thread(target=witness)
    t.start()
    r = wd.supervise([PY, str(tmp_path / 'stager.py')], report, role_roots=roots, lock_bytes=lock_bytes,
                     expected_lock_sha256=lock_sha, record_dir=rec, attempt='ns1', cancel=cancel,
                     pid_namespace=True, user_namespace=True)
    t.join()
    assert seen.get('count', 0) >= 2, 'start not witnessed: escapee never ran inside the recorded namespace'
    assert r['pid_namespace_containment'] is True and r['killed_reason'] == 'cancelled' and r['absence_verified']
    assert r['pid_namespace_identity'].startswith('pid:[')
    prog = json.loads((rec / 'stage-watchdog-progress-ns1.json').read_text())
    assert prog['absence_obligation'] == 'session_and_namespace' and prog['pid_namespace_dev_ino'] == list(seen['link'])
    # exact owned identity: no process anywhere still carries the recorded namespace link
    assert wd.ns_members(seen['link'], True) == []


def _cmdline(pid):
    try:
        return Path('/proc/%d/cmdline' % pid).read_bytes()
    except OSError:
        return b''


def test_without_namespace_a_setsid_escapee_survives_documenting_the_limit(wd, tmp_path):
    import signal as sg
    import time
    from threading import Event
    import threading
    files, roots, lock, lock_bytes, lock_sha, rec, report = _lockset(tmp_path)
    esc = tmp_path / 'escapee.pid'
    (tmp_path / 'escapee.py').write_text("import os,sys,time\nos.setsid()\nopen(sys.argv[1],'w').write(str(os.getpid()))\ntime.sleep(60)\n")
    (tmp_path / 'stager.py').write_text(
        "import subprocess,sys,time\nsubprocess.Popen([sys.executable,%r,%r])\ntime.sleep(60)\n" % (str(tmp_path / 'escapee.py'), str(esc)))
    cancel = Event()
    threading.Timer(1.0, cancel.set).start()
    r = wd.supervise([PY, str(tmp_path / 'stager.py')], report, role_roots=roots, lock_bytes=lock_bytes,
                     expected_lock_sha256=lock_sha, record_dir=rec, attempt='ns0', cancel=cancel)
    pid = int(esc.read_text())
    try:
        assert r['pid_namespace_containment'] is False
        assert wd_state(pid) != 'Z' and Path('/proc/%d' % pid).exists()  # escaped: session containment alone is insufficient
    finally:
        os.kill(pid, sg.SIGKILL)


def _mut(lock, how):
    import copy
    lk = copy.deepcopy(lock)
    rows = lk['roles']['control']['files']
    if how == 'missing_role':
        del lk['roles']['control']
    elif how == 'unexpected_role':
        lk['roles']['extra'] = lk['roles']['control']
    elif how == 'noncanonical_source':
        rows[0]['source'] = 'a//b'
    elif how == 'dot_source':
        rows[0]['source'] = './x'
    elif how == 'bad_mode':
        rows[0]['mode'] = 0o777
    elif how == 'no_license':
        lk['sdk_license_reviewed'] = False
    elif how == 'missing_required':
        lk['roles']['control']['files'] = [r for r in rows if r['destination'] != '/usr/bin/setpriv']
    elif how == 'unknown_archive':
        rows[0]['archive'] = 'nope.zip'
    elif how == 'dup_source':
        rows[1]['source'] = rows[0]['source']
    elif how == 'bad_status':
        lk['roles']['control']['status'] = 'DRAFT'
    elif how == 'bad_destination':
        rows[0]['destination'] = '/home/x'
    elif how == 'no_archives':
        lk['archives'] = []
    elif how == 'oversize':
        rows[0]['size'] = 5 * 1024 ** 3
    return lk


@pytest.mark.parametrize('how', ['missing_role', 'unexpected_role', 'noncanonical_source', 'dot_source', 'bad_mode', 'no_license',
                                 'missing_required', 'unknown_archive', 'dup_source', 'bad_status', 'bad_destination', 'no_archives', 'oversize'])
def test_prespawn_uses_production_validators_and_rejects_before_any_effect(wd, tmp_path, how):
    import hashlib
    files, roots, lock, lock_bytes, lock_sha, rec, report = _lockset(tmp_path)
    wd.validate_stage_lock(lock, roots)  # the unmutated production-shaped lock passes
    bad = _mut(lock, how)
    bb = json.dumps(bad).encode()
    with pytest.raises((ValueError, KeyError)):
        wd.supervise([PY, '-c', 'pass'], report, role_roots=roots, lock_bytes=bb, expected_lock_sha256=hashlib.sha256(bb).hexdigest(), record_dir=rec)
    assert not list(rec.iterdir()) and not any(r.exists() for r in roots.values())


def test_scan_roots_budgets_are_aggregate_across_roots(wd, tmp_path):
    a, b = tmp_path / 'a', tmp_path / 'b'
    a.mkdir(); b.mkdir()
    for d in (a, b):
        (d / 'f1').write_text('xx'); (d / 'f2').write_text('xx')
    assert wd.scan_roots([a], max_files=3)['files'] == 2
    with pytest.raises(ValueError):
        wd.scan_roots([a, b], max_files=3)
    with pytest.raises(ValueError):
        wd.scan_roots([a, b], max_bytes=6)


def test_recover_refuses_unauthenticated_reused_sid_no_signal_no_mutation(wd, tmp_path):
    import subprocess as sp
    rec = tmp_path / 'rec'; rec.mkdir(mode=0o700)
    root = tmp_path / 'role'; root.mkdir(); (root / 'partial').write_text('x')
    bystander = sp.Popen([PY, '-c', 'import time;time.sleep(30)'], preexec_fn=os.setsid)
    try:
        ident = wd.process_identity(bystander.pid)
        stale = dict(ident, start_ticks=ident['start_ticks'] + 1)  # recorded identity is of a different (dead) leader
        (rec / 'stage-watchdog-intent-r9.json').write_text(json.dumps({'roots': {'runtime': str(root)}}))
        (rec / 'stage-watchdog-progress-r9.json').write_text(json.dumps({'child_identity': stale, 'sid': ident['sid']}))
        res = wd.recover(rec, 'r9')
        assert res['state'].startswith('UNVERIFIED') and root.exists()
        assert bystander.poll() is None  # unrelated session was never signalled
    finally:
        bystander.kill(); bystander.wait()


def _mk_export(tmp_path, ctx='ctx', run='r1'):
    import hashlib
    d = tmp_path / ('d061-owned-export-%s-1' % run)
    (d / 'control').mkdir(parents=True, mode=0o700)
    os.chmod(d, 0o700)
    data = b'{"ok":1}'
    (d / 'control' / 'control-result.json').write_bytes(data)
    summary = {k: None for k in ('version', 'workflow_context', 'infrastructure_run_id', 'complete', 'complete_diagnostic_export',
                                 'complete_product_evidence', 'published_status', 'diagnostic_partial_export', 'errors', 'role_absence',
                                 'inventory', 'total_bytes', 'original_status_not_upgraded', 'private_candidates_exported',
                                 'cooperative_export_budget_seconds', 'not_cryptographic_attestation')}
    summary.update(version='owned-final-export/1', workflow_context=ctx, infrastructure_run_id=run, complete=False,
                   complete_diagnostic_export=False, complete_product_evidence=False, published_status='failed',
                   diagnostic_partial_export=True, errors=[], role_absence={}, total_bytes=len(data),
                   original_status_not_upgraded=True, private_candidates_exported=False, cooperative_export_budget_seconds=30,
                   not_cryptographic_attestation=True,
                   inventory=[{'path': 'control/control-result.json', 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}])
    (d / 'export-summary.json').write_text(json.dumps(summary))
    for f in (d / 'control' / 'control-result.json', d / 'export-summary.json'):
        os.chmod(f, 0o444)
    return d


def _pp():
    import importlib
    import sys as _sys
    if str(ROOT) not in _sys.path:
        _sys.path.insert(0, str(ROOT))
    return importlib.import_module('publication_packer')


def _args(d):
    return dict(expected_dirname=d.name, expected_workflow_context='ctx', expected_run_id='r1')


def test_publication_packer_held_deterministic_readable_under_umask_and_cleans_up(tmp_path, monkeypatch):
    import tarfile
    pp = _pp()
    d = _mk_export(tmp_path)
    out = tmp_path / 'out'
    out.mkdir(mode=0o700)
    with pytest.raises(RuntimeError):
        pp.pack(d, out / 'o.tar', **_args(d))
    monkeypatch.setattr(pp, 'APPROVED_FOR_EXECUTION', True)
    old = os.umask(0o077)
    try:
        a = pp.pack(d, out / 'o1.tar', **_args(d))
    finally:
        os.umask(old)
    b = pp.pack(d, out / 'o2.tar', **_args(d))
    assert a['tar_sha256'] == b['tar_sha256'] == hashlib.sha256((out / 'o1.tar').read_bytes()).hexdigest()
    assert (out / 'o1.tar').stat().st_mode & 0o777 == 0o644  # runner-readable even under umask 077
    assert a['diagnostic_only'] is True and a['product_evidence_export'] is False
    with tarfile.open(out / 'o1.tar') as tf:
        assert all(m.uid == 0 and m.mode == 0o644 and m.mtime == 0 for m in tf.getmembers())
    with pytest.raises(FileExistsError):
        pp.pack(d, out / 'o1.tar', **_args(d))
    assert sorted(p.name for p in out.iterdir()) == ['o1.tar', 'o2.tar']  # no partial left behind


def test_publication_packer_refusals(tmp_path, monkeypatch):
    pp = _pp()
    monkeypatch.setattr(pp, 'APPROVED_FOR_EXECUTION', True)
    out = tmp_path / 'out'
    out.mkdir(mode=0o700)

    def attempt(d, **over):
        kw = _args(d)
        kw.update(over)
        with pytest.raises((ValueError, FileExistsError, OSError)):
            pp.pack(d, out / ('x%d.tar' % len(list(out.iterdir()))), **kw)
        assert not [p for p in out.iterdir() if p.name.endswith('.partial')]
    d = _mk_export(tmp_path)
    attempt(d, expected_run_id='other')
    attempt(d, expected_workflow_context='other')
    attempt(d, expected_dirname='d061-owned-export-zzz-1')
    (d / 'control' / 'extra').write_text('x')
    attempt(d)
    (d / 'control' / 'extra').unlink()
    os.chmod(d / 'control' / 'control-result.json', 0o644)
    (d / 'control' / 'control-result.json').write_bytes(b'{"ok":2}')
    attempt(d)  # tampered vs inventory (same length)
    (d / 'control' / 'control-result.json').write_bytes(b'{"ok":1}')
    os.chmod(d / 'control' / 'control-result.json', 0o444)
    os.chmod(d, 0o755)
    attempt(d)  # export root not private
    os.chmod(d, 0o700)
    os.symlink('/etc/passwd', d / 'control' / 'l')
    attempt(d)
    (d / 'control' / 'l').unlink()
    os.mkfifo(d / 'control' / 'fifo')
    attempt(d)  # FIFO refused by walk, never opened blocking
    (d / 'control' / 'fifo').unlink()


def test_publication_packer_rejects_arbitrary_self_consistent_inventory_and_ancestor_links(tmp_path, monkeypatch):
    pp = _pp()
    monkeypatch.setattr(pp, 'APPROVED_FOR_EXECUTION', True)
    out = tmp_path / 'out'
    out.mkdir(mode=0o700)
    d = _mk_export(tmp_path)
    summary = json.loads((d / 'export-summary.json').read_text())
    (d / 'control' / 'a.txt').write_bytes(b'hello')
    summary['inventory'].append({'path': 'control/a.txt', 'bytes': 5, 'sha256': hashlib.sha256(b'hello').hexdigest()})
    os.chmod(d / 'export-summary.json', 0o644)
    (d / 'export-summary.json').write_text(json.dumps(summary))
    os.chmod(d / 'export-summary.json', 0o444)
    with pytest.raises(ValueError):
        pp.pack(d, out / 'a.tar', **_args(d))  # self-consistent but outside the exporter's fixed categories
    assert not (out / 'a.tar').exists()
    d2 = _mk_export(tmp_path / 'sub') if (tmp_path / 'sub').mkdir() is None else None
    link = tmp_path / 'viasym'
    os.symlink(tmp_path / 'sub', link)
    with pytest.raises(OSError):
        pp.pack(link / d2.name, out / 'b.tar', **_args(d2))  # ancestor symlink refused
    os.symlink(tmp_path / 'out', tmp_path / 'outlink')
    with pytest.raises(OSError):
        pp.pack(d2, tmp_path / 'outlink' / 'c.tar', **_args(d2))  # output ancestor symlink refused


def test_publication_packer_short_read_and_failure_cleanup(tmp_path, monkeypatch):
    pp = _pp()
    monkeypatch.setattr(pp, 'APPROVED_FOR_EXECUTION', True)
    out = tmp_path / 'out'
    out.mkdir(mode=0o700)
    d = _mk_export(tmp_path)
    monkeypatch.setattr(pp, 'MAX_TAR', 100)  # tar construction fails mid-write: no final file, no partial
    with pytest.raises(ValueError):
        pp.pack(d, out / 'f.tar', **_args(d))
    assert list(out.iterdir()) == []


@pytest.mark.skipif(not _userns_ok(), reason='unprivileged user+PID namespaces unavailable')
def test_requested_but_unestablished_namespace_is_unverified_and_never_mutates_roots(wd, tmp_path, monkeypatch):
    monkeypatch.setattr(wd, 'open_child_pid_ns', lambda pid: None)
    monkeypatch.setattr(wd, 'NS_ESTABLISH_WAIT', 0.2)
    r, roots, rec, report = _run(wd, tmp_path, 'ok', 'nsfail', pid_namespace=True, user_namespace=True)
    assert r['absence_verified'] is False and r['complete'] is False and r['setup_error']
    assert r['root_dispositions'] == [{'state': 'UNVERIFIED_ABSENCE_NO_ROOT_MUTATION'}]


def test_namespace_inspection_error_is_never_absence(wd, monkeypatch):
    def boom(pid, target):
        raise wd.NamespaceInspectionError('simulated EACCES')
    monkeypatch.setattr(wd, '_in_or_under', boom)
    left = wd.kill_ns_members((0, 0), wait=0.1)
    assert left and left[0].get('inspection_error')


def test_namespace_scan_sees_descendant_namespace_and_handle_holders(wd):
    # a process that merely holds the namespace link open is an obligation too; use this process's own ns as the target
    own_fd = os.open('/proc/self/ns/pid', os.O_RDONLY)
    try:
        pids = {m['pid'] for m in wd.ns_members(own_fd, True)}
        assert os.getpid() in pids
    finally:
        os.close(own_fd)
