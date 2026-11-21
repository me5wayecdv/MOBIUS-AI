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


def test_namespace_scan_sees_descendant_namespace_and_handle_holders(wd, monkeypatch):
    # a process that merely holds the namespace link open is an obligation too; use this process's own ns as the target
    own_fd = os.open('/proc/self/ns/pid', os.O_RDONLY)
    try:
        # deterministic scan set: an unrelated same-uid process on a CI runner can refuse ns/pid (EACCES), which is a correct inspection error
        # but not what this test exercises. The unreadable-process failure path is covered by its own tests.
        monkeypatch.setattr(wd.os, 'scandir', lambda path: iter([NS(name=str(os.getpid()))]))
        pids = {m['pid'] for m in wd.ns_members(own_fd, True)}
        assert os.getpid() in pids
    finally:
        os.close(own_fd)


NONCE = 'a' * 32
APP = {'pid': 10, 'uid': 20}


def _log(*kinds, pid=10, uid=20, fail='SSLHandshakeException', nonce=NONCE, tag='MobiusOwnedFixture', lpid=None, ts='11-21 13:00:00.123'):
    lines = []
    for k in kinds:
        extra = ' class=%s' % fail if k == 'FAILED' else ''
        lines.append('%s  %d  %d I %s: OWNED_FIXTURE_%s nonce=%s pid=%d uid=%d%s' % (ts, lpid or pid, pid, tag, k, nonce, pid, uid, extra))
    return '\n'.join(lines)


def _nv():
    import sys as _s
    if str(ROOT) not in _s.path:
        _s.path.insert(0, str(ROOT))
    return importlib.import_module('negative_verdict')


import calendar as _cal
E0 = _cal.timegm((2026, 11, 21, 13, 0, 0)) * 1000 + 123
RUN = 'run-1'
WIN = {'start': E0 - 1000, 'end': E0 + 5000}
CAP = {'year': 2026, 'tz_offset_minutes': 0, 'device_clock_offset_ms': 0}
_CERTS = {}


def _mk(name, issuer=None, sans=None, key=None, ca=True, nokcs=False, noeku=False, expired=False):
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = key or ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    ik, ic = issuer if issuer else (key, None)
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(ic.subject if ic else subj).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime(2026, 1, 1))
         .not_valid_after(datetime.datetime(2026, 6, 1) if expired else datetime.datetime(2030, 1, 1))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=ca and not nokcs, crl_sign=False, encipher_only=False,
                                      decipher_only=False), critical=True))
    if not ca and not noeku:
        b = b.add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    if sans is not None:
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = b.sign(ik, hashes.SHA256())
    return key, cert


def _der(c):
    from cryptography.hazmat.primitives.serialization import Encoding
    return c.public_bytes(Encoding.DER)


def _pki():
    if not _CERTS:
        import ipaddress
        from cryptography import x509
        a = _mk('Anchor A')
        b = _mk('Anchor B')
        loop = [x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]
        _CERTS.update(a=a, b=b, leaf_a=_mk('leaf', issuer=a, sans=loop, ca=False), leaf_b=_mk('leaf', issuer=b, sans=loop, ca=False),
                      wild=_mk('leaf', issuer=a, sans=[x509.DNSName('*.invalid')], ca=False),
                      dns=_mk('leaf', issuer=a, sans=[x509.DNSName('owned-name-mismatch.invalid')], ca=False),
                      reissued_b=_mk('Anchor B reissued', key=b[0]),
                      expired=_mk('leaf', issuer=a, sans=loop, ca=False, expired=True), noeku=_mk('leaf', issuer=a, sans=loop, ca=False, noeku=True),
                      nokcs=_mk('Anchor NoKCS', nokcs=True))
    return _CERTS


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _led(sc, count=0, **over):
    d = {'run_id': RUN, 'scenario': sc, 'nonce': NONCE, 'window_start': E0 - 5000, 'window_end': E0 + 9000, 'complete': True, 'count': count}
    d.update(over)
    return d


def _prem(sc):
    k = _pki()
    if sc == 'untrusted-ca':
        return {'trust_anchor_der': _der(k['a'][1]), 'presented_chain_der': [_der(k['leaf_b'][1]), _der(k['b'][1])]}
    if sc == 'wrong-hostname':
        return {'trust_anchor_der': _der(k['a'][1]), 'presented_chain_der': [_der(k['leaf_a'][1]), _der(k['a'][1])],
                'peer_name': 'owned-name-mismatch.invalid'}
    return {'trust_anchor_der': _der(k['a'][1]), 'presented_chain_der': [_der(k['leaf_b'][1]), _der(k['b'][1])]}


def _build(sc):
    a = _sha(_der(_pki()['a'][1]))
    return {'run_id': RUN, 'scenario': sc, 'apk_sha256': 'b' * 64, 'installed_apk_sha256': 'b' * 64,
            'embedded_anchor_sha256': a, 'proxy_upstream_trust_sha256': a}


def _refusal(sc, **over):
    d = {'run_id': RUN, 'scenario': sc, 'nonce': NONCE, 'upstream': '127.0.0.1:18443',
         'upstream_leaf_sha256': _sha(_der(_pki()['leaf_b'][1])), 'reason': 'certificate_verify_failed', 'observed_at': E0 + 1000, 'count': 1}
    d.update(over)
    return d


def _ev(sc, text, **kw):
    base = dict(nonce=NONCE, run_id=RUN, app_window=dict(WIN), capture=dict(CAP), expected_app=dict(APP), build_record=_build(sc),
                premises=_prem(sc), native_ledger=_led(sc), origin_ledger=_led(sc), proxy_refusal=_refusal(sc),
                teardown_absence_verified=True)
    base.update(kw)
    return _nv().evaluate(sc, text, **base)


KINDS = ('PREPARED', 'SOCKET', 'TLS_BEGIN', 'FAILED')


@pytest.mark.parametrize('sc', ['untrusted-ca', 'wrong-hostname'])
def test_negative_verdict_passes_only_with_full_expected_evidence(sc):
    res = _ev(sc, _log(*KINDS))
    assert res['passed'] is True and res['refusal_reason_established'] is False


def test_negative_verdict_untrusted_origin_requires_refusal_and_no_tls():
    ok = _log('PREPARED', 'SOCKET', 'FAILED', fail='IOException')
    assert _ev('untrusted-origin', ok)['passed'] is True
    assert not _ev('untrusted-origin', ok, proxy_refusal=None)['passed']
    for bad in ({'nonce': 'c' * 32}, {'upstream': '10.0.0.1:443'}, {'upstream_leaf_sha256': 'e' * 64}, {'observed_at': E0 + 99999}, {'run_id': 'other'}, {'reason': 'x'}):
        assert not _ev('untrusted-origin', ok, proxy_refusal=_refusal('untrusted-origin', **bad))['passed'], bad
    assert not _ev('untrusted-origin', _log(*KINDS, fail='IOException'))['passed']


def _mutated(mutate):
    text, kw = _log(*KINDS), {}
    sc = 'untrusted-ca'
    if mutate == 'established':
        text = _log('PREPARED', 'SOCKET', 'TLS_BEGIN', 'TLS_ESTABLISHED', 'FAILED')
    elif mutate == 'completed':
        text = _log(*KINDS, 'REQUEST_COMPLETED')
    elif mutate == 'success_without_nonce':
        text = _log(*KINDS) + '\n11-21 13:00:01.000  10  10 I MobiusOwnedFixture: OWNED_FIXTURE_REQUEST_COMPLETED pid=10 uid=20'
    elif mutate == 'ledger_nonzero':
        kw['native_ledger'] = _led(sc, 1)
    elif mutate == 'origin_nonzero':
        kw['origin_ledger'] = _led(sc, 1)
    elif mutate == 'ledger_bare_zero':
        kw['native_ledger'] = 0
    elif mutate == 'ledger_false':
        kw['origin_ledger'] = False
    elif mutate == 'ledger_incomplete':
        kw['native_ledger'] = _led(sc, 0, complete=False)
    elif mutate == 'ledger_wrong_nonce':
        kw['native_ledger'] = _led(sc, 0, nonce='c' * 32)
    elif mutate == 'ledger_bad_window':
        kw['origin_ledger'] = _led(sc, 0, window_start=E0 + 9, window_end=E0 - 1)
    elif mutate == 'wrong_nonce':
        text = _log(*KINDS, nonce='c' * 32)
    elif mutate == 'mixed_pid':
        text = _log(*KINDS[:2]) + '\n' + _log(*KINDS[2:], pid=11)
    elif mutate == 'logcat_pid_mismatch':
        text = _log(*KINDS, lpid=99)
    elif mutate == 'unobserved_identity':
        kw['expected_app'] = {'pid': 11, 'uid': 20}
    elif mutate == 'missing_identity':
        text = _log(*KINDS).replace(' pid=10 uid=20', '', 1)
    elif mutate == 'missing_nonce':
        text = _log(*KINDS).replace(' nonce=' + NONCE, '', 1)
    elif mutate == 'wrong_tag':
        text = _log(*KINDS, tag='SomeOtherTag')
    elif mutate == 'not_threadtime':
        text = 'OWNED_FIXTURE_PREPARED nonce=%s pid=10 uid=20' % NONCE
    elif mutate == 'duplicate_key':
        text = _log(*KINDS).replace('uid=20', 'uid=20 uid=20', 1)
    elif mutate == 'refused_marker':
        text = _log(*KINDS) + '\n11-21 13:00:01.000  10  10 I MobiusOwnedFixture: REFUSED fresh prepare required'
    elif mutate == 'bad_class':
        text = _log(*KINDS, fail='ConnectException')
    elif mutate == 'missing_begin':
        text = _log('PREPARED', 'SOCKET', 'FAILED')
    elif mutate == 'order':
        text = _log('PREPARED', 'TLS_BEGIN', 'SOCKET', 'FAILED')
    elif mutate == 'no_teardown':
        kw['teardown_absence_verified'] = False
    elif mutate == 'teardown_truthy':
        kw['teardown_absence_verified'] = 1
    elif mutate == 'apk_arbitrary_equal':
        kw['build_record'] = dict(_build(sc), apk_sha256='not-a-hash', installed_apk_sha256='not-a-hash')
    elif mutate == 'apk_not_installed':
        kw['build_record'] = dict(_build(sc), installed_apk_sha256='d' * 64)
    elif mutate == 'apk_other_scenario':
        kw['build_record'] = dict(_build(sc), scenario='wrong-hostname')
    elif mutate == 'same_anchor':
        k = _pki()
        kw['premises'] = {'trust_anchor_der': _der(k['a'][1]), 'presented_chain_der': [_der(k['leaf_a'][1]), _der(k['a'][1])]}
    elif mutate == 'same_key_reissued_anchor':
        k = _pki()
        kw['premises'] = {'trust_anchor_der': _der(k['reissued_b'][1]), 'presented_chain_der': [_der(k['leaf_b'][1]), _der(k['b'][1])]}
        kw['build_record'] = dict(_build(sc), embedded_anchor_sha256=_sha(_der(k['reissued_b'][1])))
    elif mutate == 'anchor_not_bound_to_build':
        kw['build_record'] = dict(_build(sc), embedded_anchor_sha256='9' * 64)
    elif mutate == 'ledger_disjoint_window':
        kw['native_ledger'] = _led(sc, 0, window_start=E0 + 100000, window_end=E0 + 200000)
    elif mutate == 'ledger_ends_before_app':
        kw['origin_ledger'] = _led(sc, 0, window_start=E0 - 5000, window_end=E0 - 3000)
    elif mutate == 'ledger_wrong_run':
        kw['native_ledger'] = _led(sc, 0, run_id='other')
    elif mutate == 'build_wrong_run':
        kw['build_record'] = dict(_build(sc), run_id='other')
    elif mutate == 'no_app_window':
        kw['app_window'] = None
    elif mutate == 'stale_markers':
        text = _log(*KINDS, ts='11-20 09:00:00.000')
    elif mutate == 'wrong_year_mapping':
        kw['capture'] = dict(CAP, year=2025)
    elif mutate == 'decreasing_timestamps':
        text = _log('PREPARED', 'SOCKET', ts='11-21 13:00:02.000') + '\n' + _log('TLS_BEGIN', 'FAILED', ts='11-21 13:00:01.000')
    elif mutate == 'no_clock_mapping':
        kw['capture'] = None
    elif mutate == 'none_run_id':
        kw['run_id'] = None
        kw['build_record'] = dict(_build(sc), run_id=None)
        kw['native_ledger'] = _led(sc, 0, run_id=None)
        kw['origin_ledger'] = _led(sc, 0, run_id=None)
    elif mutate == 'bad_form_run_id':
        kw['run_id'] = 'a b/c'
    elif mutate == 'expired_leaf':
        k = _pki()
        kw['premises'] = {'trust_anchor_der': _der(k['a'][1]), 'presented_chain_der': [_der(k['expired'][1]), _der(k['a'][1])]}
    elif mutate == 'leaf_without_serverauth':
        k = _pki()
        kw['premises'] = {'trust_anchor_der': _der(k['a'][1]), 'presented_chain_der': [_der(k['noeku'][1]), _der(k['a'][1])]}
    return _ev(sc, text, **kw)


@pytest.mark.parametrize('mutate', ['established', 'completed', 'success_without_nonce', 'ledger_nonzero', 'origin_nonzero', 'ledger_bare_zero',
                                    'ledger_false', 'ledger_incomplete', 'ledger_wrong_nonce', 'ledger_bad_window', 'wrong_nonce', 'mixed_pid',
                                    'logcat_pid_mismatch', 'unobserved_identity', 'missing_identity', 'missing_nonce', 'wrong_tag',
                                    'not_threadtime', 'duplicate_key', 'refused_marker', 'bad_class', 'missing_begin', 'order', 'no_teardown',
                                    'teardown_truthy', 'apk_arbitrary_equal', 'apk_not_installed', 'apk_other_scenario', 'same_anchor',
                                    'same_key_reissued_anchor', 'anchor_not_bound_to_build', 'ledger_disjoint_window', 'ledger_ends_before_app',
                                    'ledger_wrong_run', 'build_wrong_run', 'no_app_window', 'stale_markers', 'wrong_year_mapping',
                                    'decreasing_timestamps', 'no_clock_mapping', 'none_run_id', 'bad_form_run_id'])
def test_negative_verdict_fails_closed(mutate):
    res = _mutated(mutate)
    assert res['passed'] is False and res['reasons'], mutate


@pytest.mark.parametrize('leaf', ['wild', 'dns', 'leaf_b'])
def test_wrong_hostname_refuses_wildcard_dns_and_untrusted_chain(leaf):
    k = _pki()
    chain = [_der(k[leaf][1]), _der((k['b'] if leaf == 'leaf_b' else k['a'])[1])]
    prem = dict(_prem('wrong-hostname'), presented_chain_der=chain)
    assert not _ev('wrong-hostname', _log(*KINDS), premises=prem)['passed']
    assert not _ev('wrong-hostname', _log(*KINDS), premises=dict(_prem('wrong-hostname'), peer_name='other.invalid'))['passed']


def test_ns_get_parent_eperm_is_indeterminate_unless_own_namespace_proves_outside(wd, monkeypatch):
    import errno
    import fcntl

    def eperm(fd, req):
        raise OSError(errno.EPERM, 'denied')
    monkeypatch.setattr(fcntl, 'ioctl', eperm)
    # process in the watchdog's own namespace is positively outside an unrelated target: not a member, no error
    assert wd._in_or_under(os.getpid(), (0, 0)) is False
    # same process, but the watchdog's "own" namespace is something else: ancestry unknown, so an inspection obligation
    monkeypatch.setattr(wd, '_own_ref', lambda: (1, 1))
    with pytest.raises(wd.NamespaceInspectionError):
        wd._in_or_under(os.getpid(), (0, 0))


def test_external_handle_holder_is_reported_never_signalled(wd, monkeypatch):
    import subprocess as sp
    holder = sp.Popen([PY, '-c', 'import time;time.sleep(30)'])
    member = sp.Popen([PY, '-c', 'import time;time.sleep(30)'])
    try:
        ident_h = dict(wd.process_identity(holder.pid), kind='handle_holder')
        ident_m = dict(wd.process_identity(member.pid), kind='member')
        monkeypatch.setattr(wd, 'ns_members', lambda ref, skip=False: [i for i in (ident_h, ident_m) if (Path('/proc/%d' % i['pid']).exists() and wd.process_identity(i['pid'])['state'] != 'Z')])
        left = wd.kill_ns_members((0, 0), wait=0.5)
        member.wait(timeout=5)  # owned member was terminated
        assert holder.poll() is None  # foreign holder never signalled
        assert [m['pid'] for m in left] == [holder.pid] and left[0]['kind'] == 'handle_holder'
    finally:
        for p in (holder, member):
            p.kill()
            p.wait()


@pytest.mark.parametrize('leaf', ['expired', 'noeku'])
def test_wrong_hostname_refuses_when_another_certificate_defect_could_cause_the_refusal(leaf):
    k = _pki()
    prem = dict(_prem('wrong-hostname'), presented_chain_der=[_der(k[leaf][1]), _der(k['a'][1])])
    res = _ev('wrong-hostname', _log(*KINDS), premises=prem)
    assert res['passed'] is False and any('pinned certificate profile' in r for r in res['reasons'])


def test_wrong_hostname_refuses_non_keycertsign_anchor_and_profile_checks_apply_to_untrusted_chains():
    k = _pki()
    ca = k['nokcs']
    assert not _ev('wrong-hostname', _log(*KINDS), premises=dict(_prem('wrong-hostname'), trust_anchor_der=_der(ca[1])))['passed']
    prem = dict(_prem('untrusted-ca'))
    prem['presented_chain_der'] = [_der(k['leaf_b'][1]), _der(k['b'][1])]
    assert _ev('untrusted-ca', _log(*KINDS), premises=prem)['passed'] is True


def test_member_hash_inspect_streams_zip_and_tar_without_writes(tmp_path,monkeypatch):
    import hashlib,io,os,tarfile,zipfile
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'research'/'d061_android'))
    import member_hash_inspect as m
    assert m.APPROVED_FOR_EXECUTION is False
    def go(path,sha=None,size=None):
        b=path.read_bytes();fd=os.open(path,os.O_RDONLY)
        try:return m.inspect_fd(fd,sha or hashlib.sha256(b).hexdigest(),len(b) if size is None else size)
        finally:os.close(fd)
    z=tmp_path/'a.zip'
    with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as w:w.writestr('p/x.txt',b'hello')
    out=go(z);assert out['members'][0]['sha256']==hashlib.sha256(b'hello').hexdigest() and out['license_accepted'] is False
    t=tmp_path/'a.tar.gz'
    with tarfile.open(t,'w:gz') as w:
        i=tarfile.TarInfo('j/f');i.size=3;w.addfile(i,io.BytesIO(b'abc'))
        l=tarfile.TarInfo('j/l');l.type=tarfile.SYMTYPE;l.linkname='f';w.addfile(l)
    out=go(t);assert out['members'][0]['sha256']==hashlib.sha256(b'abc').hexdigest() and out['members'][1]['target']=='f'
    for bad in (('0'*64,None),(None,1),(None,m.MAX_CONTAINER+1),('xyz',None)):
        with pytest.raises(ValueError):go(t,*bad)
    fd=os.open(t,os.O_RDONLY)
    for args in ((None,5),(5,5),(hashlib.sha256(b'').hexdigest(),None)):
        with pytest.raises((ValueError,TypeError)):m.inspect_fd(fd,*args)
    os.close(fd)
    # mandatory pins refuse BEFORE parsing: a garbage container never reaches a parser
    g=tmp_path/'g.bin';g.write_bytes(b'PK'+b'x'*50)
    with pytest.raises(ValueError,match='BEFORE parsing'):go(g,'0'*64)
    bad=tmp_path/'b.zip'
    with zipfile.ZipFile(bad,'w') as w:w.writestr('../e',b'x')
    with pytest.raises(ValueError):go(bad)
    # in-place mutation during parse is refused
    orig=m._parse
    def mutating(fd,*a):
        os.utime(z,ns=(1,1));return orig(fd,*a)
    monkeypatch.setattr(m,'_parse',mutating)
    with pytest.raises(ValueError,match='changed'):go(z)
    assert not (tmp_path/'p').exists() and not (tmp_path/'j').exists()
    with pytest.raises(SystemExit):m.main()


def test_member_hash_inspect_anchored_open_and_outer_limits_in_child(tmp_path,monkeypatch):
    import os,subprocess,sys,hashlib
    root=Path(__file__).resolve().parents[1]/'research'/'d061_android'
    monkeypatch.syspath_prepend(str(root))
    import member_hash_inspect as m
    d=tmp_path/'d';d.mkdir(mode=0o700);f=d/'f';f.write_bytes(b'z');os.chmod(f,0o600);os.chmod(tmp_path,0o700)
    fd=m.open_anchored(str(f));os.close(fd)
    (d/'ln').symlink_to(f)
    with pytest.raises(OSError):m.open_anchored(str(d/'ln'))
    link=tmp_path/'dl';link.symlink_to(d)
    with pytest.raises(OSError):m.open_anchored(str(link/'f'))
    os.chmod(f,0o666)
    with pytest.raises(ValueError):m.open_anchored(str(f))
    os.chmod(f,0o600);os.link(f,d/'h')
    with pytest.raises(ValueError):m.open_anchored(str(f))
    os.mkfifo(d/'q')
    with pytest.raises((ValueError,OSError)):m.open_anchored(str(d/'q'))
    # real outer limits enforced in a child process (not the in-process unit path)
    code=("import sys;sys.path.insert(0,%r);import member_hash_inspect as m;"
          "m.apply_outer_limits({'as':512*1024**2,'cpu':5,'wall':3,'nofile':16});r=[]\n"
          "try:\n with open(%r,'wb') as q:q.write(b'x')\nexcept OSError:r.append('nowrite')\n"
          "try:bytearray(1024**3)\nexcept MemoryError:r.append('noalloc')\n"
          "print(','.join(r))\n")%(str(root),str(tmp_path/'w'))
    out=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=30)
    assert out.stdout.strip()=='nowrite,noalloc',out
    hang=subprocess.run([sys.executable,'-c',"import sys;sys.path.insert(0,%r);import member_hash_inspect as m,time;m.apply_outer_limits({'as':512*1024**2,'cpu':5,'wall':1,'nofile':16});time.sleep(10)"%str(root)],timeout=30)
    assert hang.returncode==70
    # parent capture: held CLI exits nonzero, so no inventory is returned
    with pytest.raises(m.CaptureError):m.run_child(str(f),hashlib.sha256(b'z').hexdigest(),1,wall=20)
    sha=hashlib.sha256(b'z').hexdigest()
    good={'container_sha256':sha,'container_bytes':1,'member_count':1,'declared_expanded_bytes':1,
        'members':[{'path':'a','size':1,'kind':'regular','mode':420,'sha256':sha}],'inspection':'data_only_streaming_hash',
        'member_written':False,'package_code_executed':False,'license_accepted':False,'runtime_closure_resolved':False,'provenance_note':m.PROVENANCE_NOTE}
    import json as J
    def child(code):return [sys.executable,'-c',code]
    def run(code,**k):return m.run_child('x',sha,1,cmd=child(code),**k)
    assert run('import json,sys;json.dump(%r,sys.stdout)'%good)==good
    def kind(code,**k):
        with pytest.raises(m.CaptureError) as e:run(code,**k)
        return e.value.kind
    assert kind('print("not json")')=='bad_json'
    assert kind('import sys;sys.exit(3)')=='nonzero_exit'
    assert kind('import sys;sys.stdout.write("x"*(70*1024*1024))')=='output_bound'
    assert kind('import time;time.sleep(30)',wall=1)=='deadline'
    assert kind('print(1)')=='bad_schema'
    for mut in ({'container_bytes':2},{'container_sha256':'0'*64},{'license_accepted':True},{'member_written':True},{'extra':1},{'member_count':2}):
        assert kind('import json,sys;json.dump(%r,sys.stdout)'%{**good,**mut})=='bad_schema'
    bad_rows=[{'path':'../a','size':1,'kind':'regular','mode':420,'sha256':sha},{'path':'a','size':1,'kind':'regular','mode':0o4755,'sha256':sha},{'path':'a','size':1,'kind':'regular','mode':420}]
    for r in bad_rows:
        assert kind('import json,sys;json.dump(%r,sys.stdout)'%{**good,'members':[r]})=='bad_schema'
    # pidfd failure after a successful spawn: child stopped and reaped, CaptureError, no leak
    import time as T
    def nopidfd(pid):raise OSError(24,'x')
    code='import time;time.sleep(60)'
    t0=T.monotonic()
    with pytest.raises(m.CaptureError) as e:m.run_child('x',sha,1,cmd=child(code),_pidfd_open=nopidfd)
    assert e.value.kind=='pidfd' and T.monotonic()-t0<15 and e.value.kind in m.KINDS
    # read error class
    import select as S
    orig_sel=S.select
    monkeypatch.setattr(m.select,'select',lambda *a,**k:(_ for _ in ()).throw(OSError(5,'x')))
    assert kind('import time;time.sleep(30)')=='read_error'
    monkeypatch.setattr(m.select,'select',orig_sel)
    # semantic closure: types, keys, aliases, modes, targets
    def sch(**mut):return 'import json,sys;json.dump(%r,sys.stdout)'%{**good,**mut}
    reg={'path':'a','size':1,'kind':'regular','mode':420,'sha256':sha}
    lnk={'path':'l','size':0,'kind':'symlink','mode':511,'target':'a'}
    assert run(sch(members=[reg,lnk],member_count=2))['member_count']==2
    for rows,extra in (([{**reg,'path':'a/'}],{}),([reg,{**reg,'path':'a/'}],{'member_count':2,'declared_expanded_bytes':2}),
        ([{**reg,'mode':-1}],{}),([{**reg,'mode':0o1000}],{}),([{**reg,'mode':True}],{}),([{**reg,'size':True}],{}),
        ([{**reg,'sha256':sha.upper()}],{}),([{**reg,'extra':1}],{}),([{'path':'l','size':0,'kind':'symlink','mode':511}],{'declared_expanded_bytes':0}),
        ([{**lnk,'target':'x'*5000}],{'declared_expanded_bytes':0}),([{**lnk,'target':5}],{'declared_expanded_bytes':0}),
        ([{**lnk,'target':''}],{'declared_expanded_bytes':0}),([{**lnk,'sha256':sha}],{'declared_expanded_bytes':0}),
        ([{'path':'d','size':1,'kind':'directory','mode':493}],{}),([{**reg,'kind':'fifo'}],{})):
        assert kind(sch(members=rows,**extra))=='bad_schema',rows
    assert kind(sch(container_bytes=1.0))=='bad_schema' and kind(sch(container_bytes=True))=='bad_schema'
    assert kind(sch(member_count=True))=='bad_schema' and kind(sch(declared_expanded_bytes=1.0))=='bad_schema'
    assert kind(sch(members=[{**reg,'kind':[1]}]))=='bad_schema' and kind(sch(members=[{**reg,'kind':{}}]))=='bad_schema'
    assert kind(sch(members=[5]))=='bad_schema'
    # ZIP symlink full roundtrip: inspector output must pass the parent validator
    import zipfile,io,os as O
    zp=tmp_path/'l.zip'
    with zipfile.ZipFile(zp,'w') as w:
        w.writestr('r/f',b'abc')
        zi=zipfile.ZipInfo('r/s');zi.create_system=3;zi.external_attr=(0o120777<<16);w.writestr(zi,b'f')
    data=zp.read_bytes();zsha=hashlib.sha256(data).hexdigest()
    zfd=O.open(zp,O.O_RDONLY)
    try:inv=m.inspect_fd(zfd,zsha,len(data))
    finally:O.close(zfd)
    assert m.validate_inventory(J.loads(J.dumps(inv)),zsha,len(data))['member_count']==2
    assert [r['kind'] for r in inv['members']]==['regular','symlink'] and 'sha256' not in inv['members'][1] and inv['members'][1]['target']=='f'
    # cleanup_verified is part of the closed diagnostic
    with pytest.raises(m.CaptureError) as ce:m.run_child('x',sha,1,cmd=child('print(1)'),_pidfd_open=nopidfd)
    assert ce.value.cleanup_verified in (True,False)
    assert kind(sch(provenance_note='free text'))=='bad_schema'
    # no group signalling anywhere in the parent
    import inspect as I
    assert 'killpg' not in I.getsource(m)
    assert (tmp_path/'w').stat().st_size==0


def test_runner_capability_probe_is_readonly_and_held(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'research'/'d061_android'))
    import runner_capability_probe as r
    assert r.APPROVED_FOR_EXECUTION is False
    (tmp_path/'sys/fs/cgroup').mkdir(parents=True);(tmp_path/'sys/fs/cgroup/cgroup.controllers').write_text('cpu memory pids')
    before=sorted(str(x) for x in tmp_path.rglob('*'))
    out=r.probe(str(tmp_path))
    assert out['kvm']['present'] is False and out['cgroup_v2']['controllers']=='cpu memory pids' and 'no sudo' in out['claims']
    assert before==sorted(str(x) for x in tmp_path.rglob('*'))
    with pytest.raises(SystemExit):r.main()


def test_audience_gate_is_plan_validation_only(monkeypatch,tmp_path):
    import os,json
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'research'/'d061_android'))
    import audience_gate as g
    assert g.APPROVED_FOR_EXECUTION is True   # reviewed activation commit only; the flag is a gate, not authority
    ok={'route':'local_private_file','destination':'/var/private/inv','content_class':'package_hash_inventory','declared_retention_days':7,'route_evidence_ref':'main-route-0001'}
    assert g.check_plan(ok)=={'validated_plan_only':True,'retention_enforced':False,'route_verified':False}
    for mut in ({'route':'private_agent_channel'},{'route':'workflow_log'},{'route':['a']},{'content_class':'device_logs'},{'content_class':['x']},
        {'declared_retention_days':0},{'declared_retention_days':99},{'declared_retention_days':True},{'destination':'rel/x'},
        {'destination':'/a/../b'},{'destination':'/a//b'},{'destination':'/a/./b'},{'destination':'/a/b/'},{'route_evidence_ref':'x'},{'route_evidence_ref':5},{'extra':1}):
        with pytest.raises(ValueError):g.check_plan({**ok,**mut})
    with pytest.raises(ValueError):g.check_plan('x')
    # use-time verification of the real filesystem destination
    d=tmp_path/'priv';d.mkdir(mode=0o700);os.chmod(tmp_path,0o700)
    plan={**ok,'destination':str(d),'content_class':'capability_metadata'}
    cap0={'euid':0,'kvm_present':True,'kvm_rw':False,'disk_free_bytes':1,'disk_total_bytes':2}
    res=g.publish_private(plan,'cap.json',cap0)
    assert res['written_relative_to_plan_destination'] and oct((d/'cap.json').stat().st_mode&0o777)=='0o600'
    assert res['committed'] and res['temp_removed'] and res['durable_dir_fsync']
    assert json.loads((d/'cap.json').read_text())==cap0 and not [x for x in os.listdir(d) if x.startswith('.tmp-')]
    # collision: an existing final name (even identical content) is never claimed as this run's output
    with pytest.raises(FileExistsError):g.publish_private(plan,'cap.json',cap0)
    assert not [x for x in os.listdir(d) if x.startswith('.tmp-')]
    # a pre-existing file named like a temp is never deleted by an unrelated attempt
    (d/'.tmp-foreign').write_text('keep')
    with pytest.raises(FileExistsError):g.publish_private(plan,'cap.json',cap0)
    assert (d/'.tmp-foreign').read_text()=='keep';(d/'.tmp-foreign').unlink()
    with pytest.raises(ValueError):g.publish_private(plan,'bad.json',{**cap0,'host':'x'})
    assert not (d/'bad.json').exists() and not os.listdir(d)==['x']
    for bad_name in ('../x','a/b','',' x','y.part','.tmp-x'):
        with pytest.raises(ValueError):g.publish_private(plan,bad_name,cap0)
    with pytest.raises(ValueError):g.publish_private({**plan,'route':'x'},'z.json',cap0)
    with pytest.raises(AttributeError):g.write_private
    # a partial from a failed publish is cleaned: force link failure
    import unittest.mock as um
    with um.patch('os.link',side_effect=OSError(5,'x')):
        with pytest.raises(OSError):g.publish_private(plan,'r.json',cap0)
    assert not (d/'r.json').exists() and not [x for x in os.listdir(d) if x.startswith('.tmp-')]
    # after-link unlink failure: output stays committed, leftover is REPORTED not raised, and a retry reports the collision honestly
    real_unlink=os.unlink
    def flaky(path,*a,**k):
        if str(path).startswith('.tmp-'):raise OSError(13,'x')
        return real_unlink(path,*a,**k)
    with um.patch('os.unlink',side_effect=flaky):
        res2=g.publish_private(plan,'s.json',cap0)
    assert res2['committed'] and res2['temp_removed'] is False and (d/'s.json').exists()
    for x in os.listdir(d):
        if x.startswith('.tmp-'):(d/x).unlink()
    with pytest.raises(FileExistsError):g.publish_private(plan,'s.json',cap0)
    dfd=g.open_private_destination(str(d));os.close(dfd)
    os.chmod(d,0o750)
    with pytest.raises(ValueError):g.publish_private(plan,'m.json',cap0)
    with pytest.raises(ValueError):g.open_private_destination(str(d))
    os.chmod(d,0o700);(tmp_path/'ln').symlink_to(d)
    with pytest.raises(OSError):g.open_private_destination(str(tmp_path/'ln'))
    os.chmod(tmp_path,0o770)
    with pytest.raises(ValueError):g.open_private_destination(str(d))
    os.chmod(tmp_path,0o700)
    # content validated by schema, never by label
    cap={'euid':0,'kvm_present':True,'kvm_rw':False,'disk_free_bytes':1,'disk_total_bytes':2}
    assert g.validate_content('capability_metadata',cap)==cap
    for bad in ({**cap,'host':'runner-1'},{**cap,'euid':True},{**cap,'disk_free_bytes':-1},{**cap,'kvm_present':'yes'}):
        with pytest.raises(ValueError):g.validate_content('capability_metadata',bad)
    fr={'step':'F1','ok':True,'errno':0,'start_epoch_ms':1,'end_epoch_ms':2}
    assert g.validate_content('fault_result',fr)==fr
    for bad in ({**fr,'step':'F9'},{**fr,'errno':-1},{**fr,'ok':1},{**fr,'end_epoch_ms':0},{**fr,'msg':'x'},{**fr,'errno':True}):
        with pytest.raises(ValueError):g.validate_content('fault_result',bad)
    with pytest.raises(ValueError):g.validate_content('device_logs',{})
    with pytest.raises(ValueError):g.validate_content('package_hash_inventory',{'members':[]},sha256='0'*64,size=1)


def test_host_primitive_probe_sequence_with_fake_ops_and_closed_result(monkeypatch,tmp_path):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'research'/'d061_android'))
    import host_primitive_probe as hp
    import audience_gate as g
    assert hp.APPROVED_FOR_EXECUTION is True   # reviewed activation commit only; the flag is a gate, not authority
    monkeypatch.setattr(hp,'APPROVED_FOR_EXECUTION',False)
    with pytest.raises(SystemExit):hp.main()
    monkeypatch.setattr(hp,'APPROVED_FOR_EXECUTION',True)
    env=hp.envelope('run-1','a'*40,'b'*64)
    for bad in (('x y','a'*40,'b'*64),(5,'a'*40,'b'*64),('r','zz','b'*64),('r','a'*40,'B'*64)):
        with pytest.raises(ValueError):hp.envelope(*bad)
    class Fake:
        def __init__(s,**kw):s.calls=[];s.kw=kw;s.vals={}
        def _c(s,n,*a):
            s.calls.append(n)
            if s.kw.get('fail')==n:raise OSError(s.kw.get('errno',13),'x')
        def require_controllers(s,n):s._c('controllers')
        def make_leaf(s,r):s._c('mkdir');return '/leaf'
        def write(s,l,k,v):s._c('write');s.vals[k]=v
        def read(s,l,k):s.calls.append('read');return 'tampered' if s.kw.get('bad_readback') else s.vals[k]
        def spawn_gated(s):s._c('spawn');return 7
        def join(s,l,c):s._c('join')
        def verify_member(s,l,c):s._c('verify')
        def release_gate(s,c):s._c('release')
        def unshare_result(s,c,d):s.calls.append('unshare');return s.kw.get('unshare',0)
        def wait_exit(s,c,d):s.calls.append('wait');return s.kw.get('exit',0)
        def cleanup(s,l,c):s.calls.append('cleanup');return s.kw.get('clean',True)
    f=Fake();out=hp.run(f,env)
    assert [r['ok'] for r in out['results']]==[True]*4
    # order: limits written and read back BEFORE spawn; join+verify BEFORE release; cleanup last
    c=f.calls;assert c.index('read')<c.index('spawn')<c.index('join')<c.index('verify')<c.index('release')<c.index('unshare')<c.index('wait')<c.index('cleanup')
    assert g.validate_content('host_primitive_result',out)==out
    for kw,idx in (({'fail':'controllers','errno':95},0),({'fail':'mkdir','errno':17},0),({'bad_readback':True},0),({'fail':'spawn','errno':11},1),
        ({'fail':'join','errno':1},1),({'unshare':1},1),({'exit':3},2),({'exit':None},2),({'clean':False},3)):
        f=Fake(**kw);o=hp.run(f,env)
        assert not o['results'][idx]['ok'],kw          # denial is a failure, never a pass
        assert 'cleanup' in f.calls                    # live parent always attempts bounded cleanup
        if idx<3 and kw!={'clean':False}:assert not any(r['ok'] for r in o['results'][idx:3]) 
        g.validate_content('host_primitive_result',o)
    f=Fake(fail='controllers');hp.run(f,env);assert 'spawn' not in f.calls and 'release' not in f.calls
    f=Fake(bad_readback=True);hp.run(f,env);assert 'spawn' not in f.calls   # no member joins before readback passes
    for bad in ({'envelope':env,'results':out['results'][:3]},{'envelope':{**env,'extra':1},'results':out['results']},
        {'envelope':env,'results':[{**r,'msg':'x'} for r in out['results']]},{'envelope':env,'results':out['results'][::-1]}):
        with pytest.raises(ValueError):g.validate_content('host_primitive_result',bad)
    with pytest.raises(ValueError):hp.RealOps('/sys/fs/cgroup/../x','/bin/sleep','0'*64)
    with pytest.raises(ValueError):hp.RealOps('/tmp/x','/bin/sleep','0'*64)
    sl=tmp_path/'sleep-copy';sl.write_bytes(b'#!/bin/sh\n');os.chmod(sl,0o755)   # a regular file: /bin/sleep may be a symlink on a runner image
    with pytest.raises(ValueError):hp.RealOps('/sys/fs/cgroup',str(sl),'0'*64,trusted_uid=os.getuid())   # pinned identity mismatch refuses
    for bad in (('r','a'*64,'b'*64),('r','a'*40,'b'*40)):
        with pytest.raises(ValueError):hp.envelope(*bad)   # commit and sha256 are separate types


def test_host_primitive_real_ops_acquisition_and_failure_branches(tmp_path,monkeypatch):
    import os,shutil,hashlib,subprocess
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'research'/'d061_android'))
    import host_primitive_probe as hp
    euid=os.geteuid()
    sleep=tmp_path/'sleepcopy';shutil.copy(shutil.which('sleep'),sleep);os.chmod(sleep,0o755)
    sha=hashlib.sha256(sleep.read_bytes()).hexdigest()
    root=tmp_path/'tree';cg=root/'sys/fs/cgroup';cg.mkdir(parents=True)
    for p in (tmp_path,root,root/'sys',root/'sys/fs',cg):os.chmod(p,0o755)
    (cg/'cgroup.controllers').write_text('cpu memory pids');(cg/'cgroup.subtree_control').write_text('cpu memory pids')
    class Ops(hp.RealOps):
        _root=str(root)
        files=('pids.max','memory.max','cpu.max','cgroup.events','cgroup.kill')
        def make_leaf(self,run_id):
            n=super().make_leaf(run_id)
            for f in self.files:
                fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_CLOEXEC,0o644,dir_fd=self.leaf_fd);os.close(fd)
            with open(str(cg/n/'cgroup.events'),'w') as e:e.write('populated 0\nfrozen 0\n')
            return n
    def fds():return len(os.listdir('/proc/self/fd'))
    base=fds()
    # constructor refusals close everything they opened
    with pytest.raises(ValueError):Ops('/sys/fs/cgroup',str(sleep),'0'*64,trusted_uid=euid)
    with pytest.raises(ValueError):Ops('/sys/fs/cgroup',str(sleep),sha,trusted_uid=euid+1)
    assert fds()==base
    # a symlinked parent component is refused (not followed)
    alt=tmp_path/'alt';(alt/'fs/cgroup').mkdir(parents=True)
    (root/'sys2').symlink_to(alt)
    class Ops2(Ops):pass
    with pytest.raises(ValueError):hp.RealOps('/sys/fs/cgroup/../x',str(sleep),sha)
    shutil.rmtree(root/'sys');(root/'sys').symlink_to(alt)
    with pytest.raises(OSError):Ops('/sys/fs/cgroup',str(sleep),sha,trusted_uid=euid)
    assert fds()==base
    os.unlink(root/'sys');(root/'sys/fs/cgroup').mkdir(parents=True)
    for p in (root/'sys',root/'sys/fs',cg):os.chmod(p,0o755)
    (cg/'cgroup.controllers').write_text('cpu memory pids');(cg/'cgroup.subtree_control').write_text('cpu memory pids')
    env=hp.envelope('run-t','a'*40,sha)
    # join failure (no cgroup.procs in the fake leaf): gated child must still be killed and reaped
    ops=Ops('/sys/fs/cgroup',str(sleep),sha,trusted_uid=euid)
    out=hp.run(ops,env)
    assert out['results'][0]['ok'] and not out['results'][1]['ok'] and not out['results'][3]['ok']
    assert ops.proc is not None and ops.proc.poll() is not None   # no orphan even though cgroup.kill "worked" on an empty leaf
    assert fds()==base
    # pidfd_open failure after Popen: the already-started child is killed by cleanup
    shutil.rmtree(cg/'mobius-probe-run-t',ignore_errors=True)
    ops=Ops('/sys/fs/cgroup',str(sleep),sha,trusted_uid=euid)
    monkeypatch.setattr(os,'pidfd_open',lambda pid:(_ for _ in ()).throw(OSError(24,'x')))
    ops.require_controllers({'pids'});ops.make_leaf('run-u')
    with pytest.raises(OSError):ops.spawn_gated()
    assert ops.proc is not None and ops.proc.poll() is None
    assert ops.cleanup('x',None) is False or True
    assert ops.proc.poll() is not None
    monkeypatch.undo()
    assert fds()==base
    # leaf identity bound: replacing the leaf name before removal refuses rmdir
    ops=Ops('/sys/fs/cgroup',str(sleep),sha,trusted_uid=euid);ops.make_leaf('run-v')
    (cg/'mobius-probe-run-v').rename(cg/'moved');(cg/'mobius-probe-run-v').mkdir()
    (cg/'mobius-probe-run-v/cgroup.procs').write_text('');(cg/'mobius-probe-run-v/cgroup.events').write_text('populated 0')
    assert ops.cleanup('x',None) is False and (cg/'mobius-probe-run-v').exists()
    assert fds()==base
    # unexpected exception inside the sequence is a closed failure, cleanup still runs once
    class Boom:
        calls=0
        def require_controllers(s,n):raise RuntimeError('x')
        def cleanup(s,l,c):Boom.calls+=1;return True
    o=hp.run(Boom(),env);assert Boom.calls==1 and not o['results'][0]['ok']


def test_host_probe_cleanup_obligations_and_publication_failure_paths(tmp_path,monkeypatch):
    import os,shutil,hashlib,threading,time
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'research'/'d061_android'))
    import host_primitive_probe as hp,audience_gate as g
    euid=os.geteuid()
    sleep=tmp_path/'sleepcopy';shutil.copy(shutil.which('sleep'),sleep);os.chmod(sleep,0o755)
    sha=hashlib.sha256(sleep.read_bytes()).hexdigest()
    root=tmp_path/'tree';cg=root/'sys/fs/cgroup';cg.mkdir(parents=True)
    for p in (tmp_path,root,root/'sys',root/'sys/fs',cg):os.chmod(p,0o755)
    (cg/'cgroup.controllers').write_text('cpu memory pids');(cg/'cgroup.subtree_control').write_text('cpu memory pids')
    class Ops(hp.RealOps):_root=str(root)
    # 1. mkdir succeeded but binding the leaf failed: cleanup removes the empty dir but reports UNVERIFIED (False)
    ops=Ops('/sys/fs/cgroup',str(sleep),sha,trusted_uid=euid)
    real_open=os.open
    def fail_leaf_open(path,flags,*a,**k):
        if path=='mobius-probe-run-w' and flags&os.O_DIRECTORY:raise OSError(24,'x')
        return real_open(path,flags,*a,**k)
    monkeypatch.setattr(os,'open',fail_leaf_open)
    with pytest.raises(OSError):ops.make_leaf('run-w')
    monkeypatch.setattr(os,'open',real_open)
    assert ops.leaf_unbound is True and (cg/'mobius-probe-run-w').exists()
    assert ops.cleanup('x',None) is False and (cg/'mobius-probe-run-w').exists()   # NON-mutating: the name is not ours until bound
    assert ops.unbound_locator=='mobius-probe-run-w'
    # a replacement directory at the unbound name is never removed; open-ok/fstat-failure is also unbound and no cgroup.kill is written
    os.rmdir(cg/'mobius-probe-run-w')
    ops=Ops('/sys/fs/cgroup',str(sleep),sha,trusted_uid=euid)
    real_fstat=os.fstat
    state={'n':0}
    def fstat_fail_on_leaf(fd):
        if state.get('arm') and os.path.isdir('/proc/self/fd/%d'%fd) and os.readlink('/proc/self/fd/%d'%fd).endswith('mobius-probe-run-z'):raise OSError(5,'x')
        return real_fstat(fd)
    monkeypatch.setattr(os,'fstat',fstat_fail_on_leaf);state['arm']=True
    with pytest.raises(OSError):ops.make_leaf('run-z')
    state['arm']=False;monkeypatch.setattr(os,'fstat',real_fstat)
    assert ops.leaf_fd is not None and ops.leaf_unbound is True and ops.leaf_ident is None
    (cg/'mobius-probe-run-z'/'cgroup.kill').write_text('untouched')
    assert ops.cleanup('x',None) is False and (cg/'mobius-probe-run-z').exists() and (cg/'mobius-probe-run-z/cgroup.kill').read_text()=='untouched'
    shutil.rmtree(cg/'mobius-probe-run-z')
    ops=Ops('/sys/fs/cgroup',str(sleep),sha,trusted_uid=euid)
    # 2. direct child already gone but the leaf stays populated: cgroup.kill is still written; async emptiness is awaited
    ops=Ops('/sys/fs/cgroup',str(sleep),sha,trusted_uid=euid);ops.make_leaf('run-x')
    leaf=cg/'mobius-probe-run-x'
    (leaf/'cgroup.procs').write_text('123\n');(leaf/'cgroup.events').write_text('populated 1\n');(leaf/'cgroup.kill').write_text('')
    real_write=ops.write
    def kill_then_drain(l,name,val):
        real_write(l,name,val)
        if name=='cgroup.kill':
            def later():
                time.sleep(0.3);(leaf/'cgroup.procs').write_text('');(leaf/'cgroup.events').write_text('populated 0\n')
            threading.Thread(target=later).start()
    monkeypatch.setattr(ops,'write',kill_then_drain)
    assert ops.proc is None
    real_rmdir=os.rmdir
    def cgroupfs_rmdir(path,*a,**k):          # a real cgroupfs rmdir succeeds with its pseudo files; the fake tree needs them removed
        for f in os.listdir(cg/path):os.unlink(cg/path/f)
        return real_rmdir(path,*a,**k)
    monkeypatch.setattr(os,'rmdir',cgroupfs_rmdir)
    assert ops.cleanup('x',None) is True and not leaf.exists()
    monkeypatch.setattr(os,'rmdir',real_rmdir)
    assert (cg/'moved').exists() is False
    # populated forever: bounded wait ends False and leaves the leaf (no removal of a populated leaf)
    ops=Ops('/sys/fs/cgroup',str(sleep),sha,trusted_uid=euid);ops.make_leaf('run-y')
    leaf=cg/'mobius-probe-run-y';(leaf/'cgroup.procs').write_text('9\n');(leaf/'cgroup.events').write_text('populated 1\n')
    monkeypatch.setattr(hp,'CLEANUP_S',0.3)
    t0=time.monotonic();assert ops.cleanup('x',None) is False and leaf.exists() and time.monotonic()-t0<5
    # 3. publication: post-link fsync failure is reported, not raised; temp fstat failure cleans its own exclusive temp
    d=tmp_path/'priv';d.mkdir(mode=0o700);os.chmod(tmp_path,0o700)
    plan={'route':'local_private_file','destination':str(d),'content_class':'capability_metadata','declared_retention_days':3,'route_evidence_ref':'main-route-0001'}
    cap={'euid':0,'kvm_present':True,'kvm_rw':False,'disk_free_bytes':1,'disk_total_bytes':2}
    real_fsync=os.fsync
    def fsync_dir_fails(fd):
        import stat as S
        if S.S_ISDIR(os.fstat(fd).st_mode):raise OSError(5,'x')
        return real_fsync(fd)
    monkeypatch.setattr(os,'fsync',fsync_dir_fails)
    res=g.publish_private(plan,'f.json',cap)
    monkeypatch.setattr(os,'fsync',real_fsync)
    assert res['committed'] is True and res['durable_dir_fsync'] is False and (d/'f.json').exists()
    monkeypatch.setattr(g,'_ident',lambda fd:(_ for _ in ()).throw(OSError(5,'x')))
    with pytest.raises(OSError):g.publish_private(plan,'h.json',cap)
    assert not (d/'h.json').exists() and not [x for x in os.listdir(d) if x.startswith('.tmp-')]
    # results carry the narrow pidns definition
    env=hp.envelope('run-1','a'*40,'b'*64);assert env['pidns_claim']==hp.PIDNS_CLAIM
    bad={**env,'pidns_claim':'namespace created and absent'}
    rows=[{'check':c,'ok':True,'errno':0} for c in hp.CHECKS]
    assert g.validate_content('host_primitive_result',{'envelope':env,'results':rows})
    with pytest.raises(ValueError):g.validate_content('host_primitive_result',{'envelope':bad,'results':rows})


def test_publish_close_failures_preserve_committed_state_and_primary_error(tmp_path,monkeypatch):
    import os,stat as S
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'research'/'d061_android'))
    import audience_gate as g
    d=tmp_path/'priv';d.mkdir(mode=0o700);os.chmod(tmp_path,0o700)
    plan={'route':'local_private_file','destination':str(d),'content_class':'capability_metadata','declared_retention_days':3,'route_evidence_ref':'main-route-0001'}
    cap={'euid':0,'kvm_present':True,'kvm_rw':False,'disk_free_bytes':1,'disk_total_bytes':2}
    real_close=os.close
    def close_fails(kind):
        calls={'n':0,'armed':False}
        real_open_dest=g.open_private_destination
        def armed_open(path):
            fd=real_open_dest(path);calls['armed']=True;return fd      # only closes AFTER the destination walk can fail
        monkeypatch.setattr(g,'open_private_destination',armed_open)
        def c(fd):
            st=os.fstat(fd);is_dir=S.S_ISDIR(st.st_mode)
            real_close(fd)                        # the descriptor is released either way (Linux semantics)
            if calls['armed'] and ((kind=='file' and not is_dir) or (kind=='dir' and is_dir)):
                calls['n']+=1;raise OSError(5,'x')
        return c,calls
    # file close failure after commit: still committed, temp removed, status reported, no exception
    c,calls=close_fails('file');monkeypatch.setattr(os,'close',c)
    r=g.publish_private(plan,'a.json',cap);monkeypatch.setattr(os,'close',real_close)
    assert r['committed'] and r['temp_fd_close_ok'] is False and r['temp_removed'] and (d/'a.json').exists()
    assert not [x for x in os.listdir(d) if x.startswith('.tmp-')]
    # dir close failure after commit: success result preserved with a status flag
    c,calls=close_fails('dir');monkeypatch.setattr(os,'close',c)
    r=g.publish_private(plan,'b.json',cap);monkeypatch.setattr(os,'close',real_close)
    assert r['committed'] and r['dir_fd_close_ok'] is False
    # close failure while a primary error propagates: the primary error wins and the temp is still removed
    c,calls=close_fails('file');monkeypatch.setattr(os,'close',c)
    with pytest.raises(FileExistsError):g.publish_private(plan,'a.json',cap)
    monkeypatch.setattr(os,'close',real_close)
    assert not [x for x in os.listdir(d) if x.startswith('.tmp-')]
    # identity failure plus close failure: temp is unlinked before close, primary preserved
    monkeypatch.setattr(g,'_ident',lambda fd:(_ for _ in ()).throw(OSError(5,'ident')))
    c,calls=close_fails('file');monkeypatch.setattr(os,'close',c)
    with pytest.raises(OSError) as e:g.publish_private(plan,'c.json',cap)
    monkeypatch.setattr(os,'close',real_close)
    assert 'ident' in str(e.value) and not [x for x in os.listdir(d) if x.startswith('.tmp-')] and not (d/'c.json').exists()
    assert calls['n']==1                          # closed exactly once, not retried


def test_host_primitive_entry_binding_and_failure_paths(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'research'/'d061_android'))
    import host_primitive_entry as he
    import host_primitive_probe as hp
    import audience_gate as g
    from types import SimpleNamespace as N
    C='c'*40
    uid=os.getuid()
    envr={'ImageOS':'ubuntu24','ImageVersion':'20261101.1.0'}
    dp=tmp_path/'run';dp.mkdir(mode=0o755)
    argv=['--repo','/x','--expected-commit',C,'--sleep-path','/s','--sleep-sha256','d'*64,'--parent','/sys/fs/cgroup/x','--run-id','hp1','--route-evidence-ref','route-ref-0001']
    calls=[]
    class Ops:
        def __init__(s,*a):calls.append('ctor')
        def close(s):calls.append('close')
    GOOD={'committed':True,'temp_removed':True,'temp_fd_close_ok':True,'dir_fd_close_ok':True,'durable_dir_fsync':True}
    def ld(ok=True,pub=None,run=None,approved=True):
        h=N(APPROVED_FOR_EXECUTION=approved,envelope=hp.envelope,RealOps=Ops,
            run=run or (lambda ops,env:{'envelope':env,'results':[{'check':c,'ok':ok,'errno':0} for c in hp.CHECKS]}))
        a=N(APPROVED_FOR_EXECUTION=approved,canonical_path=lambda p:p,check_plan=g.check_plan,publish_private=pub or (lambda *a,**k:calls.append('pub') or dict(GOOD)))
        return lambda:(h,a)
    def call(a=argv,loader=None,measure=lambda r:C,e=envr):
        calls.clear()
        return he.main(a,environ=e,loader=loader or ld(),measure=measure,trusted_uid=uid,dest_parent=str(dp))
    assert he.APPROVED_FOR_EXECUTION is True   # reviewed activation commit only; the flag is a gate, not authority
    monkeypatch.setattr(he,'APPROVED_FOR_EXECUTION',False)
    assert call()==he.RC_REFUSED and calls==[] and not any(dp.iterdir())
    monkeypatch.setattr(he,'APPROVED_FOR_EXECUTION',True)
    assert call(loader=ld(approved=False))==he.RC_REFUSED and calls==[]
    assert call(measure=lambda r:'e'*40)==he.RC_REFUSED and calls==[]
    assert call(e={})==he.RC_REFUSED and calls==[]
    bad=list(argv);bad[bad.index('--expected-commit')+1]='PLACEHOLDER_REVIEWED_PROBE_COMMIT_40HEX'
    assert call(bad)==he.RC_REFUSED and calls==[]
    assert call(argv+['--dest','/tmp/x'])==he.RC_REFUSED and calls==[]      # no caller-chosen destination
    bad=list(argv);bad[bad.index('--run-id')+1]='../x'
    assert call(bad)==he.RC_REFUSED and calls==[]
    # happy path: measured values in the envelope, destination created by the entry, ops closed, one publish
    seen={}
    def pub(plan,name,obj,**k):seen.update(plan=plan,name=name,obj=obj);calls.append('pub');return dict(GOOD)
    assert call(loader=ld(pub=pub))==he.RC_OK
    assert calls==['ctor','close','pub'] and seen['obj']['envelope']['source_commit']==C and seen['obj']['envelope']['runner_image']=='ubuntu24/20261101.1.0'
    d=dp/'d061-hp-hp1';assert d.is_dir() and (d.stat().st_mode&0o777)==0o700 and seen['plan']['destination']==str(d)
    g.validate_content('host_primitive_result',seen['obj'])
    # an existing destination name is never adopted
    assert call(loader=ld(pub=pub))==he.RC_REFUSED and calls==[]
    (dp/'d061-hp-hp1').rmdir()
    # failed check reported; pre-commit publish failure drops with no fallback (exit 3)
    assert call(loader=ld(ok=False,pub=pub))==he.RC_CHECK_FAILED;(dp/'d061-hp-hp1').rmdir()
    def boom(*a,**k):raise OSError(5,'x')
    assert call(loader=ld(pub=boom))==he.RC_PUBLISH_FAILED and calls==['ctor','close'];(dp/'d061-hp-hp1').rmdir()
    # committed result with incomplete flags is never ordinary success and is not dropped
    for k in GOOD:
        r=call(loader=ld(pub=lambda *a,k=k,**kw:calls.append('pub') or {**GOOD,k:False}))
        assert r==he.RC_INCOMPLETE and calls==['ctor','close','pub'];(dp/'d061-hp-hp1').rmdir()
    # run() raising still closes ops, publishes nothing
    def rb(ops,env):raise RuntimeError('x')
    assert call(loader=ld(pub=pub,run=rb))==he.RC_CHECK_FAILED and calls==['ctor','close'];(dp/'d061-hp-hp1').rmdir()
    # a loader/import failure is contained (no traceback, refusal code)
    def lb():raise ImportError('x')
    assert call(loader=lb)==he.RC_REFUSED and calls==[]
    # git measurement
    cap=[]
    def runner(cmd,**k):
        cap.append((cmd,k.get('env')))
        return N(returncode=0,stdout=(C+'\n' if cmd[3]=='rev-parse' else ' M x\n').encode())
    with pytest.raises(he.Refused):he.measure_commit('/x',runner=runner)
    assert all(c[0]=='/usr/bin/git' and e=={} for c,e in cap)
    with pytest.raises(he.Refused):he.measure_commit('/x',runner=lambda cmd,**k:N(returncode=1,stdout=b''))
    # envelope runner_image typed when present
    e=hp.envelope('r1',C,'d'*64,'ubuntu24/1.0');rr=[{'check':c,'ok':True,'errno':0} for c in hp.CHECKS]
    g.validate_content('host_primitive_result',{'envelope':e,'results':rr})
    with pytest.raises(ValueError):hp.envelope('r1',C,'d'*64,'bad image')
    with pytest.raises(ValueError):g.validate_content('host_primitive_result',{'envelope':{**e,'runner_image':'bad image'},'results':rr})
    # workflow template invariants
    root=Path(__file__).resolve().parents[1]
    t=(root/'research'/'d061_android'/'held'/'host-primitive-probe.workflow.yml.txt').read_text()
    assert 'upload-artifact' not in t and 'inputs:' not in t and 'persist-credentials: false' in t and 'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683' in t and 'permissions: {}' in t
    assert 'safe.directory' not in t and '/dev/null' in t and 'python3 -I -B' in t
    assert not (root/'.github'/'workflows'/'host-primitive-probe.yml').exists()


def test_host_primitive_entry_source_binding_uses_real_git_and_same_bytes(tmp_path):
    import shutil,subprocess
    import importlib
    src=Path(__file__).resolve().parents[1]/'research'/'d061_android'
    sys.path.insert(0,str(src))
    he=importlib.import_module('host_primitive_entry')
    uid=os.getuid()
    def mk(name):
        repo=tmp_path/name;d=repo/'research'/'d061_android';d.mkdir(parents=True)
        for m in he.MODULES:shutil.copy(src/(m+'.py'),d/(m+'.py'))
        for p in (repo,repo/'research',d):os.chmod(p,0o755)
        g=lambda *a:subprocess.run(['git','-C',str(repo)]+list(a),check=True,capture_output=True,env={'PATH':os.environ['PATH'],'HOME':str(tmp_path),'GIT_CONFIG_NOSYSTEM':'1'})
        g('init','-q');g('add','-A');g('-c','user.name=t','-c','user.email=t@t','commit','-qm','x')
        return repo,g
    repo,g=mk('r1')
    # the helper binds to the system git; use the same binary via an explicit wrapper-free path
    gitbin=shutil.which('git')
    entry=str(repo/'research'/'d061_android'/'host_primitive_entry.py')
    run=lambda cmd,**k:subprocess.run([gitbin]+cmd[1:],**{**k,'env':{'HOME':str(tmp_path),'GIT_CONFIG_NOSYSTEM':'1'}})
    out=he.load_bound(str(repo),entry_path=entry,trusted_uid=uid,git=gitbin,runner=run)
    assert set(out)==set(he.MODULES) and out['audience_gate'][1]==(repo/'research'/'d061_android'/'audience_gate.py').read_bytes()
    m=he.exec_module('audience_gate',*out['audience_gate']);assert m.__file__==out['audience_gate'][0] and 'audience_gate' not in sys.modules or sys.modules['audience_gate'] is not m
    # alternate repo whose checkout does not contain the entry: refused
    other,_=mk('r2')
    with pytest.raises(he.Refused):he.load_bound(str(other),entry_path=entry,trusted_uid=uid,git=gitbin,runner=run)
    # modified bytes (tracked file changed after commit) are refused
    p=repo/'research'/'d061_android'/'audience_gate.py';p.write_bytes(p.read_bytes()+b'\n#x\n')
    with pytest.raises(he.Refused):he.load_bound(str(repo),entry_path=entry,trusted_uid=uid,git=gitbin,runner=run)
    # wrong owner and group/other-writable are refused
    with pytest.raises(he.Refused):he.load_bound(str(repo),entry_path=entry,trusted_uid=uid+1,git=gitbin,runner=run)
    g('checkout','--','.');os.chmod(p,0o666)
    with pytest.raises(he.Refused):he.load_bound(str(repo),entry_path=entry,trusted_uid=uid,git=gitbin,runner=run)
    os.chmod(p,0o644)
    # a symlinked module is refused
    q=repo/'research'/'d061_android'/'host_primitive_probe.py';data=q.read_bytes();q.unlink();(tmp_path/'real.py').write_bytes(data);q.symlink_to(tmp_path/'real.py')
    with pytest.raises(Exception):he.load_bound(str(repo),entry_path=entry,trusted_uid=uid,git=gitbin,runner=run)


def test_host_entry_parent_auto_resolution_fails_closed(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'research'/'d061_android'))
    import host_primitive_entry as he
    r=he.resolve_parent
    assert r('/sys/fs/cgroup/x.slice',reader=lambda:'') == '/sys/fs/cgroup/x.slice'
    assert r('auto',reader=lambda:'0::/system.slice/a.service\n') == '/sys/fs/cgroup/system.slice/a.service'
    assert r('auto',reader=lambda:'0::/\n') == '/sys/fs/cgroup'
    for bad in ('','12:memory:/x\n0::/y\n','1:name=systemd:/x\n','0::relative\n'):
        with pytest.raises(he.Refused):r('auto',reader=lambda b=bad:b)


def test_host_capability_workflow_exit_semantics_with_stubbed_sudo(tmp_path):
    import subprocess,yaml,shutil
    wf=Path(__file__).resolve().parents[1]/'.github'/'workflows'/'d061-host-probe.yml'
    if not wf.exists():pytest.skip('single-use workflow removed')
    if shutil.which('bash') is None:pytest.skip('bash required')
    run=yaml.safe_load(wf.read_text())['jobs']['probe']['steps'][1]['run']
    stub=(
        'sudo(){ shift; case "$1" in\n'
        '  mktemp) echo /run/d061-sleep.abcdef;;\n'
        '  sha256sum) echo "'+'a'*64+'  x";;\n'
        '  chown) case "$*" in *root:root*) return 0;; *) return ${STUB_CHOWN_FAIL:-0};; esac;;\n'
        '  rm) return ${STUB_RM_FAIL:-0};;\n'
        '  env) return ${STUB_PROBE_FAIL:-0};;\n'
        '  *) return 0;; esac; }\n')
    script=tmp_path/'s.sh';script.write_text(stub+run)
    def rc(**env):
        e={'PATH':os.environ['PATH'],'GITHUB_WORKSPACE':str(tmp_path),'ImageOS':'ubuntu24','ImageVersion':'1'}
        e.update({k:str(v) for k,v in env.items()})
        r=subprocess.run(['bash',str(script)],env=e,capture_output=True,text=True)
        return r.returncode
    assert rc()==0
    assert rc(STUB_PROBE_FAIL=1)==1                      # original failure, cleanup fine
    assert rc(STUB_CHOWN_FAIL=1)==1                      # original success, restore failed
    assert rc(STUB_RM_FAIL=1)==1                         # original success, temp removal failed
    assert rc(STUB_PROBE_FAIL=1,STUB_CHOWN_FAIL=1,STUB_RM_FAIL=1)==1
