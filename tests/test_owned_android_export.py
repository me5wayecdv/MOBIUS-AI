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
    m = pem.build([row], store.get, ready=_ready(apk), plan=_plan(apk), run={'plan_id': 'poc_A1', 'run_id': 'pcr_C3'}, report_sha256='0' * 64)
    owner = {'run_id': 'r1', 'provisioning_id': 'p1'}
    assert fe.object_rows(m, owner) == [{'sha256': sha(apk), 'bytes': len(apk)}]
    with pytest.raises(ValueError):
        fe.object_rows(m, {'run_id': 'other', 'provisioning_id': 'p1'})
    with pytest.raises(ValueError):
        fe.object_rows({**m, 'extra': 1}, owner)
    with pytest.raises(ValueError):
        fe.object_rows({**m, 'objects': [{'sha256': sha(b'z'), 'bytes': 1}]}, owner)  # APK absent


def test_manifest_refuses_cross_case_noncanonical_and_tampered_objects():
    apk = b'apk-bytes'
    good = NS(investigation_id='scn_B2', sha256=sha(apk), byte_size=len(apk), object_key='apk/%s/%s.apk' % (sha(apk)[:2], sha(apk)))
    kw = dict(ready=_ready(apk), plan=_plan(apk), run={'plan_id': 'poc_A1', 'run_id': 'pcr_C3'}, report_sha256='0' * 64)
    with pytest.raises(ValueError):
        pem.build([NS(**{**good.__dict__, 'investigation_id': 'scn_other'})], {sha(apk): apk}.get, **kw)
    with pytest.raises(ValueError):
        pem.build([NS(**{**good.__dict__, 'object_key': '../x'})], {sha(apk): apk}.get, **kw)
    with pytest.raises(ValueError):
        pem.build([good], {sha(apk): b'tampered'}.get, **kw)
    with pytest.raises(ValueError):
        pem.build([good], {sha(apk): apk}.get, **{**kw, 'run': {'plan_id': 'zzz', 'run_id': 'pcr_C3'}})


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
    session.commit()
    plan = NS(id='poc_A1', investigation_id=inv.id, target_sha256=app.sha256)
    m = pem.prepare(ctx, ready={'run_id': 'r1', 'provisioning_id': 'p1', 'apk_sha256': app.sha256}, plan=plan,
        run={'plan_id': 'poc_A1', 'run_id': 'pcr_C3'}, report_sha256='1' * 64)
    assert {o['sha256'] for o in m['objects']} == {sha(data), app.sha256}
    assert fe.object_rows(m, {'run_id': 'r1', 'provisioning_id': 'p1'})


def _wd():
    sys.path.insert(0, str(ROOT))
    return importlib.import_module('staging_watchdog')


def test_watchdog_held_and_kills_hung_child_and_oversize_output(tmp_path, monkeypatch):
    wd = _wd()
    assert wd.APPROVED_FOR_EXECUTION is False
    with pytest.raises(RuntimeError):
        wd.supervise(['true'], tmp_path)
    monkeypatch.setattr(wd, 'APPROVED_FOR_EXECUTION', True)
    monkeypatch.setattr(wd, 'POLL', 0.05)
    hang = [sys.executable, '-c', 'import time;time.sleep(60)']
    r = wd.supervise(hang, tmp_path, wall=0.3)
    assert r['killed_reason'] == 'wall_clock' and r['exit_code'] != 0
    grow = [sys.executable, '-c', 'import time,sys;open(sys.argv[1]+"/big","wb").write(b"x"*5000);time.sleep(60)', str(tmp_path)]
    r = wd.supervise(grow, tmp_path, wall=20, max_bytes=1000)
    assert r['killed_reason'] == 'output_bytes'
    ok = wd.supervise([sys.executable, '-c', 'pass'], tmp_path, wall=20)
    assert ok['exit_code'] == 0 and ok['killed_reason'] is None


def test_watchdog_refuses_symlink_and_file_ceiling(tmp_path):
    wd = _wd()
    (tmp_path / 'a').write_text('1')
    (tmp_path / 'b').write_text('1')
    with pytest.raises(ValueError):
        wd.usage(tmp_path, limit_files=1)
    os.symlink('/etc', tmp_path / 'l')
    with pytest.raises(ValueError):
        wd.usage(tmp_path)
