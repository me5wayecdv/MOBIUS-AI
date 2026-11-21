"""Pure source/metadata guards, no SDK/APK/emulator/build/network execution."""
from pathlib import Path
import ast
import importlib.util
import json
import xml.etree.ElementTree as E

ROOT=Path(__file__).parents[1]/'research/d061_android'


def test_owned_source_and_build_are_held_without_workflow():
    for name,flags in [('profile.py',['APPROVED_FOR_BUILD','APPROVED_FOR_EXECUTION']),('build_owned.py',['APPROVED_FOR_BUILD']),('namespace_supervisor.py',['APPROVED_FOR_EXECUTION']),('emulator_scope.py',['APPROVED_FOR_EXECUTION']),('owned_product_setup.py',['APPROVED_FOR_EXECUTION']),('owned_absence.py',['APPROVED_FOR_EXECUTION'])]:
        tree=ast.parse((ROOT/name).read_text())
        values={target.id:node.value.value for node in tree.body if isinstance(node,ast.Assign) and isinstance(node.value,ast.Constant)
            for target in node.targets if isinstance(target,ast.Name)}
        assert all(values[x] is False for x in flags)
    assert not list((ROOT.parents[1]/'.github/workflows').glob('*owned*android*'))


def test_app_trust_and_action_source_has_fixed_local_scope():
    manifest=E.parse(ROOT/'app/AndroidManifest.xml').getroot()
    assert manifest.attrib['package']=='org.mobius.ownedfixture'
    config=E.parse(ROOT/'app/res/xml/network_security_config.xml').getroot()
    assert config.find('base-config').attrib['cleartextTrafficPermitted']=='false'
    assert [x.attrib['src'] for x in config.findall('.//certificates')]==['@raw/fixture_proxy_ca']
    source=(ROOT/'app/src/org/mobius/ownedfixture/FixtureActivity.java').read_text()
    assert 'setEndpointIdentificationAlgorithm("HTTPS")' in source
    assert 'this-run-public-proxy-ca-only' in source
    assert 'new InetSocketAddress("127.0.0.1", PROXY_PORT)' in source
    assert 'setDefaultSSLSocketFactory' not in source
    assert not (ROOT/'app/res/raw').exists()


def test_toolchain_archive_bytes_do_not_claim_runtime_closure():
    data=json.loads((ROOT/'toolchain-candidates.json').read_text())
    assert data['status']=='HELD_ARCHIVE_BYTES_VERIFIED_NOT_RUNTIME_CLOSURE'
    assert all(len(x['archive_sha256'])==64 and x['archive_downloaded'] and not x['archive_executed'] for x in data['packages'])
    assert data['jdk']['archive_sha256']==data['jdk']['official_sha256']
    assert data['jdk']['archive_executed'] is False


def test_fixed_adb_source_is_held_and_reverse_validator_closed(monkeypatch):
    import sys
    import pytest
    monkeypatch.syspath_prepend(str(ROOT))
    import adb_scope
    assert adb_scope.APPROVED_FOR_EXECUTION is False
    assert adb_scope.validate_reverse_list('',expected=False)==[]
    assert adb_scope.validate_reverse_list('(reverse) tcp:18080 tcp:18080\n',expected=True)
    for text in ['emulator-5554 tcp:18080 tcp:18080','(reverse) tcp:18080 tcp:18081','emulator-5554 tcp:0 tcp:18080',
                 'emulator-5554 tcp:18080 tcp:18080\nemulator-5554 tcp:22 tcp:22']:
        with pytest.raises(ValueError):adb_scope.validate_reverse_list(text,expected=True)


def test_namespace_closure_is_exact_and_cannot_bind_host_tree(monkeypatch):
    import pytest
    monkeypatch.syspath_prepend(str(ROOT))
    import namespace_supervisor as ns
    assert ns.APPROVED_FOR_EXECUTION is False
    rows=[{'source':name.lstrip('/'),'destination':name,'sha256':'a'*64,'size':1,'mode':0o555}
        for name in (ns.ENTRYPOINT,'/runtime/bin/python','/usr/bin/setpriv')]
    lock={'status':'EXACT_REVIEWED_ANDROID_CLOSURE','files':rows}
    assert ns.validate_manifest(lock)==rows
    for bad in ['/home/fixture/key','/run/docker.sock','/dev/kvm','/usr/../home/key','/usr//bin/x']:
        with pytest.raises(ValueError):ns.validate_manifest(dict(lock,files=rows+[dict(rows[0],destination=bad)]))
    with pytest.raises(ValueError):ns.validate_manifest(dict(lock,files=rows+[rows[0]]))
    with pytest.raises(ValueError):ns.validate_manifest(dict(lock,status='METADATA_ONLY'))
    with pytest.raises(ValueError):ns.validate_manifest(dict(lock,files=rows[:2]))


def test_app_prepare_does_not_send_before_observed_process_commit():
    source=(ROOT/'app/src/org/mobius/ownedfixture/FixtureActivity.java').read_text()
    prepare=source[source.index('@Override public void onCreate'):source.index('@Override protected void onNewIntent')]
    assert 'exchange(' not in prepare and 'new Socket(' not in prepare
    assert '"prepare".equals(phase)' in prepare
    assert 'preparedNonce.equals(nonce) || started' in source
    assert 'OWNED_FIXTURE_SOCKET nonce=' in source
    manifest=E.parse(ROOT/'app/AndroidManifest.xml').getroot()
    activity=manifest.find('application/activity')
    assert activity.attrib['{http://schemas.android.com/apk/res/android}launchMode']=='singleTask'


def test_archive_inventory_rejects_path_types_and_retains_no_execution(tmp_path,monkeypatch):
    import zipfile
    import pytest
    monkeypatch.syspath_prepend(str(ROOT))
    import archive_inventory as ai
    good=tmp_path/'good.zip'
    with zipfile.ZipFile(good,'w') as archive:archive.writestr('fixture/source.txt',b'owned source')
    result=ai.inventory(good)
    assert result['member_count']==1
    assert result['archive_extracted'] is result['package_code_executed'] is result['runtime_closure_resolved'] is False
    for index,name in enumerate(('../escape','/absolute','a/../b','a//b','a\\b')):
        bad=tmp_path/(str(index)+'.zip')
        with zipfile.ZipFile(bad,'w') as archive:archive.writestr(name,b'x')
        with pytest.raises(ValueError):ai.inventory(bad)


def test_emulator_listeners_refuse_wildcard_or_implicit_grpc(monkeypatch):
    import pytest
    monkeypatch.syspath_prepend(str(ROOT))
    import emulator_scope as es
    assert es.APPROVED_FOR_EXECUTION is False
    rows=[{'state':'0A','family':'tcp','address':'0100007F','port':p} for p in (5037,5554,5555)]
    assert es.validate_listeners(rows)
    for bad in (dict(rows[0],port=8554),dict(rows[0],address='00000000')):
        with pytest.raises(ValueError):es.validate_listeners(rows+[bad])
    with pytest.raises(ValueError):es.validate_listeners(rows[1:])


def test_unregistered_product_contract_is_disabled_and_rejects_missing_originals(monkeypatch):
    from dataclasses import asdict,replace
    import pytest
    monkeypatch.syspath_prepend(str(ROOT))
    from profile import OwnedAppRequest
    from product_contract import OwnedAppAdapter,OwnedAppOutput
    request=OwnedAppRequest(apk_sha256='a'*64,public_ca_sha256='b'*64,plan_sha256='c'*64,
        authorization_id='ath_unit',approval_id='apr_unit',investigation_id='scn_unit',plan_id='poc_unit',nonce='d'*32)
    request.validate()
    with pytest.raises(RuntimeError):OwnedAppAdapter().execute(request)
    binding=json.dumps(asdict(request)).encode()
    failure=OwnedAppOutput(request,{'binding.json':binding,'host-failure.json':b'{"code":"host_timeout"}'},
        ('unit-refusal-only',),'failed','host_timeout')
    OwnedAppAdapter.validate(request,failure)
    with pytest.raises(ValueError):OwnedAppAdapter.validate(request,replace(failure,status='passed',failure_code=None))
    with pytest.raises(ValueError):OwnedAppAdapter.validate(request,replace(failure,artifacts={'binding.json':binding}))
    with pytest.raises(ValueError):OwnedAppAdapter.validate(request,replace(failure,failure_code='host_not_executed'))
    with pytest.raises(ValueError):OwnedAppAdapter.validate(request,replace(failure,artifacts={**failure.artifacts,'arbitrary.txt':b'x'}))
    with pytest.raises(ValueError):OwnedAppAdapter.validate(request,replace(failure,binding=replace(request,nonce='e'*32)))


def test_owned_absence_refuses_missing_postlaunch_evidence(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT))
    import owned_absence
    root=tmp_path/'not-created'
    assert owned_absence.inspect(root,require_launched=False)['complete']
    result=owned_absence.inspect(root,require_launched=True)
    assert not result['complete'] and result['missing_records']==['workflow-root']
    root.mkdir()
    result=owned_absence.inspect(root,require_launched=True,proc=tmp_path/'empty-proc')
    assert not result['complete'] and not result['stage_required_records_complete']
    assert 'namespace-setup.json' in result['missing_records']
    assert 'work/evidence/owned-app-launch.json' in result['missing_records']


def test_handoff_closed_commit_cannot_change_actual_apk_or_add_instructions(monkeypatch):
    from dataclasses import asdict,replace
    import pytest
    monkeypatch.syspath_prepend(str(ROOT))
    from handoff_protocol import make_commit,validate_commit,canonical,digest
    from profile import OwnedAppRequest
    request=OwnedAppRequest(apk_sha256='a'*64,public_ca_sha256='b'*64,plan_sha256='c'*64,
        authorization_id='ath_unit',approval_id='apr_unit',investigation_id='scn_unit',plan_id='poc_unit',nonce='d'*32)
    ready={'version':'owned-android-ready/1','profile':request.profile,'package':request.package,
        'apk_sha256':request.apk_sha256,'public_ca_sha256':request.public_ca_sha256,'build_json_sha256':'e'*64,
        'source_manifest_sha256':'f'*64,'original_count':0,'origin_receipt_count':0,'apk_installed':False,'apk_launched':False}
    commit=make_commit(request,ready_metadata=ready,ready_metadata_sha256=digest(canonical(ready)))
    assert validate_commit(commit,ready_metadata=ready,expected_request=request)==request
    with pytest.raises(ValueError):validate_commit({**commit,'argv':['unrelated']},ready_metadata=ready,expected_request=request)
    with pytest.raises(ValueError):validate_commit(commit,ready_metadata=ready,expected_request=replace(request,nonce='e'*32))
    with pytest.raises(ValueError):make_commit(replace(request,apk_sha256='e'*64),ready_metadata=ready,
        ready_metadata_sha256=digest(canonical(ready)))
    with pytest.raises(ValueError):make_commit(request,ready_metadata=ready,ready_metadata_sha256='f'*64)


def test_handoff_stage_budgets_and_no_retry_after_failure(monkeypatch):
    import pytest
    monkeypatch.syspath_prepend(str(ROOT))
    from handoff_protocol import LifecycleState
    state=LifecycleState()
    with pytest.raises(ValueError):state.advance('committed',seconds=1)
    with pytest.raises(ValueError):state.advance('provisioned',seconds=241)
    with pytest.raises(ValueError):state.advance('provisioned',seconds=10,originals=1)
    assert state.advance('provisioned',seconds=240)=='ready'
    with pytest.raises(ValueError):state.advance('committed',seconds=31)
    assert state.advance('committed',seconds=30)=='committed'
    with pytest.raises(ValueError):state.advance('operation_returned',seconds=61)
    assert state.advance('operation_returned',seconds=60,originals=1,receipts=2)=='operation_returned'
    assert state.advance('runtime_absent',seconds=60)=='runtime_absent'
    assert state.advance('collected',seconds=10)=='collected'
    failed=LifecycleState();failed.fail('TimeoutError')
    with pytest.raises(ValueError):failed.advance('provisioned',seconds=1)


def test_handoff_provisioning_refuses_preapproval_traffic_and_extra_fields(monkeypatch):
    import pytest
    monkeypatch.syspath_prepend(str(ROOT))
    from handoff_protocol import validate_provisioned,READY_VERSION
    metadata={'version':READY_VERSION,'profile':'owned-android-fixed-loopback-v1','package':'org.mobius.ownedfixture',
        'apk_sha256':'a'*64,'public_ca_sha256':'b'*64,'build_json_sha256':'c'*64,'source_manifest_sha256':'d'*64,
        'original_count':0,'origin_receipt_count':0,'apk_installed':False,'apk_launched':False}
    for key,value in [('original_count',1),('apk_installed',True),('origin_receipt_count',True),('extra','instructions')]:
        with pytest.raises(ValueError):validate_provisioned({**metadata,key:value},apk=b'unit-only',public_ca_der=b'unit-only',
            build_json=b'{}',expected_source_manifest_sha256='d'*64)
