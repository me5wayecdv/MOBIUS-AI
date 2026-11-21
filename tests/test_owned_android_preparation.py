"""Pure source/metadata guards, no SDK/APK/emulator/build/network execution."""
from pathlib import Path
import ast
import importlib.util
import json
import xml.etree.ElementTree as E

ROOT=Path(__file__).parents[1]/'research/d061_android'


def test_owned_source_and_build_are_held_without_workflow():
    for name,flags in [('profile.py',['APPROVED_FOR_BUILD','APPROVED_FOR_EXECUTION']),('build_owned.py',['APPROVED_FOR_BUILD']),('namespace_supervisor.py',['APPROVED_FOR_EXECUTION']),('emulator_scope.py',['APPROVED_FOR_EXECUTION'])]:
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
