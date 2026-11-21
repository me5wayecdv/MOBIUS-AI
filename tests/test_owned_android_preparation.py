"""Pure source/metadata guards, no SDK/APK/emulator/build/network execution."""
from pathlib import Path
import ast
import importlib.util
import json
import xml.etree.ElementTree as E

ROOT=Path(__file__).parents[1]/'research/d061_android'


def test_owned_source_and_build_are_held_without_workflow():
    for name,flags in [('profile.py',['APPROVED_FOR_BUILD','APPROVED_FOR_EXECUTION']),('build_owned.py',['APPROVED_FOR_BUILD'])]:
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


def test_toolchain_candidates_honestly_unresolved():
    data=json.loads((ROOT/'toolchain-candidates.json').read_text())
    assert data['status']=='HELD_METADATA_ONLY_NOT_RESOLVED_LOCK'
    assert all(x['archive_sha256'] is None and not x['archive_downloaded_or_executed'] for x in data['packages'])
