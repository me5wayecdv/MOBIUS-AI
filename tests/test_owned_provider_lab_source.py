"""Offline source-shape regressions only, not Java compilation or Android validation."""
from pathlib import Path
import xml.etree.ElementTree as ET
import subprocess

ROOT=Path(__file__).parents[1]/'labs'/'owned-provider'
A='{http://schemas.android.com/apk/res/android}'


def test_lab_has_exact_read_exposure_and_independent_private_control():
    root=ET.parse(ROOT/'AndroidManifest.xml').getroot()
    assert root.get('package')=='com.mobius.ownedlab'
    assert not root.findall('uses-permission')
    app=root.find('application')
    assert app.get(A+'allowBackup')=='false'
    assert app.get(A+'debuggable')=='false'
    assert app.get(A+'usesCleartextTraffic')=='false'
    assert [x.tag for x in app]==['provider','provider']
    providers={p.get(A+'name'):p for p in app}
    assert set(providers)=={'.NotesProvider','.PrivateProvider'}
    for name,authority,exported in [('.NotesProvider','notes','true'),('.PrivateProvider','private','false')]:
        p=providers[name]
        assert p.get(A+'authorities')=='com.mobius.ownedlab.'+authority
        assert p.get(A+'exported')==exported
        assert p.get(A+'grantUriPermissions')=='false'
        assert not list(p)


def test_build_script_is_syntactically_valid_and_refuses_missing_sdk(tmp_path):
    script=ROOT/'build-unsigned.sh'
    assert subprocess.run(['bash','-n',str(script)],capture_output=True).returncode==0
    result=subprocess.run(['bash',str(script)],env={'PATH':'/usr/bin:/bin','TMPDIR':str(tmp_path)},capture_output=True)
    assert result.returncode!=0 and b'ANDROID_JAR' in result.stderr
    assert list(tmp_path.iterdir())==[]


def test_lab_is_in_memory_read_only_and_has_real_initialization_source():
    source=(ROOT/'src/com/mobius/ownedlab/NotesProvider.java').read_text()
    assert 'SQLiteDatabase.create(null)' in source
    assert 'MOBIUS_SYNTHETIC_LAB_ROW' in source
    assert 'return database.query(' in source
    assert source.count('throw new UnsupportedOperationException("read-only")')==3
    assert 'database.close()' in source
    private=(ROOT/'src/com/mobius/ownedlab/PrivateProvider.java').read_text()
    assert 'extends NotesProvider' in private and 'super();' in private
