"""Offline classifier/hold tests only. No adb/emulator/tool download."""
import importlib.util
from pathlib import Path
import pytest
ROOT=Path(__file__).parents[1]/'research/owned_lab_runtime'
spec=importlib.util.spec_from_file_location('owned_lab_probe',ROOT/'probe.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def test_runtime_is_held_before_any_command(tmp_path):
    def refuse(*args,**kwargs):raise AssertionError('must not invoke adb')
    with pytest.raises(RuntimeError,match='HELD'):m.run('/usr/bin/adb','emulator-5554',tmp_path/'missing',invoke=refuse)


@pytest.mark.parametrize('text,rc,private,expected',[
 ('Row: 0 _id=1, body=MOBIUS_SYNTHETIC_LAB_ROW\n',0,False,'synthetic_row_read'),
 ('Row: 0 _id=1, body=unrelated',0,False,'unclassified'),
 ('Row: 0 _id=1, body=MOBIUS_SYNTHETIC_LAB_ROW',1,False,'unclassified'),
 ('Error: timeout',1,True,'unclassified'),
 ('Permission Denial: reading provider that is not exported',0,True,'permission_denied'),
 ('Permission Denial: not exported\nRow: 0',0,True,'unclassified'),
 ('x'*262145,0,False,'unclassified'),
])
def test_read_outcomes_are_narrow(text,rc,private,expected):
    assert m.classify(text,rc,private=private)==expected


def collector():
    spec=importlib.util.spec_from_file_location('owned_collector',ROOT/'collector.py')
    module=importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return module


def test_bounded_collector_captures_both_streams():
    import sys
    r=collector().collect([sys.executable,'-c','import sys;print("ok");print("err",file=sys.stderr)'])
    assert r.status=='completed' and r.returncode==0
    assert r.stdout=='ok\n' and r.stderr=='err\n'
    assert r.descendant_cleanup=='UNVERIFIED'


def test_collector_deadline_and_dual_pipe_overflow():
    import sys
    c=collector()
    r=c.collect([sys.executable,'-c','import time;time.sleep(10)'],timeout=.05)
    assert r.status=='timeout' and r.returncode is not None
    r=c.collect([sys.executable,'-c','import os;os.write(2,b"x"*10000)'],limit=100)
    assert r.status=='output_limit' and len(r.stdout)+len(r.stderr)<=100


def test_retained_owner_reaped_without_descendant_claim():
    import subprocess,sys
    spec=importlib.util.spec_from_file_location('owned_supervisor',ROOT/'supervisor.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)'],start_new_session=True)
    owner=module.RetainedChild(p)
    result=owner.close()
    assert result=={'owner_state':'reaped','descendants':'UNVERIFIED'}
    assert p.returncode is not None
    with pytest.raises(RuntimeError,match='HELD'):module.launch_emulator()


def test_tool_pins_are_literal_official_metadata_records():
    import json,re
    d=json.loads((ROOT/'toolchain-pins.json').read_text())
    assert {x['role'] for x in d['archives']}=={'emulator','platform-tools','system-image'}
    for row in d['archives']:
        assert row['url'].startswith('https://dl.google.com/android/repository/')
        assert re.fullmatch('[a-f0-9]{40}',row['sha1']) and row['size']>0


def test_already_reaped_owner_is_a_typed_refusal():
    import subprocess,sys
    spec=importlib.util.spec_from_file_location('owned_supervisor_reaped',ROOT/'supervisor.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    p=subprocess.Popen([sys.executable,'-c','pass'],start_new_session=True)
    p.wait()
    with pytest.raises(module.OwnershipUnavailable,match='already_reaped'):module.RetainedChild(p)
