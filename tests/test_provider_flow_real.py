"""Actual hand-built bytecode through parser/detector; no model/OCI/device."""
import importlib.util
from pathlib import Path
from io import BytesIO
from zipfile import ZipFile,ZipInfo,ZIP_DEFLATED


def fixture_apk(*, caller_controlled=True):
    root=Path(__file__).parent
    spec=importlib.util.spec_from_file_location('provider_fixture',root/'fixtures/dex/build_provider_flow_dex.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    import sys
    if str(root) not in sys.path:sys.path.insert(0,str(root))
    from _axml import El,encode,ANDROID_NS as A,TYPE_STRING as S,TYPE_INT_BOOLEAN as B
    manifest=El('manifest',attrs=[('','package',S,'com.example.demo')],children=[El('application',children=[
        El('provider',attrs=[(A,'name',S,'.NotesProvider'),(A,'authorities',S,'com.example.demo.notes'),(A,'exported',B,True)])])])
    out=BytesIO()
    with ZipFile(out,'w') as z:
        for name,data in [('AndroidManifest.xml',encode(manifest)),('classes.dex',m.build(caller_controlled=caller_controlled))]:
            info=ZipInfo(name,date_time=(2020,1,1,0,0,0));info.compress_type=ZIP_DEFLATED
            info.external_attr=0o100644<<16;z.writestr(info,data)
    return out.getvalue()


def test_actual_provider_bytecode_yields_read_flow():
    from mobius.adapters.android_manifest import parse_apk
    from mobius.adapters.flow_adapt import adapt_code
    from mobius.core.providers import detect_provider_exposures
    raw=fixture_apk();assert raw==fixture_apk()
    surface=parse_apk(raw)
    methods,registers,supers,tries,ledger,origins=adapt_code(raw,app_package=surface.package_name)
    exposures=detect_provider_exposures(surface,methods,registers,supers,tries)
    assert len(exposures)==1
    read=next(o for o in exposures[0].operations if o.operation=='read')
    assert read.sink_flows,read
    assert all(f.method.startswith('com.example.demo.NotesProvider->query(') for f in read.sink_flows)
    assert all('rawQuery' in f.detail for f in read.sink_flows)


def test_constant_query_variant_is_a_real_bytecode_negative_control():
    from mobius.adapters.android_manifest import parse_apk
    from mobius.adapters.flow_adapt import adapt_code
    from mobius.core.providers import detect_provider_exposures
    raw=fixture_apk(caller_controlled=False)
    surface=parse_apk(raw)
    methods,registers,supers,tries,ledger,origins=adapt_code(raw,app_package=surface.package_name)
    exposures=detect_provider_exposures(surface,methods,registers,supers,tries)
    read=next(o for o in exposures[0].operations if o.operation=='read')
    assert not read.sink_flows
    assert read.coverage_complete is True


def test_real_provider_analysis_persists_rich_inference_not_runtime_fact(session,store,future_iso):
    from mobius.services.intake import IntakeService
    from mobius.services.recon import ReconService
    from mobius.services.provider_analysis import ProviderAnalysisService
    from mobius.adapters.models import ObservationRow
    from sqlalchemy import select
    intake=IntakeService(session,store)
    app,_=intake.create_application(fixture_apk(),'provider-static.apk',uploaded_by='analyst-1')
    auth=intake.create_authorization(apk_sha256=app.sha256,target_package='com.example.demo',
        scope_text='Static synthetic provider bytecode only; not installable or executable.',
        statement='Synthetic unit test',max_intensity=0,granted_by='analyst-1',expires_at=future_iso)
    scan=intake.create_investigation(application_id=app.id,authorization_id=auth.id,
        objective='Real bytecode source-level evidence test',intensity=0,created_by='analyst-1')
    intake.start(scan.id)
    ReconService(session,store).run(scan.id)
    ProviderAnalysisService(session,store).run(scan.id,validated_by='analyst-1')
    rows=list(session.execute(select(ObservationRow).where(ObservationRow.investigation_id==scan.id,
        ObservationRow.agent=='SPECTRE',ObservationRow.kind=='inference')).scalars())
    assert len(rows)==1
    assert rows[0].attributes['operation']=='read'
    assert rows[0].attributes['method_references'] and rows[0].evidence_refs
    assert 'NOT runtime or exploitability proof' in rows[0].statement
    assert rows[0].confidence<1
    from mobius.services.evidence_package import EvidencePackageBuilder
    package=EvidencePackageBuilder(session,store=store).build(scan.id)
    assert rows[0].id in {o['id'] for o in package.observations}
    assert package.method_references and package.sink_references


def test_dex_header_integrity_and_query_instruction_operands():
    import hashlib,struct,zlib
    from androguard.core.dex import DEX
    with ZipFile(BytesIO(fixture_apk())) as z:raw=z.read('classes.dex')
    assert raw[12:32]==hashlib.sha1(raw[32:]).digest()
    assert struct.unpack('<I',raw[8:12])[0]==zlib.adler32(raw[12:]) & 0xffffffff
    vm=DEX(raw)
    cls=next(c for c in vm.get_classes() if c.get_name()=='Lcom/example/demo/NotesProvider;')
    query=next(m for m in cls.get_methods() if m.get_name()=='query')
    assert query.get_access_flags()==1 # instance virtual method, NOT static
    assert query.get_code().get_registers_size()==8
    assert query.get_code().get_ins_size()==6 # this + five provider arguments
    instructions=list(query.get_instructions())
    assert [i.get_name() for i in instructions]==['const/4','invoke-virtual','move-result-object','return-object']
    assert 'rawQuery' in instructions[1].get_output()
    # register5 is parameter3 (selection); source comes from actual method arguments.
    assert instructions[1].get_output().startswith('v0, v5, v6,')


def test_negative_helper_bytecode_is_constant_not_a_disconnected_name_check():
    from androguard.core.dex import DEX
    with ZipFile(BytesIO(fixture_apk())) as z:vm=DEX(z.read('classes.dex'))
    cls=next(c for c in vm.get_classes() if c.get_name()=='Lcom/example/demo/NotesProvider;')
    helper=next(m for m in cls.get_methods() if m.get_name()=='negative')
    instructions=list(helper.get_instructions())
    assert [i.get_name() for i in instructions]==['const/4','const-string','invoke-virtual','move-result-object','return-object']
    assert 'SELECT 1' in instructions[1].get_output()
    assert instructions[2].get_output().startswith('v0, v1, v6,')
