"""HELD disposable API setup, with explicitly fixture-only historical imports.

Never changes the original archive, expired authorization or genuine case.
No model call, new model claim, API import coverage or owner approval claim.
"""
import argparse
from datetime import datetime,timedelta,timezone
import hashlib
import json
from pathlib import Path
import zipfile

APPROVED_FOR_EXECUTION = False
SOURCE_ARCHIVE_SHA256='2e123119845bf6da37067dd9b8eed9eb6d92335716e4e477c4941abf3f3ccb76'
SOURCE_CASE='scn_01M7Y5NADSTR1GK2CN0E05YBPV'
SOURCE_DECISION='dec_01M7Y5PNXPKD48F27WTKG7WX5X'
APK_SHA256='d6792d6634a033f048f935f1269179d3c27b859c4c34b1e9e5b008a88375efd9'
PACKAGE='infosecadventures.allsafe'
ACTOR='ci-native-local-fixture'


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def digest(value):return hashlib.sha256(value).hexdigest()


def verify_archive(archive):
    # Archived artifact identity is fixed, not caller-supplied expected hash.
    if digest(archive.read_bytes())!=SOURCE_ARCHIVE_SHA256:raise ValueError('historical source archive digest mismatch')
    with zipfile.ZipFile(archive) as z:
        names=z.namelist()
        if len(names)!=len(set(names)):raise ValueError('duplicate archive entry')
        for info in z.infolist():
            p=Path(info.filename)
            if p.is_absolute() or '..' in p.parts or '\\' in info.filename or info.file_size>220*1024*1024:
                raise ValueError('unsafe historical source entry')
            if (info.external_attr>>16)&0o170000==0o120000:raise ValueError('source symlink')
    return SOURCE_ARCHIVE_SHA256


def build_plan(scan_id,authorization_id,hypothesis_ids):
    from mobius.core.schemas import PoCTestPlan
    return PoCTestPlan(investigation_id=scan_id,authorization_id=authorization_id,target_sha256=APK_SHA256,
        target_package=PACKAGE,target_kind='native_local_fixture',hypothesis_ids=tuple(hypothesis_ids),
        expected_outcome='Controlled stdlib loopback capture/request replay, NOT hypothesis validation or APK traffic.',
        safety_class='non_destructive',requires_approval=True,max_duration_seconds=130,max_output_bytes=1048576,
        steps=[{'action':'capture_native_local_fixture_v1','target_ref':'trusted-local-positive-v1','timeout_seconds':60}],
        cleanup_steps=[{'action':'stop_native_local_fixture','target_ref':'trusted-local-positive-v1','timeout_seconds':60}])


def prepare(context,client,source,output):
    from sqlalchemy import select
    from mobius.adapters.db import make_engine,make_session_factory
    from mobius.adapters.events import SqlEventStore,utcnow
    from mobius.adapters.models import DecisionRow,EvidenceRow,HypothesisRow,InvestigationRow,ObservationRow
    from mobius.core.enums import EvidenceKind
    from mobius.core.ids import IdPrefix,new_id
    from mobius.core.schemas import PoCTestPlan
    from mobius.services.evidence import EvidenceService
    from mobius.services.artifacts import ArtifactStore
    source_db=source/'mobius.db'
    before=digest(source_db.read_bytes())
    factory=make_session_factory(make_engine('sqlite+pysqlite:///file:'+str(source_db)+'?mode=ro&uri=true'))
    # sqlite read-only URI via engine dialect is verified by connection below.
    def api(path,body):
        response=client.post('/api/v1'+path,json=body,headers={'X-Analyst-Id':ACTOR})
        if response.status_code not in (200,201):raise RuntimeError('API setup failed:'+path+':'+str(response.status_code))
        return response.json()
    with factory() as old:
        case=old.get(InvestigationRow,SOURCE_CASE)
        decision=old.get(DecisionRow,SOURCE_DECISION)
        if case is None or decision is None or decision.investigation_id!=case.id or decision.provider!='opencode':
            raise ValueError('genuine source case/decision absent')
        hypotheses=old.execute(select(HypothesisRow).where(HypothesisRow.investigation_id==SOURCE_CASE).order_by(HypothesisRow.id)).scalars().all()
        if len(hypotheses)!=5 or len(decision.output_json['hypotheses'])!=5:raise ValueError('source five-hypothesis sample differs')
        serialized=lambda row:{c.name:getattr(row,c.name) for c in row.__table__.columns}
        source_manifest={'archive_sha256':SOURCE_ARCHIVE_SHA256,'case_id':case.id,'decision_id':decision.id,
            'decision_content_sha256':digest(canonical(serialized(decision))),
            'hypotheses':[],'fixture_only_import':True,'current_model_call':False,
            'owner_approval':False,'source_db_sha256':before}
        # New authorization and case use real API. Never rebind old case/grants.
        expires=(datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat().replace('+00:00','Z')
        auth=api('/authorizations',{'apk_sha256':APK_SHA256,'target_package':PACKAGE,
            'scope_text':'DISPOSABLE INTEGRATION TEST ACTOR: anchor public Allsafe only. Local stdlib loopback fixture native capture/request replay. No APK execution, emulator, external target or production permission.',
            'statement':'Synthetic disposable CI test authorization, NOT owner consent or approval.',
            'max_intensity':2,'expires_at':expires})
        # Existing source app metadata/bytes are not imported as an owned app.
        # The public pinned APK is uploaded through the product's normal endpoint.
        original_store=ArtifactStore(source/'artifacts')
        from mobius.adapters.models import ApplicationRow
        app=old.get(ApplicationRow,case.application_id)
        apk=original_store.get(app.artifact_key)
        if digest(apk)!=APK_SHA256:raise ValueError('source public APK digest')
        response=client.post('/api/v1/applications',headers={'X-Analyst-Id':ACTOR},
            files={'file':('public-allsafe.apk',apk,'application/vnd.android.package-archive')})
        if response.status_code not in (200,201):raise RuntimeError('public anchor upload failed')
        newcase=api('/scans',{'application_id':response.json()['id'],'authorization_id':auth['id'],
            'objective':'DISPOSABLE local native fixture integration. Imported genuine historical model hypotheses, no current model generation or APK execution.',
            'intensity':2})
        scan_id=newcase['id']
        # Fixture-only database import. No claim that the product exposes this API.
        with context.session() as fresh:
            observations=old.execute(select(ObservationRow).where(ObservationRow.investigation_id==SOURCE_CASE)).scalars().all()
            required_ids={ref for h in hypotheses for ref in h.derived_from}
            observations=[x for x in observations if x.id in required_ids]
            if {x.id for x in observations}!=required_ids:raise ValueError('historical observation provenance absent')
            needed_evidence={ref for x in observations for ref in x.evidence_refs}
            evidence_map={}
            for item in old.execute(select(EvidenceRow).where(EvidenceRow.investigation_id==SOURCE_CASE,EvidenceRow.id.in_(needed_evidence))).scalars():
                content=original_store.get(item.object_key)
                if digest(content)!=item.sha256 or len(content)!=item.byte_size:raise ValueError('historical evidence differs')
                clone=EvidenceService(fresh,context.store).record(investigation_id=scan_id,
                    kind=EvidenceKind(item.kind),content=content,
                    summary='FIXTURE IMPORT historical source '+SOURCE_CASE+'/'+item.id+'; '+item.summary,
                    produced_by='FIXTURE_IMPORT',truncated=item.truncated)
                evidence_map[item.id]=clone.id
            observation_map={}
            if set(evidence_map)!=needed_evidence:raise ValueError('historical evidence provenance absent')
            for item in observations:
                values=serialized(item)
                original=values['id']
                values.update(id=new_id(IdPrefix.OBSERVATION),investigation_id=scan_id,agent='FIXTURE_IMPORT',
                    evidence_refs=[evidence_map[x] for x in values['evidence_refs']],
                    attributes={**values['attributes'],'fixture_import':{'case':SOURCE_CASE,'observation':original}})
                fresh.add(ObservationRow(**values));observation_map[original]=values['id']
            fresh.flush()
            new_ids=[]
            for item in hypotheses:
                values=serialized(item)
                original_id=values['id']
                source_hyp=digest(canonical(values))
                # Claim text must be an unchanged genuine provider-output claim.
                if values['claim'] not in {x['claim'] for x in decision.output_json['hypotheses']}:
                    raise ValueError('historical hypothesis not in original decision output')
                if values['parent_id'] is not None:raise ValueError('unexpected nested historical source')
                values.update(id=new_id(IdPrefix.HYPOTHESIS),investigation_id=scan_id,
                    derived_from=[observation_map[x] for x in values['derived_from']],
                    satisfied_evidence=[],status='open')
                fresh.add(HypothesisRow(**values));new_ids.append(values['id'])
                source_manifest['hypotheses'].append({'original_id':original_id,'imported_id':values['id'],
                    'original_row_sha256':source_hyp,'claim_sha256':digest(values['claim'].encode())})
            fresh.flush()
            SqlEventStore(fresh).emit(scan_id,'historical_hypothesis_fixture_import',source_manifest,actor=ACTOR)
            fresh.commit()
        plan=build_plan(scan_id,auth['id'],new_ids)
        approval=api('/scans/'+scan_id+'/poc/approvals',{'plan':plan.model_dump(mode='json'),
            'justification':'DISPOSABLE TEST ACTOR grants this exact fixed local-only plan, not owner approval.',
            'risk_summary':'No APK execution, external target, model call, production changes or image publication.',
            'expires_at':expires})
        api('/scans/'+scan_id+'/poc/approvals/'+approval['id']+'/resolve',
            {'decision':'granted','note':'DISPOSABLE TEST ACTOR only, exact local fixture integration.'})
        plan=plan.model_copy(update={'approval_id':approval['id']})
    if digest(source_db.read_bytes())!=before:raise RuntimeError('historical source database changed')
    output.mkdir(exist_ok=False)
    (output/'approved-plan.json').write_bytes(canonical(plan.model_dump(mode='json')))
    (output/'fixture-provenance.json').write_bytes(canonical({**source_manifest,'new_case':scan_id,
        'new_authorization':auth['id'],'new_approval':approval['id'],'no_source_authority_transferred':True}))
    return plan


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD: exact disposable setup/workflow review required')
    p=argparse.ArgumentParser()
    p.add_argument('--historical-archive',type=Path,required=True)
    p.add_argument('--historical-root',type=Path,required=True)
    p.add_argument('--db',type=Path,required=True)
    p.add_argument('--artifacts',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    verify_archive(a.historical_archive)
    # Only unpack the hash-verified archive into a fresh root, never trust a
    # separately supplied extracted tree or overwrite historical source bytes.
    a.historical_root.mkdir(exist_ok=False)
    with zipfile.ZipFile(a.historical_archive) as z:z.extractall(a.historical_root)
    from fastapi.testclient import TestClient
    from mobius.api.app import create_app
    from mobius.api.config import Settings
    from mobius.api.deps import AppContext,set_context
    context=AppContext(Settings(db_url='sqlite+pysqlite:///'+str(a.db),artifact_root=a.artifacts,env='test'))
    class NoModelGateway:
        def __getattr__(self,name):raise RuntimeError('no model access permitted in disposable setup')
    context.model_gateway=NoModelGateway()
    set_context(context)
    try:
        with TestClient(create_app()) as client:prepare(context,client,a.historical_root,a.output)
    finally:set_context(None)

if __name__=='__main__':main()
