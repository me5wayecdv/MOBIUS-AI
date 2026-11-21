"""HELD fresh owned-APK product setup, called only inside reviewed no-uplink jail.

Creates explicit disposable fixture data, never model output, vulnerability
findings, owner consent, historical imports, or real-user approvals. The actual
built APK and CA are prerequisites. No build/device/network execution here.
"""
from datetime import datetime,timedelta,timezone
import hashlib
import json
import os
from pathlib import Path

APPROVED_FOR_EXECUTION = False
ACTOR='ci-owned-android-fixture'
PACKAGE='org.mobius.ownedfixture'
PROFILE='owned-android-fixed-loopback-v1'


def prepare(context,client,*,apk,build_record,source_root,output):
    if not APPROVED_FOR_EXECUTION:raise RuntimeError('owned APK fixture setup HELD')
    if os.geteuid()==0:raise RuntimeError('contained unprivileged fixture setup required')
    from mobius.adapters.events import SqlEventStore,utcnow
    from mobius.adapters.models import HypothesisRow,ObservationRow
    from mobius.core.ids import IdPrefix,new_id
    from mobius.core.enums import EvidenceKind
    from mobius.core.schemas import PoCTestPlan
    from mobius.services.evidence import EvidenceService
    apk=Path(apk);source_root=Path(source_root);output=Path(output)
    if not apk.is_file() or apk.is_symlink() or apk.stat().st_size>4*1024**2:raise ValueError('bounded actual owned APK required')
    content=apk.read_bytes();digest=hashlib.sha256(content).hexdigest()
    if (build_record.get('tls_scenario','positive')!='positive'
        or build_record.get('embedded_public_ca_sha256',build_record.get('public_ca_sha256'))!=build_record.get('public_ca_sha256')
        or build_record.get('apk_sha256')!=digest or build_record.get('package')!=PACKAGE
        or build_record.get('actual_app_network_not_executed_by_build') is not True):
        raise ValueError('actual owned build/zero-app-traffic record required')
    ca=build_record['public_ca_sha256']
    headers={'X-Analyst-Id':ACTOR}
    def api(path,body):
        response=client.post('/api/v1'+path,json=body,headers=headers)
        if response.status_code not in (200,201):raise RuntimeError('owned fixture setup API failed '+path)
        return response.json()
    expires=(datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat().replace('+00:00','Z')
    auth=api('/authorizations',{'apk_sha256':digest,'target_package':PACKAGE,'max_intensity':0,'expires_at':expires,
        'scope_text':'DISPOSABLE INTEGRATION TEST: exact owned APK fixed loopback request/native replay only. No third-party, system CA edits, model or production action.',
        'statement':'Synthetic disposable CI test actor, NOT owner consent or approval.'})
    response=client.post('/api/v1/applications',headers=headers,files={
        'file':('owned-fixture.apk',content,'application/vnd.android.package-archive')})
    if response.status_code not in (200,201):raise RuntimeError('actual owned APK API upload failed')
    application=response.json()
    if application.get('sha256')!=digest:raise ValueError('uploaded owned APK digest changed')
    scan=api('/scans',{'application_id':application['id'],'authorization_id':auth['id'],'intensity':0,
        'objective':'DISPOSABLE owned-app integration: fixed original capture/replay. Fixture-only hypothesis, no model generation or vulnerability-finding claim.'})
    manifest=(source_root/'app/AndroidManifest.xml').read_bytes()
    java=(source_root/'app/src/org/mobius/ownedfixture/FixtureActivity.java').read_bytes()
    for name,original in [('AndroidManifest.xml',manifest),('src/org/mobius/ownedfixture/FixtureActivity.java',java)]:
        matches=[x for x in build_record.get('source_files',[]) if x['path']==name]
        if len(matches)!=1 or matches[0]['sha256']!=hashlib.sha256(original).hexdigest():
            raise ValueError('retained owned source differs from actual build manifest')
    # Fixture-only insertion, not a product hypothesis-creation API or model
    # analysis. Distinct source evidence and actor/event provenance are retained.
    with context.session() as session:
        evidence=EvidenceService(session,context.store)
        refs=[evidence.record(investigation_id=scan['id'],kind=EvidenceKind.TOOL_OUTPUT,content=data,
            summary='FIXTURE OWNED SOURCE '+name+'; source input to actual APK build, not Android runtime evidence',
            produced_by='OWNED_APP_FIXTURE_SETUP').id for name,data in [('manifest.xml',manifest),('FixtureActivity.java',java)]]
        observation=ObservationRow(id=new_id(IdPrefix.OBSERVATION),investigation_id=scan['id'],agent='OWNED_APP_FIXTURE_SETUP',
            kind='inference',fidelity='config',subject_type='owned-fixture-source',subject_ref=digest,
            statement='FIXTURE SOURCE ONLY: owned manifest/source declare the fixed explicit-trust network action; execution is untested.',
            attributes={'fixture_only':True,'build_apk_sha256':digest,'model_generated':False,
                'vulnerability_evidence':False,'source_evidence_refs':refs},maswe=[],confidence=1.0,evidence_refs=refs,created_at=utcnow())
        session.add(observation);session.flush()
        hypothesis=HypothesisRow(id=new_id(IdPrefix.HYPOTHESIS),investigation_id=scan['id'],
            claim='FIXTURE ONLY: this exact owned APK may perform its declared fixed explicit-trust loopback action and support native capture/request replay. Not a vulnerability or model finding.',
            maswe=[],derived_from=[observation.id],required_evidence=['owned-app-original-capture-and-replay'],satisfied_evidence=[],
            status='open',priority=0,depth=0,parent_id=None,created_at=utcnow())
        session.add(hypothesis);session.flush()
        SqlEventStore(session).emit(scan['id'],'owned_app_fixture_hypothesis_created',{
            'hypothesis_id':hypothesis.id,'observation_id':observation.id,'source_evidence':refs,
            'apk_sha256':digest,'fixture_only':True,'model_generated':False,'vulnerability_evidence':False,
            'owner_approval':False},actor=ACTOR)
        hypothesis_id=hypothesis.id;session.commit()
    plan=PoCTestPlan(investigation_id=scan['id'],authorization_id=auth['id'],target_sha256=digest,target_package=PACKAGE,
        target_kind='owned_android_fixture',hypothesis_ids=(hypothesis_id,),safety_class='non_destructive',requires_approval=True,
        max_duration_seconds=130,max_output_bytes=1048576,
        expected_outcome='Owned fixture APK action/native replay integration only, no vulnerability validation or model-generation claim.',
        steps=[{'action':'capture_owned_android_fixture_v1','target_ref':PROFILE,'input_values':{'public_ca_sha256':ca},'timeout_seconds':60}],
        cleanup_steps=[{'action':'stop_owned_android_fixture','target_ref':PROFILE,'timeout_seconds':60}])
    approval=api('/scans/'+scan['id']+'/poc/approvals',{'plan':plan.model_dump(mode='json'),
        'justification':'DISPOSABLE TEST ACTOR: exact built owned APK/native capture-replay integration, NOT owner approval.',
        'risk_summary':'Fixed local owned endpoint, app-only CA, no external targets/model/production. App install/launch scoped to disposable guest.',
        'expires_at':expires})
    api('/scans/'+scan['id']+'/poc/approvals/'+approval['id']+'/resolve',{'decision':'granted',
        'note':'DISPOSABLE TEST ACTOR ONLY, not user consent or an authority to activate the held harness.'})
    plan=plan.model_copy(update={'approval_id':approval['id']})
    output.mkdir(mode=0o700,exist_ok=False)
    (output/'approved-plan.json').write_text(plan.model_dump_json())
    (output/'fixture-provenance.json').write_text(json.dumps({'actor':ACTOR,'fixture_only':True,
        'apk_sha256':digest,'public_ca_sha256':ca,'hypothesis_id':hypothesis_id,'model_generated':False,
        'vulnerability_evidence':False,'owner_approval':False,'historical_authority_transferred':False,
        'case_id':scan['id'],'authorization_id':auth['id'],'approval_id':approval['id']},sort_keys=True))
    return plan
