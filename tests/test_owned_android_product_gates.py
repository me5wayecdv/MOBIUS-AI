"""Owned-app product gates/failures only, no SDK, host, build or positive evidence."""
from dataclasses import asdict,replace
import hashlib
import json

import pytest
from pydantic import ValidationError

from conftest import make_apk
from mobius.adapters.events import SqlEventStore,utcnow
from mobius.adapters.models import HypothesisRow,PoCRunEvidenceRow
from mobius.core.ids import IdPrefix,new_id
from mobius.core.schemas import PoCTestPlan
from mobius.services.intake import IntakeService
from mobius.services.owned_android_fixture import OwnedAppAdapter,OwnedAppOutput,OwnedAppRequest
from mobius.services.poc_approval import PoCApprovalService
from mobius.services.poc_execution import PoCExecutionService
from mobius.services.poc_runner import PoCAdapterUnavailable,PoCApprovalRequired,PoCScopeRejected


def owned_plan(session,store,future_iso):
    intake=IntakeService(session,store)
    app,_=intake.create_application(make_apk(manifest="<manifest package='org.mobius.ownedfixture'/>"),
        'owned-unit-only.apk',uploaded_by='analyst-1')
    auth=intake.create_authorization(apk_sha256=app.sha256,target_package='org.mobius.ownedfixture',
        scope_text='UNIT ONLY owned fixture, no runtime execution',statement='Synthetic unit actor, not owner consent',
        max_intensity=0,granted_by='analyst-1',expires_at=future_iso)
    scan=intake.create_investigation(application_id=app.id,authorization_id=auth.id,
        objective='UNIT owned fixture gates only',intensity=0,created_by='analyst-1')
    hyp=HypothesisRow(id=new_id(IdPrefix.HYPOTHESIS),investigation_id=scan.id,
        claim='FIXTURE ONLY: owned app declares its fixed network test action; not a vulnerability or model finding.',
        maswe=[],derived_from=[],required_evidence=['owned-app-originals'],satisfied_evidence=[],status='open',
        priority=0,depth=0,parent_id=None,created_at=utcnow())
    session.add(hyp);session.flush()
    SqlEventStore(session).emit(scan.id,'owned_app_fixture_hypothesis_created',
        {'hypothesis_id':hyp.id,'fixture_only':True,'model_generated':False,'vulnerability_evidence':False},actor='UNIT_FIXTURE')
    return PoCTestPlan(investigation_id=scan.id,authorization_id=auth.id,target_sha256=app.sha256,
        target_package='org.mobius.ownedfixture',target_kind='owned_android_fixture',hypothesis_ids=(hyp.id,),
        expected_outcome='UNIT fixture gating, not runtime proof',safety_class='non_destructive',requires_approval=True,
        max_duration_seconds=130,max_output_bytes=1048576,
        steps=[{'action':'capture_owned_android_fixture_v1','target_ref':'owned-android-fixed-loopback-v1',
            'input_values':{'public_ca_sha256':'a'*64},'timeout_seconds':60}],
        cleanup_steps=[{'action':'stop_owned_android_fixture','target_ref':'owned-android-fixed-loopback-v1','timeout_seconds':60}])


def grant(session,plan,future_iso):
    service=PoCApprovalService(session)
    row=service.request(plan,requested_by='analyst-1',justification='UNIT TEST ACTOR, no runtime permission',
        risk_summary='No host launch in test',expires_at=future_iso)
    service.resolve(row.id,investigation_id=plan.investigation_id,decision='granted',decided_by='analyst-1',note='UNIT ONLY')
    session.commit()
    return plan.model_copy(update={'approval_id':row.id})


def test_owned_plan_cannot_disguise_or_change_scope(session,store,future_iso):
    plan=owned_plan(session,store,future_iso)
    for key,value in [('target_kind','native_local_fixture'),('target_kind','emulator'),('requires_approval',False),
        ('target_package','thirdparty.app'),('max_duration_seconds',131),('max_output_bytes',65536),('safety_class','read_only')]:
        with pytest.raises(ValidationError):PoCTestPlan.model_validate({**plan.model_dump(),key:value})
    data=plan.model_dump();data['steps'][0]['input_values']={'url':'https://thirdparty.invalid'}
    with pytest.raises(ValidationError):PoCTestPlan.model_validate(data)


def test_owned_default_adapter_unavailable_before_any_host(session,store,future_iso):
    plan=owned_plan(session,store,future_iso)
    with pytest.raises(PoCApprovalRequired):PoCExecutionService(session,store).execute_and_persist(plan)
    plan=grant(session,plan,future_iso)
    with pytest.raises(PoCAdapterUnavailable):PoCExecutionService(session,store).execute_and_persist(plan)
    with pytest.raises(RuntimeError):OwnedAppAdapter().execute(OwnedAppRequest.from_plan(plan))


def test_owned_ca_digest_is_in_approval_and_existing_serialization_unchanged(session,store,future_iso):
    from test_poc_execution import _context
    _,old=_context(session,store,future_iso)
    original=old.model_dump(mode='json')
    assert 'fixture_public_ca_sha256' not in original
    assert old.steps[0].input_values=={'url':'javascript:alert(1)'}
    plan=grant(session,owned_plan(session,store,future_iso),future_iso)
    data=plan.model_dump();data['steps'][0]['input_values']['public_ca_sha256']='b'*64
    changed=PoCTestPlan.model_validate(data)
    with pytest.raises(PoCApprovalRequired):PoCExecutionService(session,store).execute_and_persist(changed)


def test_owned_failed_attempt_persists_originals_and_readback_remains_failed(session,store,future_iso):
    plan=grant(session,owned_plan(session,store,future_iso),future_iso)
    def failed(request,**kwargs):
        return OwnedAppOutput(request,{'binding.json':json.dumps(asdict(request)).encode(),
            'host-failure.json':b'{"code":"host_timeout","unit_failure_only":true}'},('unit-refusal-only',),'failed','host_timeout')
    service=PoCExecutionService(session,store,owned_android_adapter=OwnedAppAdapter(failed))
    run=service.execute_and_persist(plan);session.commit()
    assert run.status=='failed'
    result=service.readback(run.run_id,investigation_id=plan.investigation_id)
    assert result['status']=='failed'
    assert result['output']['output_json']['traffic_source']=='owned-android-app-process-fixed-loopback'
    assert result['output']['output_json']['apk_execution'] is None
    links=session.query(PoCRunEvidenceRow).filter_by(run_id=run.run_id,kind='owned-android').all()
    assert links
    session.delete(links[0]);session.flush()
    with pytest.raises(ValueError,match='links incomplete'):service.readback(run.run_id,investigation_id=plan.investigation_id)


def test_owned_revocation_rejects_before_host_and_after_pending_host(session,store,future_iso):
    from sqlalchemy.orm import Session
    from mobius.adapters.models import AuthorizationRow
    plan=grant(session,owned_plan(session,store,future_iso),future_iso)
    calls=[]
    def pending(request,**kwargs):
        calls.append(request)
        with Session(bind=session.get_bind()) as other:
            other.get(AuthorizationRow,plan.authorization_id).revoked_at='2026-01-01T00:00:00Z';other.commit()
        return None
    service=PoCExecutionService(session,store,owned_android_adapter=OwnedAppAdapter(pending))
    run=service.execute_and_persist(plan);assert run.status=='failed' and len(calls)==1
    session.commit();assert service.readback(run.run_id,investigation_id=plan.investigation_id)['status']=='failed'
    with pytest.raises(PoCScopeRejected):service.execute_and_persist(plan)
    assert len(calls)==1


def test_fresh_api_fixture_setup_retains_test_actor_and_no_model_provenance(ctx,tmp_path,monkeypatch):
    # Synthetic build metadata exercises setup mechanics only. No Java compile,
    # APK runtime, native capture or positive host result is fabricated here.
    import sys
    from pathlib import Path
    from fastapi.testclient import TestClient
    from mobius.api.app import create_app
    from mobius.adapters.models import ApprovalRow,DecisionRow
    from mobius.core.enums import Fidelity
    root=Path(__file__).parents[1]/'research/d061_android'
    monkeypatch.syspath_prepend(str(root))
    import owned_product_setup as product_setup
    monkeypatch.setattr(product_setup,'APPROVED_FOR_EXECUTION',True)
    monkeypatch.setattr(product_setup.os,'geteuid',lambda:65534)
    apk=tmp_path/'unit-not-runtime.apk';apk.write_bytes(make_apk(manifest="<manifest package='org.mobius.ownedfixture'/>"))
    manifest=root/'app/AndroidManifest.xml';java=root/'app/src/org/mobius/ownedfixture/FixtureActivity.java'
    build={'apk_sha256':hashlib.sha256(apk.read_bytes()).hexdigest(),'package':'org.mobius.ownedfixture',
        'actual_app_network_not_executed_by_build':True,'public_ca_sha256':'b'*64,
        'source_files':[{'path':str(x.relative_to(root/'app')),'sha256':hashlib.sha256(x.read_bytes()).hexdigest()}
            for x in (manifest,java)]}
    class NoModel:
        def __getattr__(self,name):raise AssertionError('unit setup may not call model')
    ctx.model_gateway=NoModel()
    with TestClient(create_app()) as client:
        plan=product_setup.prepare(ctx,client,apk=apk,build_record=build,source_root=root,output=tmp_path/'setup')
    provenance=json.loads((tmp_path/'setup/fixture-provenance.json').read_text())
    assert provenance['fixture_only'] and provenance['model_generated'] is provenance['owner_approval'] is False
    assert provenance['actor']==product_setup.ACTOR
    with ctx.session() as session:
        approval=session.get(ApprovalRow,plan.approval_id)
        assert approval.decided_by==product_setup.ACTOR and approval.state=='granted'
        assert session.query(DecisionRow).filter_by(investigation_id=plan.investigation_id).count()==0
        with pytest.raises(PoCAdapterUnavailable):PoCExecutionService(session,ctx.store).execute_and_persist(plan)


@pytest.mark.parametrize('mode',['exception','invalid','budget'])
def test_owned_rejections_keep_failure_and_full_budget_without_positive_proof(session,store,future_iso,mode):
    plan=grant(session,owned_plan(session,store,future_iso),future_iso)
    def rejected(request,**kwargs):
        if mode=='exception':raise OSError('UNIT ONLY original failure')
        files={'binding.json':json.dumps(asdict(request)).encode(),'host-failure.json':b'{"code":"host_failed"}'}
        if mode=='budget':files['proxy.log']=b'x'*1048576
        return OwnedAppOutput(request,files,('unit-failure-only',),
            'passed' if mode=='invalid' else 'failed',None if mode=='invalid' else 'host_failed')
    service=PoCExecutionService(session,store,owned_android_adapter=OwnedAppAdapter(rejected))
    result=service.execute_and_persist(plan);session.commit()
    readback=service.readback(result.run_id,investigation_id=plan.investigation_id)
    assert readback['status']=='failed' and readback['actual_apk_sha256']==plan.target_sha256
    assert readback['output']['output_json']['host_failure_code']=='product_rejected'
    assert readback['output']['output_json']['apk_execution'] is None
    assert sum(x['bytes'] for x in readback['evidence'])<=plan.max_output_bytes
    if mode=='budget':assert 'proxy.log' not in {x['name'] for x in readback['output']['output_json']['native_artifacts']}


@pytest.mark.parametrize('variant',[{'tls_scenario':'untrusted-ca'},{'tls_scenario':'wrong-hostname'},
    {'embedded_public_ca_sha256':'d'*64}])
def test_negative_apk_variants_rejected_before_product_setup_effects(tmp_path,monkeypatch,variant):
    import sys
    from pathlib import Path
    root=Path(__file__).parents[1]/'research/d061_android';monkeypatch.syspath_prepend(str(root))
    import owned_product_setup
    monkeypatch.setattr(owned_product_setup,'APPROVED_FOR_EXECUTION',True)
    monkeypatch.setattr(owned_product_setup.os,'geteuid',lambda:65534)
    apk=tmp_path/'synthetic.apk';apk.write_bytes(b'not a built APK')
    record={'apk_sha256':hashlib.sha256(apk.read_bytes()).hexdigest(),'package':'org.mobius.ownedfixture',
        'actual_app_network_not_executed_by_build':True,'public_ca_sha256':'b'*64,**variant}
    class NoEffects:
        def __getattr__(self,key):raise AssertionError('negative may not create positive grants/API objects')
    with pytest.raises(ValueError,match='actual owned build'):
        owned_product_setup.prepare(NoEffects(),NoEffects(),apk=apk,build_record=record,source_root=root,output=tmp_path/'forbidden')
    assert not (tmp_path/'forbidden').exists()
