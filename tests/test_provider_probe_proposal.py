"""Proposal-only tests, synthetic rows. No model, adb, Docker, APK execution or network."""
import json
import pytest
from sqlalchemy import select
from conftest import make_apk
from mobius.adapters.models import ApplicationRow,AuthorizationRow,HypothesisRow,ObservationRow,EvidenceRow,InvestigationRow
from mobius.adapters.events import utcnow
from mobius.core.ids import new_id,IdPrefix
from mobius.core.enums import EvidenceKind
from mobius.services.evidence import EvidenceService
from mobius.services.intake import IntakeService
from mobius.services.poc_runner import PoCScopeRejected
from mobius.services.provider_probe_proposal import ProviderReadContract,ProviderReadProposal


def setup(session,store,future_iso):
    intake=IntakeService(session,store)
    app,_=intake.create_application(make_apk(),'unit.apk',uploaded_by='analyst-1')
    auth=intake.create_authorization(apk_sha256=app.sha256,target_package='com.example',
        scope_text='Unit fixture read-only local laboratory only',statement='Unit test authorization',max_intensity=0,
        granted_by='analyst-1',expires_at=future_iso)
    scan=intake.create_investigation(application_id=app.id,authorization_id=auth.id,
        objective='Unit proposal',intensity=0,created_by='analyst-1')
    ar=session.get(ApplicationRow,app.id);ar.package_name='com.example'
    evidence=EvidenceService(session,store)
    ev=evidence.record(investigation_id=scan.id,kind=EvidenceKind.TOOL_OUTPUT,produced_by='SPECTRE',
        summary='Unit provider document',content=json.dumps({'provider':'com.example.Notes',
            'operation':'read','sink_flows':[{'method':'Notes.query','sink':'SQLiteDatabase.query'}]}).encode())
    manifest=evidence.record(investigation_id=scan.id,kind=EvidenceKind.MANIFEST,produced_by='RECON',summary='Unit manifest',content=b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example"><application><provider android:name=".Notes" android:authorities="com.example.notes" android:exported="true"/><provider android:name=".Private" android:authorities="com.example.private" android:exported="false"/></application></manifest>''')
    obs=ObservationRow(id=new_id(IdPrefix.OBSERVATION),investigation_id=scan.id,agent='SPECTRE',
        kind='inference',fidelity='decompiled',subject_type='component',subject_ref='com.example.Notes',
        statement='Synthetic code-flow unit observation',attributes={'operation':'read',
        'method_references':['Notes.query'],'flow_complete':False,'operation_coverage_complete':False},
        maswe=[],confidence=.6,evidence_refs=[ev.id],created_at=utcnow())
    session.add(obs)
    hyp=HypothesisRow(id=new_id(IdPrefix.HYPOTHESIS),investigation_id=scan.id,
        claim='Synthetic unit hypothesis, not real model output',maswe=[],derived_from=[obs.id],
        required_evidence=['runtime_observation'],satisfied_evidence=[],status='open',priority=.5,
        depth=0,parent_id=None,created_at=utcnow())
    session.add(hyp);session.flush()
    contract=ProviderReadContract(app.sha256,'a'*64,'com.example','com.example.Notes','com.example.notes','note',
        'com.example.Private','com.example.private','note','emulator-5554')
    return ar,session.get(AuthorizationRow,auth.id),scan,hyp,obs,ev,manifest,contract


def test_empty_registration_refuses_instead_of_guessing_a_fixture_uri(session,store,future_iso):
    _,_,scan,hyp,*_=setup(session,store,future_iso)
    with pytest.raises(PoCScopeRejected,match='no independently reviewed'):
        ProviderReadProposal(session,store).propose(scan.id,hyp.id,analyst_id='analyst-1')


def test_proposal_binds_genuine_rows_but_never_claims_ready_or_validates_prose(session,store,future_iso):
    app,auth,scan,hyp,obs,ev,manifest,c=setup(session,store,future_iso)
    before=hyp.status
    out=ProviderReadProposal(session,store,(c,)).propose(scan.id,hyp.id,analyst_id='analyst-1')
    assert out['ready_for_execution'] is False and out['negative_control']['implemented'] is True
    assert out['plan']['requires_approval'] is True
    assert out['plan']['target_sha256']==app.sha256 and out['plan']['hypothesis_ids']==[hyp.id]
    assert out['plan']['steps'][2]['target_ref']=='com.example.notes/note'
    assert out['plan']['steps'][2]['expected_value']==1 # no magic fixture row count4
    assert out['flow_observation_id']==obs.id and out['flow_evidence_id']==ev.id
    assert hyp.status==before and list(hyp.satisfied_evidence)==[]
    assert out['plan']['approval_id'] is None


@pytest.mark.parametrize('mutation',['other_owner','revoked','expired','wrong_package','wrong_hypothesis',
    'paused','wrong_kind','bad_method_ref','truncated_manifest','truncated_flow','write_only','no_refs','other_agent','changed_manifest','forged_flow','closed_scan','nonexported_positive'])
def test_proposal_abstains_on_missing_scope_identity_or_provenance(session,store,future_iso,mutation):
    app,auth,scan,hyp,obs,ev,manifest,c=setup(session,store,future_iso)
    who='analyst-1'
    if mutation=='other_owner':who='other'
    elif mutation=='revoked':auth.revoked_at=utcnow()
    elif mutation=='expired':auth.expires_at='2020-01-01T00:00:00Z'
    elif mutation=='wrong_package':app.package_name='other.package'
    elif mutation=='wrong_hypothesis':hyp.derived_from=[]
    elif mutation=='paused':
        row=session.get(InvestigationRow,scan.id);row.paused_at=utcnow();row.paused_by='analyst-1'
    elif mutation=='wrong_kind':obs.kind='fact';obs.confidence=1.0
    elif mutation=='bad_method_ref':obs.attributes={**obs.attributes,'method_references':['Other.method']}
    elif mutation=='truncated_manifest':session.get(EvidenceRow,manifest.id).truncated=True
    elif mutation=='truncated_flow':session.get(EvidenceRow,ev.id).truncated=True
    elif mutation=='write_only':obs.attributes={**obs.attributes,'operation':'write'}
    elif mutation=='no_refs':obs.evidence_refs=[]
    elif mutation=='other_agent':obs.agent='user'
    elif mutation=='changed_manifest':session.get(EvidenceRow,manifest.id).sha256='b'*64
    elif mutation=='forged_flow':session.get(EvidenceRow,ev.id).sha256='b'*64
    elif mutation=='closed_scan':session.get(InvestigationRow,scan.id).state='CLOSED'
    elif mutation=='nonexported_positive':
        from dataclasses import replace
        c=replace(c,provider='com.example.Private',authority='com.example.private',negative_provider='com.example.Notes',negative_authority='com.example.notes')
        obs.subject_ref=c.provider
    session.flush()
    with pytest.raises((PoCScopeRejected,ValueError,OSError)):
        ProviderReadProposal(session,store,(c,)).propose(scan.id,hyp.id,analyst_id=who)


@pytest.mark.parametrize('path',['../x','note?query=x','a/b','$(id)',''])
def test_contract_is_not_arbitrary_path_or_model_command(path):
    with pytest.raises(ValueError):
        ProviderReadContract('a'*64,'b'*64,'com.example','com.example.P','com.example.p',path,
            'com.example.N','com.example.n','x','emulator-5554')


def test_review_and_evidence_are_inside_canonical_approval_plan(session,store,future_iso):
    import hashlib
    from dataclasses import replace
    app,auth,scan,hyp,obs,ev,manifest,c=setup(session,store,future_iso)
    def plan(contract):
        return ProviderReadProposal(session,store,(contract,)).propose(scan.id,hyp.id,analyst_id='analyst-1')['plan']
    original=plan(c)
    binding=original['provider_probe_binding']
    assert binding['source_review_sha256']==c.source_review_sha256
    assert binding['flow_evidence_id']==ev.id and binding['manifest_evidence_id']==manifest.id
    assert binding['observation_id']==obs.id and binding['expected_uid']==2000
    changed=plan(replace(c,source_review_sha256='b'*64))
    assert changed['provider_probe_binding']['contract_sha256']!=binding['contract_sha256']
    # Compare stable plan IDs: approval hashing includes the complete binding.
    changed['id']=original['id']
    digest=lambda d:hashlib.sha256(json.dumps(d,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    assert digest(original)!=digest(changed)


def test_bound_plan_preflight_every_query_and_approval_tampering(session,store,future_iso):
    from mobius.core.schemas import PoCTestPlan
    from mobius.services.poc_runner import SafePoCRunner,PoCApprovalRequired
    from mobius.services.phantom import EmulatorProbeResult
    from test_phantom import _granted_approval
    app,auth,scan,hyp,obs,ev,manifest,c=setup(session,store,future_iso)
    plan=PoCTestPlan.model_validate(ProviderReadProposal(session,store,(c,)).propose(scan.id,hyp.id,analyst_id='analyst-1')['plan'])
    approval=_granted_approval(session,plan)
    plan=plan.model_copy(update={'approval_id':approval.id})
    calls=[]
    class Adapter:
        VERSION='offline-fake'
        def probe_package_present(self,p):return EmulatorProbeResult('package',p,True,'unit','')
        def verify_installed_identity(self,*args):calls.append(('identity',args))
        def probe_provider_permission_denied(self,*args):
            calls.append(('denial',args));return EmulatorProbeResult('negative','unit',True,'unit','','permission_denied')
        def probe_provider_query_rows(self,*args):
            calls.append(('read',args));return EmulatorProbeResult('positive','unit',1,'unit','','readable_as_shell')
    runner=SafePoCRunner(session,emulator_adapter=Adapter())
    result=runner.run(plan)
    assert result.status=='passed'
    assert [c[0] for c in calls]==['identity','denial','identity','read']
    assert result.output_json['steps'][1]['outcome']=='permission_denied'
    assert result.output_json['steps'][2]['outcome']=='readable_as_shell'
    for field in ('source_review_sha256','contract_sha256','emulator_serial'):
        altered=plan.provider_probe_binding.model_copy(update={field:'emulator-5556' if field=='emulator_serial' else 'b'*64})
        with pytest.raises(PoCApprovalRequired):runner.validate_authority(plan.model_copy(update={'provider_probe_binding':altered}))
    session.get(EvidenceRow,ev.id).sha256='b'*64
    with pytest.raises(PoCScopeRejected,match='evidence metadata'):runner.validate_authority(plan)
