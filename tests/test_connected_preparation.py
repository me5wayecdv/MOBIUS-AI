"""Preparation driver tests. No worker, model, subprocess, emulator or network is run."""
import importlib.util
from pathlib import Path
import uuid

import pytest


def driver():
    path = Path(__file__).resolve().parents[1] / 'scripts' / 'connected_journey_smoke.py'
    spec = importlib.util.spec_from_file_location('connected_preparation_driver', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def package(code=True):
    return {'observations':[{'id':'obs_1'}], 'evidence':[{'id':'ev_1'}],
            'method_references':['C->method'] if code else [],
            'sink_references':[], 'source_snippets':[], 'limitations':['bounded only']}


def test_preparation_uses_real_closed_worker_routes_before_model():
    m=driver();calls=[];jid=str(uuid.uuid4())
    def request(method,path):
        calls.append((method,path))
        if path.endswith('/evidence-package'):return package()
        if method=='POST' and path.endswith('/jobs'):return {'job_id':jid}
        if method=='GET':return {'status':'succeeded'}
        return {'applied':True}
    assert m.prepare_static_evidence('scn_a',request=request)==package()
    assert calls==[
        ('POST','/scans/scn_a/provider-analysis/jobs'),
        ('GET','/scans/scn_a/provider-analysis/jobs/'+jid),
        ('POST','/scans/scn_a/provider-analysis/jobs/'+jid+'/apply'),
        ('POST','/scans/scn_a/spectre/jobs'),
        ('GET','/scans/scn_a/spectre/jobs/'+jid),
        ('POST','/scans/scn_a/spectre/jobs/'+jid+'/apply'),
        ('GET','/scans/scn_a/evidence-package')]
    assert m.CALL_DEADLINE is None


@pytest.mark.parametrize('failure',['failed','unknown','manifest_only','missing_evidence','bad_id','unconfigured'])
def test_preparation_never_fakes_capability_evidence_or_hypotheses(failure):
    m=driver();calls=[];jid=str(uuid.uuid4())
    def request(method,path):
        calls.append((method,path))
        if failure=='unconfigured':raise OSError('worker unavailable')
        if method=='POST' and path.endswith('/jobs'):
            return {'job_id':'../other-route' if failure=='bad_id' else jid}
        if method=='GET' and not path.endswith('evidence-package'):
            return {'status':failure if failure in ('failed','unknown') else 'succeeded'}
        if path.endswith('/evidence-package'):
            p=package(code=failure!='manifest_only')
            if failure=='missing_evidence':p['evidence']=[]
            return p
        return {}
    with pytest.raises((ValueError,OSError)):
        m.prepare_static_evidence('scn_a',request=request)
    assert m.CALL_DEADLINE is None
    assert not any('hypotheses' in p or 'poc/' in p or p.endswith('/spectre') or p.endswith('provider-analysis') for _,p in calls)


def test_preparation_has_one_shared_deadline_no_per_stage_reset():
    m=driver();now=[0.0];calls=[];jid=str(uuid.uuid4())
    def request(method,path):
        calls.append(path)
        if method=='POST':return {'job_id':jid}
        return {'status':'queued'}
    def sleep(seconds):now[0]+=seconds
    with pytest.raises(TimeoutError):
        m.prepare_static_evidence('scn_a',request=request,clock=lambda:now[0],sleep=sleep,timeout_seconds=2)
    assert now[0]==2
    assert len(calls)==5
    assert not any('spectre' in p for p in calls)
    assert m.CALL_DEADLINE is None


def test_empty_model_result_stays_empty_not_replaced_or_retried(monkeypatch):
    m=driver();calls=[]
    monkeypatch.setattr(m,'multipart_upload',lambda *_:{'id':'app_a','sha256':m.SHA256})
    monkeypatch.setattr(m,'prepare_static_evidence',lambda _:package())
    def request(method,path,body=None):
        calls.append(path)
        if path=='/authorizations':return {'id':'auth_a'}
        if path=='/scans':return {'id':'scn_a'}
        if path.endswith('model-consent'):return {'llm_data_sharing':{'enabled':True,'provider':'opencode'}}
        if path.endswith('hypotheses'):return {'mode':'model_gateway','hypotheses':[],'summary':'insufficient evidence'}
        return {'application':{'package_name':m.PKG}}
    monkeypatch.setattr(m,'call',request)
    assert m.main()==1
    assert sum(p.endswith('hypotheses') for p in calls)==1
    assert not any('/poc/' in p for p in calls)


@pytest.mark.parametrize('complete', [True, False])
def test_preparation_through_actual_api_lifecycle_with_supplied_worker_payloads(client,ctx,monkeypatch,complete):
    """Real routes/DB/claim/apply/state machine. Only external worker completion is faked.
    This is not container/Android evidence and does not call a model.
    """
    import hashlib
    import json
    from mobius.adapters.dex import index_apk
    from mobius.adapters.dex_payload import code_index_payload
    from mobius.services.worker_queue import WorkerQueue
    from test_api import _upload,_authorize,_scan
    from test_provider_worker import _fixture_apk,_sample_payload,FIXTURE_DEX,IMAGE
    monkeypatch.setenv('MOBIUS_PROVIDER_IMAGE',IMAGE)
    raw=_fixture_apk();sha=hashlib.sha256(raw).hexdigest()
    app=_upload(client,data=raw).json()
    auth=_authorize(client,sha).json();scan=_scan(client,app['id'],auth['id']).json();sid=scan['id']
    assert client.post(f'/api/v1/scans/{sid}/recon').status_code==200
    supplied=_sample_payload(sha)
    # API cross-checks the supplied worker ledger against the archive metadata.
    supplied['dex_coverage'][0]['size_bytes']=len(FIXTURE_DEX.read_bytes())
    if not complete:
        # Force flow text well beyond package's 4000-char statement cap.
        import copy
        flow=supplied['exposures'][0]['operations'][0]['sink_flows'][0]
        flow['detail']='detail '*250
        supplied['exposures'][0]['operations'][0]['sink_flows']=[copy.deepcopy(flow) for _ in range(4)]
        supplied['exposures'][0]['operations'][0]['coverage_complete']=False
        supplied['exposures'][0]['operations'][0]['flow_complete']=False
        supplied['exposures'][0]['operations'][0]['caller_check_absent']=None
    index=code_index_payload(index_apk(raw),sha)
    def request(method,path):
        response=client.request(method,'/api/v1'+path)
        assert response.status_code<300,response.text
        data=response.json()
        if method=='POST' and path.endswith('/jobs'):
            with ctx.session() as session:
                q=WorkerQueue(session);job=q.claim('offline-test-worker')
                assert job.id==data['job_id']
                if job.kind=='provider_analysis':
                    job.staged_sha256=sha
                    payload=supplied
                else:payload=index
                q.succeed(job.id,'offline-test-worker',payload,staged_sha256=sha);session.commit()
        return data
    p=driver().prepare_static_evidence(sid,request=request)
    assert p['observations'] and p['evidence']
    obs=[o for o in p['observations'] if o['subject_ref']=='com.example.NotesProvider' and o['agent']=='SPECTRE' and o['statement'].startswith('Bounded provider bytecode')]
    assert len(obs)==1 and obs[0]['kind']=='inference' and obs[0]['confidence']<1
    assert 'NOT runtime or exploitability proof' in obs[0]['statement']
    assert obs[0]['attributes']['exhaustive'] is False
    assert obs[0]['attributes']['path']==[]
    assert obs[0]['attributes']['method_references']==['com.example.NotesProvider.query']
    assert obs[0]['evidence_refs'][0] in {e['id'] for e in p['evidence']}
    assert 'SQLiteDatabase.rawQuery' in p['sink_references']
    assert obs[0]['attributes']['operation']=='read'
    assert obs[0]['attributes']['operation_coverage_complete'] is complete
    assert obs[0]['attributes']['flow_complete'] is complete
    if not complete:
        assert len(obs[0]['statement'])==4000
        assert obs[0]['attributes']['statement_clipped'] is True
        assert p['truncated'] is True
        assert 'coverage_complete=False' in obs[0]['statement']
        assert 'flow_complete=False' in obs[0]['statement']
        assert 'Only analyzed operation methods and resolved helpers' in obs[0]['statement']
        assert all(f['status']!='confirmed' for f in p['findings'] if f['category']=='exported-provider-unprotected-sink')
    # The successful provider apply occurred while SURFACE_READY; SPECTRE then
    # advances the actual FSM. Reversing this order fails the next enqueue.
    assert client.get(f'/api/v1/scans/{sid}').json()['state']=='CORRELATING'
    assert not client.get(f'/api/v1/scans/{sid}/hypotheses').json()['items']
