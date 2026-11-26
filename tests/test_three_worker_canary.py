"""Offline injected API records only. No queue process, Docker, model or device."""
import hashlib
import importlib.util
from pathlib import Path
import uuid
import pytest


def module():
    spec=importlib.util.spec_from_file_location('canary',Path(__file__).parents[1]/'scripts/three_worker_canary.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


@pytest.mark.parametrize('failure',[None,'failed','no_worker','no_applied','digest','bad_id','timeout','wrong_worker','nonempty_host'])
def test_three_worker_route_and_fail_closed(failure):
    m=module();apk=m.fixed_fixture();sha=hashlib.sha256(apk).hexdigest();calls=[];now=[0];jid=str(uuid.uuid4());rid=str(uuid.uuid4())
    def request(method,path,body=None):
        calls.append((method,path));now[0]+=2 if failure=='timeout' else 0
        if path=='/_canary/freshness':return {} if failure=='nonempty_host' else {'kind':'disposable-canary-v1','run_id':rid,'worker_id':'offline-fake','empty':True}
        if path=='/authorizations':return {'id':'auth_test'}
        if path=='/scans':return {'id':'scn_test'}
        if method=='POST' and path.endswith('/jobs'):return {'job_id':'../x' if failure=='bad_id' else jid}
        if path.endswith('/apply'):return {}
        if '/jobs/' in path:
            return {'status':'failed' if failure=='failed' else 'succeeded',
                'worker_id':None if failure=='no_worker' else 'other-worker' if failure=='wrong_worker' else 'offline-fake',
                'started_at':'unit','finished_at':'unit','applied':failure!='no_applied'}
        if path.endswith('/evidence-package'):return {'observations':[{'id':'unit'}],'evidence':[{'id':'unit'}]}
        return {'application':{'sha256':'b'*64 if failure=='digest' else sha,'package_name':'com.example.demo'}}
    def run():return m.run_canary(apk,request,lambda _:{'id':'app_test','sha256':sha},expect_worker_id='offline-fake',expect_run_id=rid,clock=lambda:now[0],sleep=lambda _:None,budget=3)
    if failure:
        with pytest.raises((ValueError,TimeoutError)):run()
    else:
        result=run();assert result['model_called'] is False and result['provider_flow_semantics_proven'] is False
        assert [j['kind'] for j in result['jobs']]==['recon','provider-analysis','spectre']
    assert not any('consent' in p or 'nexus' in p or '/poc/' in p or '/approvals' in p for _,p in calls)


def test_canary_fixture_is_deterministic_and_real_dex():
    import io,zipfile
    m=module();assert m.fixed_fixture()==m.fixed_fixture()
    with zipfile.ZipFile(io.BytesIO(m.fixed_fixture())) as z:
        assert z.read('classes.dex').startswith(b'dex\n')
        assert not z.read('AndroidManifest.xml').startswith(b'<')


def test_canary_through_actual_api_with_explicitly_supplied_completions(client,ctx,monkeypatch):
    """Real API/DB/apply. Worker completion is supplied, NOT OCI evidence."""
    from mobius.services.worker_queue import WorkerQueue
    from mobius.adapters.android_manifest import extract_manifest_bytes,to_text_xml
    from mobius.adapters.dex import index_apk
    from mobius.adapters.dex_payload import code_index_payload
    from test_provider_worker import _sample_payload,FIXTURE_DEX,IMAGE
    m=module();raw=m.fixed_fixture();sha=hashlib.sha256(raw).hexdigest();rid=str(uuid.uuid4())
    monkeypatch.setenv('MOBIUS_PROVIDER_IMAGE',IMAGE)
    def upload(apk):
        result=client.post('/api/v1/applications',files={'file':('canary.apk',apk,'application/vnd.android.package-archive')})
        assert result.status_code<300,result.text
        return result.json()
    def request(method,path,body=None):
        if method=='GET' and path=='/_canary/freshness':return {'kind':'disposable-canary-v1','run_id':rid,'worker_id':'offline-supplied-canary','empty':True} # supplied test-only capability
        result=client.request(method,'/api/v1'+path,json=body)
        assert result.status_code<300,result.text
        data=result.json()
        if method=='POST' and path.endswith('/jobs'):
            with ctx.session() as session:
                q=WorkerQueue(session);job=q.claim('offline-supplied-canary')
                assert job.id==data['job_id']
                if job.kind=='recon_manifest':payload={'manifest_xml':to_text_xml(extract_manifest_bytes(raw)).decode()}
                elif job.kind=='provider_analysis':
                    payload=_sample_payload(sha);payload['package_name']='com.example.demo'
                    payload['exposures']=[];payload['origins']={}
                    payload['dex_coverage'][0]['size_bytes']=len(FIXTURE_DEX.read_bytes())
                else:payload=code_index_payload(index_apk(raw),sha)
                q.succeed(job.id,'offline-supplied-canary',payload,staged_sha256=sha);session.commit()
        return data
    result=m.run_canary(raw,request,upload,expect_worker_id='offline-supplied-canary',expect_run_id=rid)
    assert result['status']=='canary_api_jobs_applied'
    assert len(result['jobs'])==3 and not result['provider_flow_semantics_proven']


def test_current_api_has_no_fresh_host_capability_and_canary_refuses_before_upload(client):
    import httpx
    m=module();writes=[];methods=[]
    def request(method,path,body=None):
        methods.append(method)
        response=client.request(method,'/api/v1'+path,json=body)
        response.raise_for_status()
        return response.json()
    with pytest.raises(httpx.HTTPStatusError) as caught:
        m.run_canary(m.fixed_fixture(),request,lambda _:writes.append('upload'),expect_worker_id='unit',expect_run_id=str(uuid.uuid4()))
    assert caught.value.response.status_code==404
    assert writes==[] and methods==['GET']


def test_connected_transport_import_has_no_side_effects(monkeypatch):
    import socket,subprocess,inspect
    def refused(*args,**kwargs):raise AssertionError('import attempted external effect')
    monkeypatch.setattr(socket.socket,'connect',refused)
    monkeypatch.setattr(subprocess,'Popen',refused)
    spec=importlib.util.spec_from_file_location('import_only_connected',Path(__file__).parents[1]/'scripts/connected_journey_smoke.py')
    transport=importlib.util.module_from_spec(spec);spec.loader.exec_module(transport)
    assert {'raw','headers'} <= set(inspect.signature(transport.call).parameters)
    assert transport.failures==[] and transport.CALL_DEADLINE is None


def test_transport_refuses_redirect_instead_of_following_to_another_api():
    import urllib.request,urllib.error
    spec=importlib.util.spec_from_file_location('transport_no_redirect',Path(__file__).parents[1]/'scripts/connected_journey_smoke.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    request=urllib.request.Request('http://127.0.0.1/api/v1/health')
    with pytest.raises(urllib.error.HTTPError) as caught:
        m.NoRedirect().redirect_request(request,None,302,'redirect',{},'http://other.invalid')
    assert caught.value.code==302
