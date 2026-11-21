"""HELD real product API journey with trusted host injection, no setup bypass."""
import argparse
import hashlib
import json
from pathlib import Path

APPROVED_FOR_EXECUTION = False


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD: exact product API journey/workflow review required')
    p=argparse.ArgumentParser()
    p.add_argument('--db',type=Path,required=True)
    p.add_argument('--artifacts',type=Path,required=True)
    p.add_argument('--plan',type=Path,required=True)
    p.add_argument('--host-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    from fastapi.testclient import TestClient
    from mobius.api.app import create_app
    from mobius.api.config import Settings
    from mobius.api.deps import AppContext,set_context
    from mobius.core.schemas import PoCTestPlan
    from mobius.services.native_local_fixture import NativeLocalFixtureAdapter
    from product_host import PreparedCIHost
    from product_setup import ACTOR
    plan=PoCTestPlan.model_validate_json(a.plan.read_bytes())
    context=AppContext(Settings(db_url='sqlite+pysqlite:///'+str(a.db),artifact_root=a.artifacts,env='test'),create_schema=False)
    class NoModelGateway:
        def __getattr__(self,name):raise RuntimeError('model access refused in product fixture journey')
    context.model_gateway=NoModelGateway()
    context.native_fixture_adapter=NativeLocalFixtureAdapter(PreparedCIHost(a.host_root))
    set_context(context)
    a.output.mkdir(exist_ok=False)
    headers={'X-Analyst-Id':ACTOR}
    def get(client,path):
        response=client.get('/api/v1'+path,headers=headers)
        if response.status_code!=200:raise RuntimeError('API readback failed:'+path+':'+str(response.status_code))
        return response
    try:
        with TestClient(create_app()) as client:
            base='/scans/'+plan.investigation_id
            response=client.post('/api/v1'+base+'/poc/execute',json=plan.model_dump(mode='json'),headers=headers)
            (a.output/'execute-response.json').write_text(json.dumps({'status_code':response.status_code,'body':response.json()},sort_keys=True))
            if response.status_code!=200:raise RuntimeError('actual product execution refused/failed at API')
            run=response.json()
            # GET uses a distinct request/session and rehashes immutable originals.
            readback=get(client,base+'/poc/runs/'+run['run_id']+'/evidence').json()
            (a.output/'api-readback.json').write_text(json.dumps(readback,sort_keys=True))
            response=client.post('/api/v1'+base+'/report',headers=headers)
            if response.status_code!=200:raise RuntimeError('product report failed')
            report=response.json()
            actual=get(client,base+'/report').text
            if hashlib.sha256(actual.encode()).hexdigest()!=report['sha256']:raise RuntimeError('fresh API report hash differs')
            if run['run_id'] not in actual or plan.id not in actual:raise RuntimeError('actual report lacks run/plan references')
            for item in readback['evidence']:
                if item['evidence_id'] not in actual:raise RuntimeError('report lacks immutable evidence reference')
            (a.output/'report.md').write_text(actual)
            (a.output/'journey-summary.json').write_text(json.dumps({'run_id':run['run_id'],
                'status':run['status'],'report_evidence_id':report['evidence_id'],'report_sha256':report['sha256'],
                'api_execute_readback_report':True,'fixture_only_hypothesis_import':True,
                'current_model_call':False,'owner_grant':False,'apk_execution':False,
                'tls_negative_controls':'UNTESTED_IN_PRODUCT_POSITIVE_PROFILE'},sort_keys=True))
            if run['status']!='passed':raise RuntimeError('actual product run failed, retained honestly')
    finally:set_context(None)

if __name__=='__main__':main()
