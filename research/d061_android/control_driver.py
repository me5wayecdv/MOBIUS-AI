"""HELD unprivileged no-uplink product-control sibling entrypoint.

No KVM, ADB, setns, namespace descriptors or privilege escalation. The only host
seam exchanges bounded fixed JSON/immutable evidence with the trusted relay.
"""
import json
import os
from pathlib import Path
import time

from handoff_io import read,write,json_write,wait,digest
from handoff_protocol import validate_provisioned,make_commit,canonical
from mobius.services.owned_android_fixture import OwnedAppAdapter,OwnedAppOutput,TRAFFIC_SOURCE,REQUIRED

APPROVED_FOR_EXECUTION = False


class FixedRelayHost:
    VERSION='owned-android-fixed-relay/0.1.0-held'
    def __init__(self,ready,work):self.ready=ready;self.work=work;self.used=False

    def __call__(self,request,*,cancel_check=None):
        if self.used:raise RuntimeError('one-shot owned app relay already consumed')
        self.used=True;request.validate()
        # Product service has already performed its fresh committed authority
        # check. The relay record is data, not root/user consent or argv.
        commit=make_commit(request,ready_metadata=self.ready,ready_metadata_sha256=digest(canonical(self.ready)))
        json_write(self.work/'commit.json',commit)
        deadline=time.monotonic()+130
        while not Path('/control/result/result.json').exists():
            if cancel_check is not None and cancel_check():
                json_write(self.work/'cancel.json',{'version':'owned-android-cancel/1','run_id':self.ready['run_id']})
                raise RuntimeError('product cancellation while waiting for fixed runtime relay')
            if time.monotonic()>deadline:raise TimeoutError('approved host relay total exceeded')
            time.sleep(.05)
        result=json.loads(read('/control/result/result.json',65536))
        if set(result)!={'status','failure_code','tool_versions','files','request'} or result['request']!=commit['request']:
            raise ValueError('fixed runtime result identity differs')
        files={};total=0
        allowed=REQUIRED|{'host-failure.json','product-rejection.json','policy.json','proxy.log','origin.log'}
        if not isinstance(result['files'],list) or len(result['files'])>40:raise ValueError('bounded artifact manifest')
        for row in result['files']:
            name=row['name']
            if name not in allowed or name in files:raise ValueError('unallowlisted or duplicate relay artifact')
            content=read(Path('/control/result')/name,min(1048576,request.max_evidence_bytes-total))
            total+=len(content)
            if digest(content)!=row['sha256'] or len(content)!=row['bytes']:raise ValueError('immutable relayed artifact differs')
            files[name]=content
        return OwnedAppOutput(request,files,tuple(result['tool_versions']),result['status'],result['failure_code'])


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD coherent sibling source/closure review required')
    if os.geteuid()==0:raise RuntimeError('control API must be unprivileged')
    status=Path('/proc/self/status').read_text()
    if 'NoNewPrivs:\t1' not in status:raise RuntimeError('control no-new-privs required')
    import re
    if not all(re.search(r'^'+name+r':\s+0+$',status,re.M) for name in ('CapEff','CapBnd')):
        raise RuntimeError('control must have no capabilities')
    if Path('/dev/kvm').exists():raise RuntimeError('control must have no KVM device')
    work=Path('/work')
    json_write(work/'control-privileges.json',{'status':status,'namespace':os.readlink('/proc/self/ns/net'),
        'fds':{p.name:os.readlink(p) for p in Path('/proc/self/fd').iterdir() if p.exists()},
        'mountinfo':Path('/proc/self/mountinfo').read_text(),'devices':sorted(p.name for p in Path('/dev').iterdir()),
        'interfaces':Path('/proc/net/dev').read_text(),'routes4':Path('/proc/net/route').read_text()})
    context=json.loads(read('/control/context.json',65536))
    ready=json.loads(wait('/control/snapshot/ready.json',deadline=time.monotonic()+240))
    apk=read('/control/snapshot/owned-fixture.apk',4*1024**2)
    public_ca=read('/control/snapshot/public-ca.der',16384)
    build_bytes=read('/control/snapshot/build-result.json',65536)
    build=validate_provisioned(ready,apk=apk,public_ca_der=public_ca,build_json=build_bytes,
        expected_source_manifest_sha256=context['source_manifest_sha256'])
    for key in ('run_id','provisioning_id','closure_sha256'):
        if ready[key]!=context[key]:raise ValueError('immutable snapshot belongs to another run/closure')
    local_apk=work/'owned-fixture.apk';write(local_apk,apk)
    from fastapi.testclient import TestClient
    from mobius.api.app import create_app
    from mobius.api.config import Settings
    from mobius.api.deps import AppContext,set_context
    from owned_product_setup import prepare,ACTOR
    app_context=AppContext(Settings(db_url='sqlite+pysqlite:////work/mobius.db',artifact_root=work/'store',env='test'))
    class NoModel:
        def __getattr__(self,name):raise RuntimeError('no model gateway allowed in fixed owned fixture')
    app_context.model_gateway=NoModel()
    app_context.owned_android_fixture_adapter=OwnedAppAdapter(FixedRelayHost(ready,work))
    set_context(app_context)
    try:
        with TestClient(create_app()) as client:
            plan=prepare(app_context,client,apk=local_apk,build_record=build,source_root=Path('/fixture'),output=work/'setup')
            base='/api/v1/scans/'+plan.investigation_id;headers={'X-Analyst-Id':ACTOR}
            response=client.post(base+'/poc/execute',json=plan.model_dump(mode='json'),headers=headers)
            json_write(work/'execute-response.json',{'status_code':response.status_code,'body':response.json()})
            if response.status_code!=200:raise RuntimeError('owned product API execution refused')
            run=response.json()
            response=client.get(base+'/poc/runs/'+run['run_id']+'/evidence',headers=headers)
            if response.status_code!=200:raise RuntimeError('owned product fresh readback refused')
            readback=response.json()
            json_write(work/'api-readback.json',readback)
            report=client.post(base+'/report',headers=headers)
            if report.status_code!=200:raise RuntimeError('owned product report generation failed')
            text=client.get(base+'/report',headers=headers)
            if text.status_code!=200 or digest(text.content)!=report.json()['sha256']:raise ValueError('report readback hash differs')
            if run['run_id'] not in text.text or plan.id not in text.text:raise ValueError('report misses actual run/plan')
            if any(item['evidence_id'] not in text.text for item in readback['evidence']):raise ValueError('report misses immutable evidence refs')
            write(work/'report.md',text.content)
            json_write(work/'control-result.json',{'status':run['status'],'run_id':run['run_id'],'plan_id':plan.id,
                'fixture_only':True,'model_generated':False,'owner_approval':False,
                'report_sha256':report.json()['sha256'],'runtime_absence_checked_before_result':True if run['status']=='passed' else None})
            if run['status']!='passed':raise RuntimeError('owned runtime failed, persisted honestly')
    finally:set_context(None)


if __name__=='__main__':main()
