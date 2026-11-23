#!/usr/bin/env python3
"""Preparation-only entry point, never wired to CI/startup.

Explicit invocation MUTATES a fresh local test API using a fixed synthetic APK.
It requires separate runtime authorization. No model, emulator, approvals,
external target, publication, DB edits, worker seeding or inline fallback.
A pass is queue/API plumbing, not provider-flow semantics or isolation proof.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import sys
import time
import uuid
from urllib.parse import urlparse

ROOT=Path(__file__).resolve().parents[1]


def fixed_fixture() -> bytes:
    """Same existing binary AXML + actual DEX as the RECON/DEX CI canary.

    The DEX does NOT contain provider source/sink classes. Empty provider
    exposures are expected, never replaced with supplied detector output.
    """
    import io
    from zipfile import ZipFile,ZipInfo,ZIP_DEFLATED
    sys.path.insert(0,str(ROOT/'tests'))
    from _axml import encode,manifest_xml
    stream=io.BytesIO()
    with ZipFile(stream,'w') as archive:
        for name,data in [('AndroidManifest.xml',encode(manifest_xml())),
                          ('classes.dex',(ROOT/'tests/fixtures/dex/AnalysisTest.dex').read_bytes())]:
            info=ZipInfo(name,date_time=(2020,1,1,0,0,0));info.compress_type=ZIP_DEFLATED
            info.external_attr=0o100644<<16;archive.writestr(info,data)
    return stream.getvalue()


def run_canary(apk:bytes,request,upload,*,expect_worker_id:str,clock=time.monotonic,sleep=time.sleep,budget=900)->dict:
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}",expect_worker_id) is None:raise ValueError("explicit literal worker identity required")
    deadline=clock()+budget
    def req(method,path,body=None):
        if clock()>=deadline:raise TimeoutError('canary shared deadline')
        return request(method,path,body)
    # No writes if this capability is missing, fails or shows any application.
    # Current API has no applications-list route: intentionally fail closed until
    # an independently reviewed fresh-host attestation seam exists.
    applications=req('GET','/applications')
    if applications != []:raise ValueError('empty applications list required before any write')
    app=upload(apk)
    sha=hashlib.sha256(apk).hexdigest()
    if app.get('sha256')!=sha:raise ValueError('uploaded digest mismatch')
    auth=req('POST','/authorizations',{'apk_sha256':sha,'target_package':'com.example.demo',
        'scope_text':'Fixed synthetic three-worker static canary only; no model or device.',
        'statement':'Synthetic test record, not owner authorization.', 'max_intensity':0,
        'expires_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time()+3600))})
    scan=req('POST','/scans',{'application_id':app['id'],'authorization_id':auth['id'],
        'objective':'Synthetic model-free isolated three-worker canary','intensity':0})
    sid=scan['id'];jobs=[]
    # Provider application leaves SURFACE_READY intact; DEX advances it.
    for kind in ('recon','provider-analysis','spectre'):
        stem=f'/scans/{sid}/{kind}/jobs'
        job_id=req('POST',stem)['job_id']
        if not isinstance(job_id,str) or str(uuid.UUID(job_id))!=job_id:raise ValueError('noncanonical worker job identity')
        while True:
            result=req('GET',stem+'/'+job_id)
            if result.get('status')=='succeeded':break
            if result.get('status') not in ('queued','running'):raise ValueError('worker failed or returned unknown state')
            sleep(min(1,max(0,deadline-clock())))
        if result.get('worker_id')!=expect_worker_id or not result.get('started_at') or not result.get('finished_at'):
            raise ValueError('completed worker provenance missing')
        req('POST',stem+'/'+job_id+'/apply')
        applied=req('GET',stem+'/'+job_id)
        if applied.get('applied') is not True:raise ValueError('worker result not applied')
        jobs.append({'kind':kind,'job_id':job_id,'worker_id':result['worker_id']})
    detail=req('GET',f'/scans/{sid}')
    if (detail.get('application') or {}).get('sha256')!=sha:raise ValueError('scan APK binding changed')
    if (detail.get('application') or {}).get('package_name')!='com.example.demo':raise ValueError('parsed canary package mismatch')
    package=req('GET',f'/scans/{sid}/evidence-package')
    if not package.get('observations') or not package.get('evidence'):raise ValueError('persisted evidence missing')
    return {'status':'canary_api_jobs_applied','scan_id':sid,'apk_sha256':sha,'jobs':jobs,
        'model_called':False,'device_used':False,'provider_flow_semantics_proven':False,
        'isolation_kernel_enforcement_proven':False,
        'limitations':['Fixed DEX has no provider flow; this is not a model-evidence-readiness gate.',
            'API worker provenance is not independent isolation proof; run existing OCI contract probe separately.',
            'No model hypothesis, security test, deployment uptime or whole-agent readiness established.']}


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api',required=True)
    parser.add_argument('--expect-worker-id',required=True)
    parser.add_argument('--execute-local-canary',action='store_true',help='Required explicit acknowledgement, not permission')
    args=parser.parse_args()
    url=urlparse(args.api)
    if (url.scheme!='http' or url.hostname not in ('127.0.0.1','localhost') or url.username or url.password
        or url.path not in ('','/') or url.query or url.fragment):parser.error('loopback-only plain HTTP API root required')
    if not args.execute_local_canary:parser.error('preparation only unless explicitly invoked with acknowledgement')
    # Reuse the bounded stdlib HTTP transport, not the connected driver's main.
    spec=importlib.util.spec_from_file_location('canary_transport',ROOT/'scripts/connected_journey_smoke.py')
    transport=importlib.util.module_from_spec(spec);spec.loader.exec_module(transport)
    transport.BASE=args.api.rstrip('/');transport.CALL_DEADLINE=time.monotonic()+900
    def upload(apk):
        boundary='mobiuscanary'+uuid.uuid4().hex
        raw=(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="canary.apk"\r\n'
             'Content-Type: application/vnd.android.package-archive\r\n\r\n').encode()+apk+f'\r\n--{boundary}--\r\n'.encode()
        return transport.call('POST','/applications',raw=raw,headers={'Content-Type':f'multipart/form-data; boundary={boundary}'})
    import json
    try:
        result=run_canary(fixed_fixture(),transport.call,upload,expect_worker_id=args.expect_worker_id)
    except Exception as exc:
        # Never dump arbitrary provider/API bodies or local connection details.
        print(json.dumps({'status':'failed','error_type':type(exc).__name__}));return 1
    print(json.dumps(result,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
