"""HELD root-owned post-runtime collector, exact fixed artifact allowlist only."""
import json
from pathlib import Path
from dataclasses import asdict

from handoff_io import read,write,json_write,digest
from mobius.services.owned_android_fixture import OwnedAppAdapter,OwnedAppOutput,REQUIRED,DIAGNOSTICS,TRAFFIC_SOURCE
from owned_absence import inspect

APPROVED_FOR_EXECUTION = False


def collect(runtime,request,destination,*,command_rc):
    if not APPROVED_FOR_EXECUTION:raise RuntimeError('owned runtime collector HELD')
    runtime=Path(runtime);destination=Path(destination);destination.mkdir(mode=0o755,exist_ok=False)
    files={};errors=[];inventory=[];total=0
    for name in sorted((REQUIRED|DIAGNOSTICS)-{'collector-summary.json','wrapper-cleanup.json','independent-absence.json'}):
        source=runtime/'work/evidence'/name
        if not source.exists():continue
        try:
            content=read(source,min(1048576,max(0,request.max_evidence_bytes-total)))
            total+=len(content);files[name]=content
        except BaseException as error:errors.append({'stage':name,'class':type(error).__name__})
    for name,content in [('wrapper-cleanup.json',read(runtime/'wrapper-cleanup.json',65536)),
        ('independent-absence.json',json.dumps(inspect(runtime),sort_keys=True,separators=(',',':')).encode())]:
        total+=len(content);files[name]=content
    if not json.loads(files['independent-absence.json'])['complete']:errors.append({'stage':'absence','class':'Incomplete'})
    if command_rc!=0:errors.append({'stage':'runtime_command','class':'NonzeroExit'})
    if files.get('binding.json')!=json.dumps(asdict(request),sort_keys=True,separators=(',',':')).encode():
        errors.append({'stage':'original_binding','class':'MissingOrDifferent'})
    status='passed' if not errors else 'failed'
    if errors:
        # Root diagnostic is attributed as collector failure, never a reconstructed
        # original launch/capture/cleanup or counterfeit success record.
        files['host-failure.json']=json.dumps({'code':'host_collection_failed','collector_errors':errors,
            'original_host_failure_sha256':digest(files['host-failure.json']) if 'host-failure.json' in files else None,
            'not_a_capture_or_cleanup_proof':True},sort_keys=True).encode()
        files.setdefault('binding.json',json.dumps(asdict(request),sort_keys=True,separators=(',',':')).encode())
    copied=[{'path':name,'sha256':digest(content),'bytes':len(content)} for name,content in sorted(files.items())]
    files['collector-summary.json']=json.dumps({'success':not errors,'errors':errors,'binding':asdict(request),
        'traffic_source':TRAFFIC_SOURCE,'copied':copied,'runtime_command_rc':command_rc},sort_keys=True).encode()
    output=OwnedAppOutput(request,files,('mobius-owned-android/0.1.0-preparation',),status,
        None if status=='passed' else 'host_collection_failed')
    try:OwnedAppAdapter.validate(request,output)
    except BaseException as error:
        inventory=[{'name':name,'bytes':len(data),'sha256':digest(data)} for name,data in sorted(files.items())]
        # Keep bounded failed evidence, never overflow because omitted originals
        # were silently dropped. Hash inventory covers the omitted originals.
        files={'binding.json':json.dumps(asdict(request),sort_keys=True,separators=(',',':')).encode(),
            'host-failure.json':json.dumps({'code':'host_collection_failed','error_class':type(error).__name__,
                'original_inventory':inventory,'not_a_capture_or_cleanup_proof':True},sort_keys=True).encode()}
        status='failed'
    for name,data in files.items():write(destination/name,data)
    result={'status':status,'failure_code':None if status=='passed' else 'host_collection_failed',
        'tool_versions':list(output.tool_versions),'request':asdict(request),
        'files':[{'name':name,'sha256':digest(data),'bytes':len(data)} for name,data in sorted(files.items())]}
    json_write(destination/'result.json',result)
    return result
