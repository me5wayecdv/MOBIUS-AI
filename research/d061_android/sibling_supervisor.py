"""HELD trusted fixed root relay for TWO SIBLING no-uplink jails.

Not an API privilege service. No caller argv/path/UID/namespace/endpoint choice.
Only exact reviewed closures/entrypoints and one immutable public snapshot, one
bound commit, and one post-absence result are accepted. No execution on import.
"""
from dataclasses import asdict
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
import time

from handoff_io import read,write,json_write,wait,digest
from handoff_protocol import ExpectedContext,LifecycleState,validate_provisioned,canonical
from emulator_scope import process_identity
from contained_driver import Producers
from owned_collect import collect

APPROVED_FOR_EXECUTION = False
SOURCE=Path('/opt/d061-owned-reviewed-source')
CLEAN={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','HOME':'/nonexistent'}


def root_file(path,limit):
    path=Path(path)
    if path.stat().st_uid!=0 or path.stat().st_mode&0o022:raise ValueError('root-owned immutable reviewed input required')
    return read(path,limit)


def verify_root_inputs():
    # File closure content is verified again by each fixed wrapper, never trust
    # archive SHA256 as a staged executable/library closure. No licenses accepted.
    runtime=root_file('/opt/d061-android-closure/closure-lock.json',16*1024**2)
    control=root_file('/opt/d061-control-closure/closure-lock.json',16*1024**2)
    source=root_file(SOURCE/'source-manifest.json',1048576)
    lock=json.loads(source)
    if lock.get('status')!='EXACT_REVIEWED_SIBLING_SOURCE_LOCK':raise ValueError('source lock unresolved')
    required={'sibling_supervisor.py','namespace_supervisor.py','contained_driver.py','control_driver.py',
        'handoff_protocol.py','handoff_io.py','owned_collect.py','owned_absence.py','owned_product_setup.py',
        'adb_scope.py','emulator_scope.py','build_owned.py','profile.py','product_contract.py'}
    rows=lock.get('files',[])
    if len(rows)!=len(required) or {row['path'] for row in rows}!=required:raise ValueError('fixed complete relay source set required')
    for row in rows:
        content=root_file(SOURCE/row['path'],262144)
        if digest(content)!=row['sha256'] or len(content)!=row['bytes']:raise ValueError('reviewed root relay source differs')
    return {'closure_sha256':digest(runtime),'control_closure_sha256':digest(control),
        'source_manifest_sha256':digest(source)}


def check_absent(output):
    # Distinct runtime and control namespace claims. Root holds no namespace FDs;
    # record scanning all visible process memberships AND open namespace handles.
    setup=json.loads(read(Path(output)/'namespace-setup.json',1048576))
    expected={setup['namespaces'][name] for name in ('net','mnt','pid')}
    remaining=[];errors=[]
    for process in Path('/proc').glob('[0-9]*'):
        for kind in ('net','mnt','pid'):
            try:
                path=process/'ns'/kind
                if os.readlink(path) in expected:remaining.append(str(path))
            except FileNotFoundError:pass
            except PermissionError:errors.append('namespace_unreadable')
        try:
            for path in (process/'fd').iterdir():
                try:
                    if os.readlink(path) in expected:remaining.append(str(path))
                except FileNotFoundError:pass
                except PermissionError:errors.append('namespace_handle_unreadable')
        except FileNotFoundError:pass
        except PermissionError:errors.append('fd_directory_unreadable')
    wrapper=json.loads(read(Path(output)/'wrapper-cleanup.json',65536))
    if wrapper.get('errors') or not wrapper.get('jail_absent'):errors.append('wrapper_cleanup_incomplete')
    state={'complete':not remaining and not errors,'errors':errors,'remaining_namespace_members_or_handles':remaining,
        'scope':Path(output).name,'trusted_relay_namespace_handles_open':False}
    json_write(Path(output)/'trusted-final-absence.json',state)
    if not state['complete']:raise RuntimeError('sibling final absence incomplete')
    return state


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD complete exact sibling relay/closure/lifecycle review required')
    if os.geteuid()!=0:raise RuntimeError('trusted disposable CI root supervisor only')
    os.umask(0o077)
    inputs=verify_root_inputs();run_id=secrets.token_hex(16);provisioning_id=secrets.token_hex(16)
    root=Path('/opt')/('d061-owned-android-run-'+run_id);root.mkdir(mode=0o700,exist_ok=False)
    expected=ExpectedContext(run_id=run_id,provisioning_id=provisioning_id,
        closure_sha256=inputs['closure_sha256'],source_manifest_sha256=inputs['source_manifest_sha256'])
    ctx={**inputs,'run_id':run_id,'provisioning_id':provisioning_id,'host_netns':os.readlink('/proc/self/ns/net')}
    for role in ('runtime','control'):
        inbox=root/(role+'-in');inbox.mkdir(mode=0o755);json_write(inbox/'context.json',ctx)
    json_write(root/'trusted-run-intent.json',{'context':ctx,'root_identity':process_identity(os.getpid()),
        'fixed_roles':['runtime','control'],'launches':0,'owner_approval':False})
    state=LifecycleState();children={};producer=Producers(CLEAN);failure=None;errors=[];request=None;result_delivered=False
    old_handlers={}
    def interrupted(sig,frame):raise SystemExit(128+sig)
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):old_handlers[sig]=signal.signal(sig,interrupted)
    def launch(role):
        if role in children:raise RuntimeError('fixed sibling launch already consumed')
        closure='/opt/d061-android-closure' if role=='runtime' else '/opt/d061-control-closure'
        child=producer.start([sys.executable,SOURCE/'namespace_supervisor.py','--role',role,
            '--closure-root',closure,'--closure-lock',closure+'/closure-lock.json','--output',root/role],role,root)
        children[role]=child
        json_write(root/(role+'-launch.json'),{'role':role,'identity':process_identity(child.pid),
            'started_monotonic':time.monotonic(),'root_owned_lifecycle':True})
        return child
    def pump():
        producer.pump()
        if 'control' in children and (root/'control/work/cancel.json').exists():
            raise RuntimeError('fixed one-shot control cancellation')
    try:
        started=time.monotonic();runtime=launch('runtime')
        raw=wait(root/'runtime/work/provision/ready.json',deadline=started+240,child=runtime,pump=pump)
        ready=json.loads(raw);expected.accept_ready(ready)
        evidence=root/'runtime/work/evidence'
        if (evidence/'initial.native').exists() or (evidence/'backend-receipts.json').exists():
            raise ValueError('root observed native/origin traffic before approval')
        zero=json.loads(read(evidence/'provision-zero-state.json',65536))
        if not all(zero.get(key) is True for key in ('owned_package_absent','native_original_absent','origin_receipts_absent')):
            raise ValueError('explicit zero preapproval state missing')
        public=root/'runtime/work/provision'
        apk=read(public/'owned-fixture.apk',4*1024**2);ca=read(public/'public-ca.der',16384)
        build=read(public/'build-result.json',65536)
        validate_provisioned(ready,apk=apk,public_ca_der=ca,build_json=build,
            expected_source_manifest_sha256=inputs['source_manifest_sha256'])
        state.advance('provisioned',seconds=time.monotonic()-started,
            originals=ready['original_count'],receipts=ready['origin_receipt_count'])
        snapshot=root/'control-in/snapshot';snapshot.mkdir(mode=0o755)
        # Child never receives these root-owned samefiles. All bytes copied from
        # already bounded reads. Publish ready LAST after immutable public files.
        write(snapshot/'owned-fixture.apk',apk);write(snapshot/'public-ca.der',ca)
        write(snapshot/'build-result.json',build);json_write(snapshot/'ready.json',ready)
        ready_at=time.monotonic();control=launch('control')
        commit=json.loads(wait(root/'control/work/commit.json',deadline=ready_at+30,child=control,pump=pump))
        request=expected.consume(commit)
        state.advance('committed',seconds=time.monotonic()-ready_at)
        # Trusted root validates fixed format/snapshot identity only. It does not
        # claim to authenticate the API grant; product owns committed checks.
        operation_started=time.monotonic();json_write(root/'runtime-in/commit.json',commit)
        operation_path=root/'runtime/work/evidence/operation-returned.json'
        operation=json.loads(wait(operation_path,deadline=operation_started+60,child=runtime,pump=pump))
        if operation.get('request')!=asdict(request) or operation.get('operation_completed') is not True:
            raise ValueError('fixed operation result binding differs')
        evidence=root/'runtime/work/evidence'
        events=json.loads(read(evidence/'native-events.json',65536))
        receipts=json.loads(read(evidence/'backend-receipts.json',65536))
        if not isinstance(events,list) or not isinstance(receipts,list):raise ValueError('actual runtime event counts missing')
        originals=sum(not e.get('is_replay') for e in events)
        state.advance('operation_returned',seconds=time.monotonic()-operation_started,originals=originals,receipts=len(receipts))
        teardown_started=time.monotonic()
        while runtime.poll() is None:
            pump()
            if time.monotonic()-teardown_started>60:raise TimeoutError('root-monotonic runtime teardown ceiling')
            time.sleep(.05)
        runtime.wait();check_absent(root/'runtime')
        state.advance('runtime_absent',seconds=time.monotonic()-teardown_started)
        collection_started=time.monotonic()
        collect(root/'runtime',request,root/'control-in/result',command_rc=runtime.returncode)
        result_delivered=True
        state.advance('collected',seconds=time.monotonic()-collection_started)
        while control.poll() is None:
            pump()
            if time.monotonic()-collection_started>30:raise TimeoutError('fixed control persistence/report ceiling')
            time.sleep(.05)
        control.wait();check_absent(root/'control')
        if control.returncode!=0:raise RuntimeError('control product journey failed')
    except BaseException as error:
        failure=error
        if state.failure is None:state.fail(type(error).__name__)
    finally:
        for sig in old_handlers:signal.signal(sig,signal.SIG_IGN)
        # A failed operation still returns attributed failure diagnostics through
        # product persistence. No retry, reconstructed capture, or fake absence.
        if request is not None and not result_delivered and 'control' in children:
            runtime=children.get('runtime')
            try:
                if runtime is not None and runtime.poll() is None:
                    os.killpg(runtime.pid,signal.SIGTERM)
                    try:runtime.wait(timeout=45)
                    except subprocess.TimeoutExpired:os.killpg(runtime.pid,signal.SIGKILL);runtime.wait(timeout=5)
                if runtime is not None:
                    try:check_absent(root/'runtime')
                    except BaseException as error:errors.append({'stage':'failed_runtime_absence','class':type(error).__name__})
                result_root=root/'control-in/result'
                if result_root.exists():
                    # A partially published collector result is not overwritten
                    # or upgraded. Keep it and stop rather than retry collection.
                    if not (result_root/'result.json').exists():raise RuntimeError('partial immutable result publication')
                else:
                    result_root.mkdir(mode=0o755)
                    binding=canonical(asdict(request))
                    diagnostic=canonical({'code':'host_failed','original_error':None if failure is None else type(failure).__name__,
                        'binding_json_source':'trusted_relay_expected_request_not_original_host_proof',
                        'not_a_capture_or_cleanup_proof':True,'root_lifecycle_errors':errors})
                    write(result_root/'binding.json',binding);write(result_root/'host-failure.json',diagnostic)
                    json_write(result_root/'result.json',{'status':'failed','failure_code':'host_failed',
                        'tool_versions':['owned-android-fixed-relay/0.1.0-held'],'request':asdict(request),
                        'files':[{'name':name,'bytes':len(data),'sha256':digest(data)} for name,data in
                            [('binding.json',binding),('host-failure.json',diagnostic)]]})
                result_delivered=True
                until=time.monotonic()+30
                while children['control'].poll() is None and time.monotonic()<until:
                    producer.pump();time.sleep(.05)
            except BaseException as error:errors.append({'stage':'failed_product_return','class':type(error).__name__})
        try:producer.stop()
        except BaseException as error:errors.append({'stage':'siblings_stop','class':type(error).__name__})
        for role,child in children.items():
            try:
                if child.poll() is None:raise RuntimeError('sibling leader not reaped')
                # Original failures stay failures even when final namespace
                # recovery succeeds. Never re-launch or replay a consumed commit.
                final=root/role/'trusted-final-absence.json'
                if not final.exists():check_absent(root/role)
            except BaseException as error:errors.append({'stage':role+'_final_absence','class':type(error).__name__})
        json_write(root/'trusted-relay-result.json',{'complete':failure is None and not errors,
            'errors':errors,'original_error':None if failure is None else type(failure).__name__,
            'state':state.stage,'state_failure':state.failure,'phase_records':state.records,
            'commit_consumed':expected.used,'context_failed':expected.failed,'root':str(root)})
        for sig,handler in old_handlers.items():signal.signal(sig,handler)
    if failure:raise failure
    if errors:raise RuntimeError('sibling relay cleanup incomplete')


if __name__=='__main__':main()
