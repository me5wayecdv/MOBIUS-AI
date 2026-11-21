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

from handoff_io import read,write,json_write,wait,digest,exists,publish_directory,public_directory
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


def verify_root_inputs(backend='jail'):
    # File closure content is verified again by each fixed wrapper, never trust
    # archive SHA256 as a staged executable/library closure. No licenses accepted.
    # Docker backend: the image-inventory lock (typed rows, see image_closure/docker_lifecycle.inventory_matches) replaces the jail lock.
    lock_dirs=('/opt/d061-android-closure','/opt/d061-control-closure') if backend=='jail' else ('/opt/d061-docker-closure/runtime','/opt/d061-docker-closure/control')
    runtime=root_file(lock_dirs[0]+'/closure-lock.json',16*1024**2)
    control=root_file(lock_dirs[1]+'/closure-lock.json',16*1024**2)
    source=root_file(SOURCE/'source-manifest.json',1048576)
    lock=json.loads(source)
    if lock.get('status')!='EXACT_REVIEWED_SIBLING_SOURCE_LOCK':raise ValueError('source lock unresolved')
    required={'sibling_supervisor.py','namespace_supervisor.py','contained_driver.py','control_driver.py',
        'handoff_protocol.py','handoff_io.py','owned_collect.py','owned_absence.py','owned_product_setup.py',
        'adb_scope.py','emulator_scope.py','build_owned.py','app_negative_preparation.py','profile.py','product_contract.py','outer_owner.py'}
    if backend=='docker':required=required|{'docker_lifecycle.py','docker_owner.py','image_closure.py','container_gate.py'}
    rows=lock.get('files',[])
    if len(rows)!=len(required) or {row['path'] for row in rows}!=required:raise ValueError('fixed complete relay source set required')
    for row in rows:
        content=root_file(SOURCE/row['path'],262144)
        if digest(content)!=row['sha256'] or len(content)!=row['bytes']:raise ValueError('reviewed root relay source differs')
    return {'closure_sha256':digest(runtime),'control_closure_sha256':digest(control),
        'source_manifest_sha256':digest(source)}


def check_absent(output,root_stage=None,record_name="trusted-final-absence.json",recover_missing_wrapper=False):
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
    wrapper_path=Path(output)/'wrapper-cleanup.json'
    original_cleanup_present=exists(wrapper_path)
    if setup.get('backend')=='docker':
        # Backend-tagged branch. Jail validation below is untouched for untagged records.
        import docker_lifecycle
        if recover_missing_wrapper:
            errors.append('docker_recovery_unverified_no_independent_signal')
        elif original_cleanup_present:
            problems=docker_lifecycle.wrapper_problems(setup,json.loads(read(wrapper_path,65536)),role=Path(output).name,run_id=Path(output).parent.name.rsplit('-',1)[-1])
            if problems:errors.extend('docker_'+x for x in problems)
        else:errors.append('wrapper_cleanup_missing_unverified')
    elif original_cleanup_present:
        wrapper=json.loads(read(wrapper_path,65536))
        if wrapper.get('errors') or not wrapper.get('jail_absent'):errors.append('wrapper_cleanup_incomplete')
    elif not recover_missing_wrapper:errors.append('wrapper_cleanup_missing_unverified')
    if recover_missing_wrapper and not remaining and not errors:
        # Independent recovery uses an exact trusted pre-effect jail locator,
        # never reconstructs/replaces the missing original wrapper report.
        from handoff_io import remove
        intent=json.loads(read(Path(output)/'root-jail-intent.json',65536))
        jail=Path(intent['jail'])
        if (intent.get('root_owned') is not True or jail.parent!=Path('/opt')
            or not jail.name.startswith('d061-owned-android-jail-')):
            raise ValueError('trusted exact jail intent missing')
        for relative in ('work/evidence/home','work/evidence/origin.key','work/build/private-build-home'):
            try:remove(Path(output)/relative)
            except FileNotFoundError:pass
        try:remove(jail)
        except FileNotFoundError:pass
        if exists(jail):errors.append('recovery_jail_remains')
    runtime_inspection=None
    if Path(output).name=='runtime' and not recover_missing_wrapper:
        from owned_absence import inspect
        runtime_inspection=inspect(output,root_stage=root_stage)
        if not runtime_inspection['complete']:errors.append('runtime_stage_absence_unverified')
    state={'original_wrapper_cleanup_present':original_cleanup_present,
        'recovery_only_not_original_cleanup_proof':recover_missing_wrapper,
        'runtime_stage_absence':runtime_inspection,'complete':not remaining and not errors,'errors':errors,'remaining_namespace_members_or_handles':remaining,
        'scope':Path(output).name,'trusted_relay_namespace_handles_open':False}
    json_write(Path(output)/record_name,state)
    if not state['complete']:raise RuntimeError('sibling final absence incomplete')
    return state


def publish_accepted(staged,destination,*,state,collection_started,deadline,clock=time.monotonic):
    # The only visibility transition. Staging is private and may contain a failed
    # result, but no passed result is visible before full validation/deadline.
    now=clock()
    if now>deadline:
        state.fail('TimeoutError');raise TimeoutError('root collection deadline before publication')
    state.advance('collected',seconds=now-collection_started)
    if clock()>deadline:
        state.fail('TimeoutError');raise TimeoutError('root collection deadline at publication')
    publish_directory(staged,destination)


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD complete exact sibling relay/closure/lifecycle review required')
    if os.geteuid()!=0:raise RuntimeError('trusted disposable CI root supervisor only')
    os.umask(0o077)
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--owned-root',type=Path,required=True);args=parser.parse_args()
    root=args.owned_root
    if root.parent!=Path('/opt') or not root.name.startswith('d061-owned-android-run-'):
        raise ValueError('outer owner exact root required')
    owner=json.loads(root_file(root/'outer-owner-intent.json',65536))
    run_id=owner['run_id'];provisioning_id=owner['provisioning_id']
    if root.name!='d061-owned-android-run-'+run_id:raise ValueError('outer root identity differs')
    backend=owner.get('backend','jail')
    if backend not in ('jail','docker'):raise ValueError('closed backend set')
    inputs=verify_root_inputs(backend)
    expected=ExpectedContext(run_id=run_id,provisioning_id=provisioning_id,
        closure_sha256=inputs['closure_sha256'],source_manifest_sha256=inputs['source_manifest_sha256'])
    ctx={**inputs,'run_id':run_id,'provisioning_id':provisioning_id,'host_netns':os.readlink('/proc/self/ns/net')}
    for role in ('runtime','control'):
        inbox=root/(role+'-in');public_directory(inbox);json_write(inbox/'context.json',ctx)
    run_intent={'context':ctx,'root_identity':process_identity(os.getpid()),
        'fixed_roles':['runtime','control'],'launches':0,'owner_approval':False}
    json_write(root/'trusted-run-intent.json',run_intent)
    state=LifecycleState();children={};producer=Producers(CLEAN);failure=None;errors=[];request=None;result_delivered=False
    root_stage={'runtime_launched':False,'emulator_expected':False,'app_expected':False}
    launch_count=0
    old_handlers={}
    def interrupted(sig,frame):raise SystemExit(128+sig)
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):old_handlers[sig]=signal.signal(sig,interrupted)
    docker_owners={}
    def launch_docker(role):
        # Docker backend: the trusted owner module binds identity before release; call sites below keep the same child-like shape.
        import docker_owner,docker_lifecycle
        spec=owner['docker']   # {'image','mem_mb','pids','cpus','kvm_gid'} from the root-owned owner intent, never from a payload
        params={k:spec[k] for k in ('mem_mb','pids','cpus')};params['kvm_gid']=spec.get('kvm_gid') if role=='runtime' else None
        proc=docker_owner.HostProc()
        other=docker_owners.get('control' if role=='runtime' else 'runtime')
        sibling=None if other is None else {k:other.bound[k] for k in docker_lifecycle.NS_KEYS}
        o=docker_owner.RoleOwner(root,role,run_id,spec['image'],params,docker_owner.DockerCli(),proc,sibling_ns=sibling)
        docker_owners[role]=o
        handle=o.launch()
        return handle
    def launch(role):
        nonlocal launch_count
        if role in children:raise RuntimeError('fixed sibling launch already consumed')
        if backend=='docker':
            launch_count+=1;run_intent['launches']=launch_count
            json_write(root/'trusted-run-intent.json',run_intent,replace=True)
            children[role]=launch_docker(role)
            if role=='runtime':root_stage['runtime_launched']=True
            return children[role]
        closure='/opt/d061-android-closure' if role=='runtime' else '/opt/d061-control-closure'
        launch_count+=1
        run_intent['launches']=launch_count
        json_write(root/'trusted-run-intent.json',run_intent,replace=True)
        json_write(root/(role+'-launch-intent.json'),{'role':role,'exact_output':str(root/role),
            'root_owned':True,'stage':'before_launch','launch_count':launch_count})
        json_write(root/'trusted-run-progress.json',{'launches':launch_count,'role':role,'stage':'before_launch'},replace=True)
        child=producer.start([sys.executable,SOURCE/'namespace_supervisor.py','--role',role,
            '--closure-root',closure,'--closure-lock',closure+'/closure-lock.json','--output',root/role],role,root,bind_parent=True)
        children[role]=child
        if role=='runtime':root_stage['runtime_launched']=True
        json_write(root/(role+'-launch.json'),{'role':role,'identity':process_identity(child.pid),
            'started_monotonic':time.monotonic(),'root_owned_lifecycle':True})
        json_write(root/'trusted-run-progress.json',{'launches':launch_count,'role':role,'stage':'child_started',
            'identity':process_identity(child.pid)},replace=True)
        return child
    def pump():
        producer.pump()
        stage_request=root/'runtime/work/emulator-stage-request.json'
        if not root_stage['emulator_expected'] and exists(stage_request):
            record=json.loads(read(stage_request,65536))
            if record!={'version':'owned-emulator-stage/1','run_id':run_id}:raise ValueError('fixed emulator stage intent')
            root_stage['emulator_expected']=True
            json_write(root/'runtime-root-stage.json',root_stage,replace=True)
            json_write(root/'runtime-in/emulator-stage-ack.json',record)
        if 'control' in children and exists(root/'control/work/cancel.json'):
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
        snapshot=root/'control-in/snapshot';public_directory(snapshot)
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
        operation_started=time.monotonic()
        root_stage['app_expected']=True;json_write(root/'runtime-root-stage.json',root_stage,replace=True)
        json_write(root/'runtime-in/commit.json',commit)
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
        runtime.wait()
        if backend=='docker':docker_owners['runtime'].cleanup(runtime)
        check_absent(root/'runtime',root_stage)
        state.advance('runtime_absent',seconds=time.monotonic()-teardown_started)
        collection_started=time.monotonic()
        staged=root/'private-collected-result'
        collect(root/'runtime',request,staged,command_rc=runtime.returncode,root_stage=root_stage,deadline=collection_started+10)
        publish_accepted(staged,root/'control-in/result',state=state,collection_started=collection_started,deadline=collection_started+10)
        result_delivered=True
        while control.poll() is None:
            pump()
            if time.monotonic()-collection_started>30:raise TimeoutError('fixed control persistence/report ceiling')
            time.sleep(.05)
        control.wait()
        if backend=='docker':docker_owners['control'].cleanup(control)
        check_absent(root/'control')
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
                if runtime is not None and backend=='docker' and runtime.poll() is None:
                    # live-owner kill by held identity and bound container ID only, never a group kill
                    docker_owners['runtime'].kill_bound()
                    runtime.wait(timeout=45)
                elif runtime is not None and runtime.poll() is None:
                    os.killpg(runtime.pid,signal.SIGTERM)
                    try:runtime.wait(timeout=45)
                    except subprocess.TimeoutExpired:os.killpg(runtime.pid,signal.SIGKILL);runtime.wait(timeout=5)
                if runtime is not None:
                    try:check_absent(root/'runtime',root_stage)
                    except BaseException as error:errors.append({'stage':'failed_runtime_absence','class':type(error).__name__})
                result_root=root/'control-in/result'
                if result_root.exists():
                    # A partially published collector result is not overwritten
                    # or upgraded. Keep it and stop rather than retry collection.
                    if not (result_root/'result.json').exists():raise RuntimeError('partial immutable result publication')
                else:
                    public_directory(result_root)
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
        if backend=='docker':
            for role,o in docker_owners.items():
                try:
                    if not exists(root/role/'wrapper-cleanup.json') and role in children:o.cleanup(children[role])
                except BaseException as error:errors.append({'stage':role+'_docker_cleanup','class':type(error).__name__})
        for role,child in children.items():
            try:
                if child.poll() is None:raise RuntimeError('sibling leader not reaped')
                # Original failures stay failures even when final namespace
                # recovery succeeds. Never re-launch or replay a consumed commit.
                final=root/role/'trusted-final-absence.json'
                if not exists(final):check_absent(root/role,root_stage if role=='runtime' else None)
            except BaseException as error:errors.append({'stage':role+'_final_absence','class':type(error).__name__})
        json_write(root/'trusted-relay-result.json',{'complete':failure is None and not errors,
            'errors':errors,'original_error':None if failure is None else type(failure).__name__,
            'state':state.stage,'state_failure':state.failure,'phase_records':state.records,
            'launch_count':launch_count,'root_stage':root_stage,'commit_consumed':expected.used,'context_failed':expected.failed,'root':str(root)})
        for sig,handler in old_handlers.items():signal.signal(sig,handler)
    if failure:raise failure
    if errors:raise RuntimeError('sibling relay cleanup incomplete')


if __name__=='__main__':main()
