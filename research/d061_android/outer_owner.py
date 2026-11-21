"""HELD independent outer owner with durable exact root/relay recovery locators.

This is the workflow entrypoint, outside the relay and both payloads. No owner
account or production host use. A killed relay cannot erase its owner's exact
locator/launch intent. Recovery never discovers processes by name or prefix.
"""
import ctypes
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time

from handoff_io import read,json_write,exists,remove
from emulator_scope import process_identity

APPROVED_FOR_EXECUTION = False
SOURCE=Path('/opt/d061-owned-reviewed-source')
LOCATOR=Path('/opt/d061-owned-android-owner.json')
CLEAN={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LANG':'C.UTF-8'}


def terminate(record,seconds=10):
    # Identity before and after pidfd open, never signal a reused numeric PID.
    try:
        if process_identity(record['pid'])!=record:return {'state':'already_absent_or_identity_changed'}
    except (FileNotFoundError,ProcessLookupError):return {'state':'already_absent'}
    fd=os.pidfd_open(record['pid'])
    try:
        if process_identity(record['pid'])!=record:return {'state':'identity_changed_before_signal'}
        signal.pidfd_send_signal(fd,signal.SIGKILL)
        import select
        if not select.select([fd],[],[],seconds)[0]:raise TimeoutError('owned identity not terminated')
        return {'state':'terminated'}
    finally:os.close(fd)


def recover(root,*,attempt_id=None):
    # Independently called after relay death/failure. Separate recovery report,
    # never rewrite missing original cleanup into a fake successful wrapper log.
    from sibling_supervisor import check_absent
    root=Path(root);errors=[];roles=[]
    attempt_id=attempt_id or secrets.token_hex(16)
    import re
    if re.fullmatch('[0-9a-f]{32}',attempt_id) is None:raise ValueError('unique recovery attempt ID required')
    json_write(root/('outer-recovery-intent-'+attempt_id+'.json'),{'attempt_id':attempt_id,
        'root':str(root),'stage':'before_recovery_effects','scope':'independent_outer_recovery'})
    stage_path=root/'runtime-root-stage.json'
    stage=json.loads(read(stage_path,65536)) if exists(stage_path) else None
    for role in ('runtime','control'):
        intent=root/(role+'-launch-intent.json');launched=root/(role+'-launch.json')
        if not exists(intent):roles.append({'role':role,'state':'not_reached'});continue
        state={'role':role,'state':'expected_but_unverified'}
        try:
            if not exists(launched):raise RuntimeError('launch identity missing after launch intent')
            identity=json.loads(read(launched,65536))['identity']
            state['termination']=terminate(identity)
            # Parent-death closes unshare PID1. Membership/FD absence is checked
            # independently; a missing setup record remains unverified, not clean.
            wrapper=root/role/'wrapper-cleanup.json'
            state['absence']=check_absent(root/role,stage if role=='runtime' else None,record_name='outer-independent-absence-'+attempt_id+'.json',recover_missing_wrapper=True)
            state['state']='verified_absent'
        except BaseException as error:
            errors.append({'role':role,'class':type(error).__name__})
        roles.append(state)
    result={'attempt_id':attempt_id,'complete':not errors,'errors':errors,'roles':roles,
        'scope':'outer_recovery_only_not_original_runtime_or_capture_proof'}
    json_write(root/('outer-recovery-'+attempt_id+'.json'),result)
    return result


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD exact complete outer/relay/closure review required')
    if os.geteuid()!=0:raise RuntimeError('disposable CI root owner only')
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--recover-only',action='store_true');args=parser.parse_args()
    if args.recover_only:
        owner=json.loads(read(LOCATOR,65536))
        root=Path(owner['root'])
        if root.parent!=Path('/opt') or root.name!='d061-owned-android-run-'+owner['run_id']:
            raise ValueError('exact independent recovery locator differs')
        record=owner.get('relay_identity')
        if record is not None:terminate(record)
        result=recover(root)
        if not result['complete']:raise RuntimeError('independent outer recovery incomplete')
        return
    os.umask(0o077);run_id=secrets.token_hex(16);provisioning_id=secrets.token_hex(16)
    root=Path('/opt')/('d061-owned-android-run-'+run_id)
    owner={'version':'owned-android-owner/1','run_id':run_id,'provisioning_id':provisioning_id,
        'root':str(root),'owner_identity':process_identity(os.getpid()),'stage':'before_root_creation',
        'relay_launch_expected':False,'relay_identity':None}
    # Exact external locator created BEFORE the run-root or any relay effect.
    # One-shot publication refuses another active owner, never silently replaces.
    json_write(LOCATOR,owner)
    root.mkdir(mode=0o700)
    json_write(root/'outer-owner-intent.json',owner)
    child=None;failure=None;errors=[]
    def interrupted(sig,frame):raise SystemExit(128+sig)
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,interrupted)
    try:
        owner.update(stage='before_relay_launch',relay_launch_expected=True)
        json_write(LOCATOR,owner,replace=True);json_write(root/'outer-owner-progress.json',owner,replace=True)
        from contained_driver import Producers
        logs=Producers(CLEAN)
        try:
            child=logs.start([sys.executable,str(SOURCE/'sibling_supervisor.py'),'--owned-root',str(root)],
                'relay',root,bind_parent=True)
            owner.update(stage='relay_started',relay_identity=process_identity(child.pid))
            json_write(LOCATOR,owner,replace=True);json_write(root/'outer-owner-progress.json',owner,replace=True)
            until=time.monotonic()+540
            while child.poll() is None:
                logs.pump()
                if time.monotonic()>until:raise TimeoutError('fixed outer relay ceiling')
                time.sleep(.05)
            logs.pump();rc=child.wait()
            owner.update(stage='relay_returned',relay_rc=rc)
            if rc:raise RuntimeError('owned sibling relay failed')
        finally:logs.stop()
    except BaseException as error:failure=error
    finally:
        for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
        if child is not None and child.poll() is None:
            try:
                terminate(owner['relay_identity']);child.wait(timeout=10)
            except BaseException as error:errors.append({'stage':'relay_stop','class':type(error).__name__})
        try:
            recovery=recover(root)
            if not recovery['complete']:errors.append({'stage':'outer_recovery','class':'Incomplete'})
        except BaseException as error:errors.append({'stage':'outer_recovery','class':type(error).__name__})
        owner.update(stage='owner_returned',complete=failure is None and not errors,
            errors=errors,original_error=None if failure is None else type(failure).__name__)
        json_write(root/'outer-owner-result.json',owner)
        json_write(LOCATOR,owner,replace=True)
    if failure:raise failure
    if errors:raise RuntimeError('outer owner recovery incomplete')


if __name__=='__main__':main()
