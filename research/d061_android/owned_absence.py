"""HELD read-only independent stage-aware Android absence inspector.

Never launches/kills a process, executes ADB, deletes a file, or treats a missing
postlaunch record as clean. Exact workflow-owned root required for CLI. An
unlaunched empty root can be inspected only with require_launched=False.
"""
import json
import os
from pathlib import Path
import stat
from handoff_io import read as anchored_read,exists as anchored_exists

APPROVED_FOR_EXECUTION = False


def bounded_json(path):
    return json.loads(anchored_read(path,1048576))


def inspect(root,*,require_launched=True,proc=Path('/proc'),root_stage=None):
    root=Path(root)
    state={'complete':False,'errors':[],'missing_records':[],'remaining_namespace_members':[],
        'remaining_namespace_handles':[],'private_material_absent':False,'stage_required_records_complete':False,
        'reverse_mappings':None,'not_an_app_execution_or_capture_proof':True}
    def load(name):
        path=root/name
        if not anchored_exists(path):state['missing_records'].append(name);return None
        try:return bounded_json(path)
        except (OSError,ValueError,TypeError) as error:
            state['errors'].append({'stage':name,'class':type(error).__name__});return None
    if not root.exists():
        if require_launched:state['missing_records'].append('workflow-root')
        else:state.update(complete=True,stage_required_records_complete=True,private_material_absent=True,reverse_mappings=[])
        return state
    if root.is_symlink():state['errors'].append({'stage':'root','class':'symlink'});return state
    setup=load('namespace-setup.json');wrapper=load('wrapper-cleanup.json')
    if root_stage is not None:
        if set(root_stage)!={'runtime_launched','emulator_expected','app_expected'} or any(type(v) is not bool for v in root_stage.values()):
            raise ValueError('closed root-owned expected stage required')
        if root_stage['app_expected'] and not root_stage['emulator_expected']:raise ValueError('invalid root stage order')
    emulator_expected=True if root_stage is None else root_stage['emulator_expected']
    app_expected=require_launched if root_stage is None else root_stage['app_expected']
    state['obligations']={'emulator':'expected' if emulator_expected else 'not_reached',
        'app':'expected' if app_expected else 'not_reached','source':'independent_root_stage' if root_stage is not None else 'conservative_unspecified'}
    launched=anchored_exists(root/'work/evidence/owned-app-launch.json')
    # Infrastructure creation itself creates keys/AVD/process obligations even
    # when an app never launched. Every required record must be explicit.
    required=['driver-cleanup.json']
    if emulator_expected:required.append('emulator-cleanup.json')
    if app_expected:required.append('adb-cleanup.json')
    records={name:load('work/evidence/'+name) for name in required}
    if app_expected and not launched:state['missing_records'].append('work/evidence/owned-app-launch.json')
    if setup:
        namespaces=setup.get('namespaces',{})
        expected={namespaces.get(kind) for kind in ('net','mnt','pid')}
        if None in expected or len(expected)!=3:state['errors'].append({'stage':'namespace','class':'invalid_identity'})
        else:
            for process in proc.glob('[0-9]*'):
                for kind in ('net','mnt','pid'):
                    path=process/'ns'/kind
                    try:
                        if os.readlink(path) in expected:state['remaining_namespace_members'].append(str(path))
                    except FileNotFoundError:pass
                    except PermissionError:state['errors'].append({'stage':'namespace_scan','class':'unreadable'})
                try:
                    for descriptor in (process/'fd').iterdir():
                        try:
                            if os.readlink(descriptor) in expected:state['remaining_namespace_handles'].append(str(descriptor))
                        except FileNotFoundError:pass
                        except PermissionError:state['errors'].append({'stage':'namespace_fd_scan','class':'unreadable'})
                except FileNotFoundError:pass
                except PermissionError:state['errors'].append({'stage':'namespace_fd_directory','class':'unreadable'})
    if wrapper:
        if wrapper.get('errors')!=[] or wrapper.get('jail_absent') is not True:
            state['errors'].append({'stage':'wrapper','class':'incomplete'})
        jail=wrapper.get('jail')
        if not isinstance(jail,str) or not Path(jail).name.startswith('d061-owned-android-jail-') or Path(jail).parent!=Path('/opt'):
            state['errors'].append({'stage':'jail','class':'unverified_path'})
        elif Path(jail).exists():state['errors'].append({'stage':'jail','class':'still_exists'})
        else:
            sensitive=('work/build/private-build-home','work/evidence/origin.key','work/evidence/home','work/home','work/build/disposable-signing.p12')
            remaining=[name for name in sensitive if anchored_exists(root/name)]
            state['private_material_absent']=not remaining
            if remaining:state['errors'].append({'stage':'private_material','remaining':remaining})
    for name,record in records.items():
        if record is not None and (record.get('complete') is not True or record.get('errors')!=[]):
            state['errors'].append({'stage':name,'class':'incomplete'})
    adb=records.get('adb-cleanup.json')
    if not app_expected:
        state['reverse_mappings']=[]
        state['reverse_status']='not_reached_from_independent_root_stage'
    else:state['reverse_status']='expected_requires_original_readback'
    if adb:
        state['reverse_mappings']=adb.get('reverse_after')
        if adb.get('reverse_after')!=[] or adb.get('package_absent') is not True or adb.get('app_pid_absent') is not True:
            state['errors'].append({'stage':'adb_cleanup','class':'absence_unverified'})
    if state['remaining_namespace_members'] or state['remaining_namespace_handles']:
        state['errors'].append({'stage':'namespace','class':'members_or_handles_remain'})
    state['stage_required_records_complete']=not state['missing_records']
    state['complete']=(not state['errors'] and state['stage_required_records_complete']
        and state['private_material_absent'] and state['reverse_mappings']==[])
    return state


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD exact independent lifecycle review required')
    import argparse
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);a=p.parse_args()
    if a.root.parent!=Path('/opt') or not a.root.name.startswith('d061-owned-android-'):
        raise ValueError('exact disposable workflow root required')
    result=inspect(a.root)
    print(json.dumps(result,sort_keys=True))
    if not result['complete']:raise SystemExit(1)


if __name__=='__main__':main()
