"""HELD bounded allowlist-only final evidence exporter, never broad work/home copy.

All output is fixture evidence, not attestation. Failed/missing original cleanup
stays failed. No private key, AVD, SDK, build home, arbitrary store path, shell,
network or artifact publication is implemented here.
"""
import json
import os
from pathlib import Path
import re
import secrets
import time

from handoff_io import read,write,json_write,mkdir,parent_fd,exists,publish_directory,digest
from outer_owner import workflow_fields,trusted_context,validate_workflow_owner,LOCATOR
from sibling_supervisor import check_absent
from mobius.services.owned_android_fixture import REQUIRED,DIAGNOSTICS

APPROVED_FOR_EXECUTION = False
ROOT_FILES=frozenset({'outer-owner-intent.json','outer-owner-progress.json','outer-owner-result.json',
    'trusted-run-intent.json','trusted-run-progress.json','trusted-relay-result.json','runtime-root-stage.json',
    'runtime-launch-intent.json','runtime-launch.json','control-launch-intent.json','control-launch.json',
    'relay.log','runtime.log','control.log'})
ROLE_FILES=frozenset({'namespace-setup.json','namespace-driver-result.json','wrapper-cleanup.json',
    'trusted-final-absence.json','root-jail-intent.json'})
CONTROL_FILES=frozenset({'control-privileges.json','execute-response.json','api-readback.json','report.md',
    'control-result.json','export-manifest.json','setup/approved-plan.json','setup/fixture-provenance.json'})
PUBLIC_FILES=frozenset({'owned-fixture.apk','public-ca.der','build-result.json','ready.json'})
ROOT_ATTEMPT=re.compile(r'outer-recovery(?:-intent)?-[0-9a-f]{32}\.json')
ROLE_ATTEMPT=re.compile(r'(?:outer-independent-absence|export-independent-absence)-[0-9a-f]{32}\.json')
REQUIRED_ROOT=frozenset({'outer-owner-intent.json','outer-owner-result.json','runtime-root-stage.json'})
REQUIRED_ROLE=frozenset({'namespace-setup.json','namespace-driver-result.json','trusted-final-absence.json'})
MAX_FILES=512
MAX_TOTAL=64*1024**2


def attempt_names(root,pattern):
    with parent_fd(Path(root)/'leaf-not-opened') as (fd,leaf):
        names=os.listdir(fd)
    if len(names)>2048:raise ValueError('bounded owned evidence directory index required')
    return sorted(name for name in names if pattern.fullmatch(name))


def object_rows(manifest,owner):
    expected={'version','infrastructure_run_id','provisioning_id','investigation_id','product_run_id',
        'plan_id','apk_sha256','report_sha256','objects'}
    if set(manifest)!=expected or manifest['version']!='owned-product-export/1':raise ValueError('closed product export manifest required')
    if (manifest['infrastructure_run_id'],manifest['provisioning_id'])!=(owner['run_id'],owner['provisioning_id']):
        raise ValueError('product export belongs to another owned run')
    for key,prefix in [('investigation_id','scn_'),('product_run_id','pcr_'),('plan_id','poc_')]:
        if not isinstance(manifest[key],str) or re.fullmatch(prefix+'[A-Za-z0-9]{1,40}',manifest[key]) is None:
            raise ValueError('fixed product identity form required')
    for name in ('apk_sha256','report_sha256'):
        if not isinstance(manifest[name],str) or re.fullmatch('[0-9a-f]{64}',manifest[name]) is None:raise ValueError('product digest required')
    rows=manifest['objects'];seen=set();total=0
    if not isinstance(rows,list) or not rows or len(rows)>128:raise ValueError('bounded exact product object list required')
    for row in rows:
        if set(row)!={'sha256','bytes'} or not isinstance(row['sha256'],str) or re.fullmatch('[0-9a-f]{64}',row['sha256']) is None:
            raise ValueError('closed digest-only store object identity required')
        if row['sha256'] in seen or type(row['bytes']) is not int or not 0<=row['bytes']<=4*1024**2:
            raise ValueError('unique bounded product store object required')
        seen.add(row['sha256']);total+=row['bytes']
        if total>32*1024**2:raise ValueError('aggregate exact product objects ceiling')
    if manifest['apk_sha256'] not in seen:raise ValueError('exact owned APK object absent')
    return rows


def bind_manifest(manifest,work,root):
    """Fail closed unless the manifest agrees with the actually exported case records."""
    def js(path,limit=1048576):return json.loads(read(path,limit))
    report=read(work/'report.md',16*1024**2)
    if digest(report)!=manifest['report_sha256']:raise ValueError('manifest report digest differs from exported report bytes')
    result=js(work/'control-result.json')
    if (result.get('run_id'),result.get('plan_id'),result.get('report_sha256'))!=(manifest['product_run_id'],manifest['plan_id'],manifest['report_sha256']):
        raise ValueError('manifest differs from control result')
    execute=js(work/'execute-response.json').get('body',{})
    if (execute.get('run_id'),execute.get('plan_id'))!=(manifest['product_run_id'],manifest['plan_id']):raise ValueError('manifest differs from execute response')
    plan=js(work/'setup/approved-plan.json')
    if (plan.get('id'),plan.get('investigation_id'),plan.get('target_sha256'))!=(manifest['plan_id'],manifest['investigation_id'],manifest['apk_sha256']):
        raise ValueError('manifest differs from approved plan')
    ready=js(root/'control-in/snapshot/ready.json',65536)
    if (ready.get('run_id'),ready.get('provisioning_id'),ready.get('apk_sha256'))!=(manifest['infrastructure_run_id'],manifest['provisioning_id'],manifest['apk_sha256']):
        raise ValueError('manifest differs from ready record')
    if digest(read(root/'control-in/snapshot/owned-fixture.apk',4*1024**2))!=manifest['apk_sha256']:raise ValueError('published APK differs from manifest')
    # Coherent DB cross-check (sidecars were already refused by the caller).
    import sqlite3
    db=sqlite3.connect('file:'+str(work/'mobius.db')+'?mode=ro&immutable=1',uri=True)
    try:
        row=db.execute('select investigation_id,plan_id from poc_runs where id=?',(manifest['product_run_id'],)).fetchone()
        if row!=(manifest['investigation_id'],manifest['plan_id']):raise ValueError('manifest run/case differs from DB')
        count=db.execute('select count(*) from evidence where investigation_id=? and sha256=?',(manifest['investigation_id'],manifest['report_sha256'])).fetchone()[0]
        if count<1:raise ValueError('report digest absent from same-case DB evidence')
    finally:db.close()


def export(root,destination,*,owner,absence_checker=check_absent,clock=time.monotonic):
    if not APPROVED_FOR_EXECUTION:raise RuntimeError('final allowlisted exporter HELD')
    root=Path(root);destination=Path(destination)
    if root!=Path(owner['root']):raise ValueError('exact owner export root required')
    started=clock();attempt=secrets.token_hex(16);errors=[];inventory=[];total=0
    stage=destination.parent/('.'+destination.name+'.'+attempt+'.private')
    mkdir(stage,0o700)
    def checkpoint():
        if clock()-started>30:raise TimeoutError('cooperative final export budget')
    def copy(source,relative,limit=1048576,expected=None):
        nonlocal total
        checkpoint()
        if len(inventory)>=MAX_FILES:raise ValueError('final allowlist file ceiling')
        data=read(source,min(limit,MAX_TOTAL-total));total+=len(data)
        if total>MAX_TOTAL:raise ValueError('final aggregate export bytes ceiling')
        if expected is not None and (len(data),digest(data))!=(expected['bytes'],expected['sha256']):raise ValueError('exact export object differs')
        target=stage/relative;current=stage
        for part in target.relative_to(stage).parts[:-1]:
            current=current/part
            if not exists(current):mkdir(current,0o700)
        write(target,data)
        inventory.append({'path':relative,'bytes':len(data),'sha256':digest(data)})
    def optional(source,relative,limit=1048576,required=False):
        if not exists(source):
            if required:errors.append({'path':relative,'class':'RequiredOriginalMissing'})
            return False
        try:copy(source,relative,limit)
        except BaseException as error:errors.append({'path':relative,'class':type(error).__name__})
        return True
    # Root-created originals are retained even when payload absence is unverified.
    reached=[x for x in ('runtime','control') if exists(root/x) or exists(root/(x+'-launch-intent.json'))]
    if not reached:errors.append({'class':'EmptyOrUnreachedRoot','detail':'no role directory or launch intent; nothing to verify'})
    for name in sorted(ROOT_FILES|set(attempt_names(root,ROOT_ATTEMPT))):optional(root/name,'root/'+name,required=name in REQUIRED_ROOT)
    role_absence={}
    stage_record=json.loads(read(root/'runtime-root-stage.json',65536)) if exists(root/'runtime-root-stage.json') else None
    for role in ('runtime','control'):
        output=root/role
        if not exists(output):
            role_absence[role]='not_reached_or_missing_unverified'
            if exists(root/(role+'-launch-intent.json')):errors.append({'role':role,'class':'ExpectedOutputMissing'})
            continue
        try:
            absence_checker(output,stage_record if role=='runtime' else None,
                record_name='export-independent-absence-'+attempt+'.json')
            role_absence[role]='independently_verified_absent'
        except BaseException as error:
            role_absence[role]='unverified';errors.append({'role':role,'class':type(error).__name__})
        for name in sorted(ROLE_FILES|set(attempt_names(output,ROLE_ATTEMPT))):optional(output/name,role+'/'+name,required=name in REQUIRED_ROLE)
        if role_absence[role]!='independently_verified_absent':continue
        if role=='runtime':
            for name in sorted(REQUIRED|DIAGNOSTICS):optional(output/'work/evidence'/name,'runtime-originals/'+name,required=name in REQUIRED)
        else:
            work=output/'work'
            for name in sorted(CONTROL_FILES):optional(work/name,'control/'+name,required=True)
            # Never present an unresolved WAL/journal snapshot as coherent DB.
            journals=[name for name in ('mobius.db-wal','mobius.db-shm','mobius.db-journal') if exists(work/name)]
            if journals:errors.append({'role':'control','class':'DatabaseSidecarsUnresolved','files':journals})
            elif not optional(work/'mobius.db','control/mobius.db',16*1024**2):errors.append({'role':'control','class':'DatabaseMissing'})
            try:
                manifest=json.loads(read(work/'export-manifest.json',1048576))
                rows=object_rows(manifest,owner)
                bind_manifest(manifest,work,root)
                # Resolve only the store's fixed content-addressed key shape,
                # never a path supplied by a DB row or payload manifest.
                for row in rows:
                    sha=row['sha256'];key='apk/'+sha[:2]+'/'+sha+'.apk'
                    copy(work/'store'/key,'product-store/'+key,4*1024**2,expected=row)
            except BaseException as error:errors.append({'role':'control','class':type(error).__name__,'stage':'exact_product_objects'})
    for name in sorted(PUBLIC_FILES):optional(root/'control-in/snapshot'/name,'public-snapshot/'+name,4*1024**2,required='control' in reached)
    # Private collector candidates are deliberately NOT exported. Only already
    # published product results can be copied as such, never passed private data.
    for name in sorted(REQUIRED|DIAGNOSTICS|{'result.json'}):optional(root/'control-in/result'/name,'published-result/'+name,required='control' in reached)
    checkpoint()
    result={'version':'owned-final-export/1','workflow_context':owner['workflow_context'],'infrastructure_run_id':owner['run_id'],
        'complete':bool(reached) and not errors,'diagnostic_partial_export':bool(errors) or not reached,'errors':errors,'role_absence':role_absence,'inventory':inventory,
        'total_bytes':total,'original_status_not_upgraded':True,'private_candidates_exported':False,
        'cooperative_export_budget_seconds':30,'not_cryptographic_attestation':True}
    json_write(stage/'export-summary.json',result)
    # Retain private700 directories. The eventual artifact uploader must run as
    # trusted root or consume a separately reviewed immutable publication step;
    # no broad chown/chmod to an arbitrary runner identity is inferred here.
    publish_directory(stage,destination)
    return result


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD reviewed final export/publication boundary required')
    if os.geteuid()!=0:raise RuntimeError('trusted disposable root exporter only')
    fields=workflow_fields(os.environ);context=trusted_context(fields)
    owner=json.loads(read(LOCATOR,65536));root=validate_workflow_owner(fields,context,owner)
    destination=Path('/opt')/('d061-owned-export-'+fields['workflow_run_id']+'-'+fields['workflow_attempt'])
    result=export(root,destination,owner=owner)
    if not result['complete']:raise RuntimeError('partial export preserved without upgrading originals')


if __name__=='__main__':main()
