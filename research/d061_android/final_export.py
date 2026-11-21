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
ALWAYS_CONTROL=frozenset({'control-privileges.json','control-result.json'})
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
    if manifest['report_sha256'] not in seen:raise ValueError('exact report object absent from manifest')
    return rows


def _db_status(stage,run):
    import sqlite3
    db=sqlite3.connect(':memory:')
    try:
        db.deserialize(read(Path(stage)/'control/mobius.db',16*1024**2))
        row=db.execute('select status from poc_runs where id=?',(run,)).fetchone()
        return None if row is None else row[0]
    finally:db.close()


def check_status(stage,pub_status):
    """Staged control/execute/DB status must agree with the root-published status (passed-ness), else fail closed."""
    stage=Path(stage)
    want=pub_status=='passed'
    result=json.loads(read(stage/'control/control-result.json',65536))
    if result.get('status') is None or (result['status']=='passed')!=want:raise ValueError('staged control status disagrees with published result')
    if want:
        execute=json.loads(read(stage/'control/execute-response.json',1048576)).get('body',{})
        if execute.get('status')!='passed':raise ValueError('execute response status disagrees with published result')
        if _db_status(stage,result.get('run_id'))!='passed':raise ValueError('DB run status disagrees with published result')
    else:
        db_status=_db_status(stage,result.get('run_id')) if (stage/'control/mobius.db').exists() else None
        if db_status=='passed':raise ValueError('DB run status passed while published result is not passed')


def bind_manifest(manifest,stage,pub_status='passed'):
    """Fail closed unless the manifest agrees with the STAGED immutable copies (never source paths)."""
    stage=Path(stage)
    def js(relative,limit=1048576):return json.loads(read(stage/relative,limit))
    report=read(stage/'control/report.md',16*1024**2)
    if digest(report)!=manifest['report_sha256']:raise ValueError('manifest report digest differs from exported report bytes')
    result=js('control/control-result.json')
    if (result.get('run_id'),result.get('plan_id'),result.get('report_sha256'))!=(manifest['product_run_id'],manifest['plan_id'],manifest['report_sha256']):
        raise ValueError('manifest differs from control result')
    execute=js('control/execute-response.json').get('body',{})
    if (execute.get('run_id'),execute.get('plan_id'))!=(manifest['product_run_id'],manifest['plan_id']):raise ValueError('manifest differs from execute response')
    if pub_status!='passed' or execute.get('status')!='passed' or result.get('status')!='passed':raise ValueError('product binding requires a passed run in every record')
    plan=js('control/setup/approved-plan.json')
    if (plan.get('id'),plan.get('investigation_id'),plan.get('target_sha256'))!=(manifest['plan_id'],manifest['investigation_id'],manifest['apk_sha256']):
        raise ValueError('manifest differs from approved plan')
    ready=js('public-snapshot/ready.json',65536)
    if (ready.get('run_id'),ready.get('provisioning_id'),ready.get('apk_sha256'))!=(manifest['infrastructure_run_id'],manifest['provisioning_id'],manifest['apk_sha256']):
        raise ValueError('manifest differs from ready record')
    apk=read(stage/'public-snapshot/owned-fixture.apk',4*1024**2)
    if digest(apk)!=manifest['apk_sha256']:raise ValueError('published APK differs from manifest')
    # Coherent DB: deserialize the staged immutable copy in memory, never reopen a path.
    import sqlite3
    db=sqlite3.connect(':memory:')
    try:
        db.deserialize(read(stage/'control/mobius.db',16*1024**2))
        case,run=manifest['investigation_id'],manifest['product_run_id']
        row=db.execute('select investigation_id,plan_id,status from poc_runs where id=?',(run,)).fetchone()
        if row!=(case,manifest['plan_id'],'passed'):raise ValueError('manifest run/case/status differs from DB')
        evidence={r[0]:(r[1],r[2],r[3]) for r in db.execute('select id,sha256,byte_size,object_key from evidence where investigation_id=?',(case,))}
        expected={}
        for sha,size,key in evidence.values():
            if key!='apk/'+sha[:2]+'/'+sha+'.apk':raise ValueError('noncanonical DB evidence key')
            expected[sha]=size
        expected.setdefault(manifest['apk_sha256'],len(apk))
        for sha,size,key in db.execute('select content_sha256,0,object_key from reports where investigation_id=?',(case,)):
            if key!='apk/'+sha[:2]+'/'+sha+'.apk':raise ValueError('noncanonical DB report key')
            expected.setdefault(sha,None)
        listed={o['sha256']:o['bytes'] for o in manifest['objects']}
        if len(listed)!=len(manifest['objects']) or set(listed)!=set(expected):raise ValueError('manifest object set differs from DB-referenced objects')
        for sha,size in expected.items():
            if size is not None and listed[sha]!=size:raise ValueError('manifest object size differs from DB')
        if manifest['report_sha256'] not in listed:raise ValueError('report object absent from manifest')
        linked={r[0] for r in db.execute('select evidence_id from poc_run_evidence where investigation_id=? and run_id=?',(case,run))}
        if not linked or not linked<=set(evidence):raise ValueError('run evidence links absent or cross-case')
        readback=js('control/api-readback.json',4*1024**2)
        if (readback.get('run_id'),readback.get('plan_id'),readback.get('investigation_id'),readback.get('status'))!=(run,manifest['plan_id'],case,'passed'):
            raise ValueError('readback run/plan/case/status differs from manifest')
        if set(execute.get('evidence_ids') or ())!=linked or len(execute.get('evidence_ids') or ())!=len(linked):
            raise ValueError('execute evidence ids differ from DB run links')
        items=readback.get('evidence')
        if not isinstance(items,list) or {i.get('evidence_id') for i in items}!=linked or len(items)!=len(linked):
            raise ValueError('readback evidence links differ from DB run links')
        for item in items:
            sha,size,_=evidence[item['evidence_id']]
            if (item.get('sha256'),item.get('bytes'))!=(sha,size):raise ValueError('readback evidence digest differs from DB')
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
    control_work=None
    # Obligations come from the root-published immutable result, never from the payload's own control status.
    # Unknown/unreadable status fails closed: full evidence is demanded AND an error is recorded.
    pub_status=None
    if 'control' in reached:
        try:
            value=json.loads(read(root/'control-in/result/result.json',65536)).get('status')
            pub_status=value if isinstance(value,str) and value else None
        except BaseException:pass
        if pub_status is None:errors.append({'class':'PublishedStatusUnknown'})
    passed=pub_status in (None,'passed')
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
            for name in sorted(REQUIRED|DIAGNOSTICS):optional(output/'work/evidence'/name,'runtime-originals/'+name,required=passed and name in REQUIRED)
        else:
            work=output/'work'
            for name in sorted(CONTROL_FILES):optional(work/name,'control/'+name,required=passed or name in ALWAYS_CONTROL)
            # Never present an unresolved WAL/journal snapshot as coherent DB.
            journals=[name for name in ('mobius.db-wal','mobius.db-shm','mobius.db-journal') if exists(work/name)]
            if journals:errors.append({'role':'control','class':'DatabaseSidecarsUnresolved','files':journals})
            elif not optional(work/'mobius.db','control/mobius.db',16*1024**2):errors.append({'role':'control','class':'DatabaseMissing'})
            control_work=work
    for name in sorted(PUBLIC_FILES):optional(root/'control-in/snapshot'/name,'public-snapshot/'+name,4*1024**2,required='control' in reached)
    # Private collector candidates are deliberately NOT exported. Only already
    # published product results can be copied as such, never passed private data.
    for name in sorted(REQUIRED|DIAGNOSTICS|{'result.json'}):
        optional(root/'control-in/result'/name,'published-result/'+name,
            required='control' in reached and (name=='result.json' or (passed and name in REQUIRED)))
    if control_work is not None and pub_status is not None:
        try:check_status(stage,pub_status)
        except BaseException as error:errors.append({'role':'control','class':type(error).__name__,'stage':'status_binding','detail':str(error)[:120]})
    binding_verified=False
    if control_work is not None and passed:
        try:
            manifest=json.loads(read(stage/'control/export-manifest.json',1048576))
            rows=object_rows(manifest,owner)
            bind_manifest(manifest,stage,pub_status)
            for row in rows:
                sha=row['sha256'];key='apk/'+sha[:2]+'/'+sha+'.apk'
                copy(control_work/'store'/key,'product-store/'+key,4*1024**2,expected=row)
            binding_verified=pub_status=='passed'
        except BaseException as error:errors.append({'role':'control','class':type(error).__name__,'stage':'exact_product_objects'})
    checkpoint()
    result={'version':'owned-final-export/1','workflow_context':owner['workflow_context'],'infrastructure_run_id':owner['run_id'],
        'complete':bool(reached) and not errors,'complete_diagnostic_export':bool(reached) and not errors,
        'complete_product_evidence':bool(reached) and not errors and pub_status=='passed' and binding_verified,
        'published_status':pub_status,'diagnostic_partial_export':bool(errors) or not reached,'errors':errors,'role_absence':role_absence,'inventory':inventory,
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
