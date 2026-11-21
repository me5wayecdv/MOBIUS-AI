"""Read-only owned-case object inventory for later allowlisted export.

No API writes, approvals, model, device or network action. The enclosing held
control driver writes the manifest only after actual API/readback/report success.
"""
import hashlib
import re


def build(rows,lookup,*,ready,plan,run,report_sha256):
    if len(rows)>128:raise ValueError('bounded case evidence export list required')
    if run['plan_id']!=plan.id:raise ValueError('product export plan/run mismatch')
    objects={}
    def include(sha,declared=None):
        if not isinstance(sha,str) or re.fullmatch('[0-9a-f]{64}',sha) is None:raise ValueError('export object digest required')
        data=lookup(sha)
        if not isinstance(data,bytes) or len(data)>4*1024**2 or hashlib.sha256(data).hexdigest()!=sha:
            raise ValueError('actual scoped store object identity differs')
        if declared is not None and len(data)!=declared:raise ValueError('stored evidence byte count differs')
        objects[sha]={'sha256':sha,'bytes':len(data)}
        if len(objects)>128 or sum(row['bytes'] for row in objects.values())>32*1024**2:
            raise ValueError('bounded actual product export bytes/count required')
    include(plan.target_sha256)
    for row in rows:
        if row.investigation_id!=plan.investigation_id:raise ValueError('cross-case product object refused')
        if row.object_key!='apk/'+row.sha256[:2]+'/'+row.sha256+'.apk':raise ValueError('noncanonical scoped object key refused')
        include(row.sha256,row.byte_size)
    if plan.target_sha256!=ready['apk_sha256']:raise ValueError('owned export differs from ready APK')
    return {'version':'owned-product-export/1','infrastructure_run_id':ready['run_id'],
        'provisioning_id':ready['provisioning_id'],'investigation_id':plan.investigation_id,
        'product_run_id':run['run_id'],'plan_id':plan.id,'apk_sha256':plan.target_sha256,
        'report_sha256':report_sha256,'objects':[objects[key] for key in sorted(objects)]}


def prepare(context,*,ready,plan,run,report_sha256):
    from sqlalchemy import select
    from mobius.adapters.models import EvidenceRow
    with context.session() as session:
        rows=list(session.scalars(select(EvidenceRow).where(EvidenceRow.investigation_id==plan.investigation_id).limit(129)))
        return build(rows,lambda sha:context.store.get(context.store.key_for(sha)),
            ready=ready,plan=plan,run=run,report_sha256=report_sha256)
