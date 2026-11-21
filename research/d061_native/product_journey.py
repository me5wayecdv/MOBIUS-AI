"""HELD product service journey, no creation of hypotheses/approvals/targets.

A separately reviewed ephemeral CI setup must supply an actual persisted case
and granted exact plan. No seed, synthetic consent or model call is performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

APPROVED_FOR_EXECUTION = False


def main():
    if not APPROVED_FOR_EXECUTION:raise SystemExit('HELD: product integration scope/workflow review required')
    p=argparse.ArgumentParser()
    p.add_argument('--db-url',required=True)
    p.add_argument('--artifact-root',required=True)
    p.add_argument('--approved-plan',required=True)
    p.add_argument('--output',required=True)
    p.add_argument('--host-root',required=True)
    a=p.parse_args()
    from mobius.adapters.db import make_engine,make_session_factory
    from mobius.adapters.models import EvidenceRow
    from mobius.core.schemas import PoCTestPlan
    from mobius.services.artifacts import ArtifactStore
    from mobius.services.archivist import ArchivistService
    from mobius.services.native_local_fixture import NativeLocalFixtureAdapter
    from mobius.services.poc_execution import PoCExecutionService
    from product_host import PreparedCIHost
    plan=PoCTestPlan.model_validate_json(Path(a.approved_plan).read_text())
    if plan.target_kind!='native_local_fixture':raise RuntimeError('fixed local product plan required')
    store=ArtifactStore(a.artifact_root)
    factory=make_session_factory(make_engine(a.db_url))
    # Never create schema/case/auth/hypothesis/approval or elevate a process.
    with factory() as s:
        adapter=NativeLocalFixtureAdapter(PreparedCIHost(a.host_root))
        result=PoCExecutionService(s,store,native_adapter=adapter).execute_and_persist(plan)
        s.commit()
        run_id=result.run_id
    with factory() as fresh:
        readback=PoCExecutionService(fresh,store).readback(run_id,investigation_id=plan.investigation_id)
        report=ArchivistService(fresh,store).write(plan.investigation_id)
        fresh.commit()
        report_id=report['evidence_id']
        report_sha=report['sha256']
    with factory() as fresh:
        row=fresh.get(EvidenceRow,report_id)
        if row is None or row.investigation_id!=plan.investigation_id:raise RuntimeError('report case identity')
        content=store.get(row.object_key)
        if hashlib.sha256(content).hexdigest()!=report_sha or row.sha256!=report_sha:
            raise RuntimeError('stored report hash mismatch')
        text=content.decode()
        if run_id not in text or plan.id not in text:
            raise RuntimeError('stored report missing product run/plan refs')
        for ref in readback['evidence']:
            if ref['evidence_id'] not in text:raise RuntimeError('stored report missing evidence ref')
    Path(a.output).write_text(json.dumps({'run':readback,'report_evidence_id':report_id,
        'report_sha256':report_sha,'source':'actual service persistence/fresh-session readback',
        'apk_execution':False,'tls_negative_controls':'UNTESTED'},sort_keys=True)+'\n')

if __name__=='__main__':main()
