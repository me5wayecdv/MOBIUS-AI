"""Scope/gating regressions, no host launch or fabricated positive evidence."""
from dataclasses import replace

import pytest
from pydantic import ValidationError

from mobius.core.schemas import PoCTestPlan
from mobius.services.native_local_fixture import NativeFixtureRequest, NativeLocalFixtureAdapter
from mobius.services.poc_approval import PoCApprovalService
from mobius.services.poc_execution import PoCExecutionService
from mobius.services.poc_runner import PoCAdapterUnavailable, PoCApprovalRequired, PoCScopeRejected
from test_poc_execution import _context


def native_plan(session,store,future_iso):
    _,old=_context(session,store,future_iso)
    data=old.model_dump()
    data.update(target_kind='native_local_fixture',safety_class='non_destructive',requires_approval=True,
        steps=[{'action':'capture_native_local_fixture_v1','target_ref':'trusted-local-positive-v1','timeout_seconds':60}],
        cleanup_steps=[{'action':'stop_native_local_fixture','target_ref':'trusted-local-positive-v1'}])
    return PoCTestPlan.model_validate(data)


def grant(session,plan,future_iso):
    service=PoCApprovalService(session)
    row=service.request(plan,requested_by='analyst-1',justification='Unit gate regression only',
        risk_summary='No real execution in this test',expires_at=future_iso)
    service.resolve(row.id,investigation_id=plan.investigation_id,decision='granted',
                    decided_by='analyst-1',note='UNIT TEST ONLY, not an execution approval')
    return plan.model_copy(update={'approval_id':row.id})


def test_native_plan_cannot_disguise_as_simulated_harness(session,store,future_iso):
    plan=native_plan(session,store,future_iso)
    for field,value in [('target_kind','local_harness'),('safety_class','read_only'),('requires_approval',False)]:
        with pytest.raises(ValidationError):PoCTestPlan.model_validate({**plan.model_dump(),field:value})
    data=plan.model_dump()
    data['steps'][0]['target_ref']='http://thirdparty.invalid'
    with pytest.raises(ValidationError):PoCTestPlan.model_validate(data)


def test_native_host_not_called_without_grant_and_disabled_after_valid_grant(session,store,future_iso):
    plan=native_plan(session,store,future_iso)
    with pytest.raises(PoCApprovalRequired):PoCExecutionService(session,store).execute_and_persist(plan)
    approved=grant(session,plan,future_iso)
    with pytest.raises(PoCAdapterUnavailable):PoCExecutionService(session,store).execute_and_persist(approved)
    request=NativeFixtureRequest.from_plan(approved)
    with pytest.raises(PoCAdapterUnavailable):NativeLocalFixtureAdapter().execute(request)


def test_native_scope_revocation_blocks_before_host(session,store,future_iso):
    plan=grant(session,native_plan(session,store,future_iso),future_iso)
    from mobius.adapters.models import AuthorizationRow
    session.get(AuthorizationRow,plan.authorization_id).revoked_at='2026-01-01T00:00:00Z'
    with pytest.raises(PoCScopeRejected):PoCExecutionService(session,store).execute_and_persist(plan)


def test_existing_run_readback_rehashes_original_persisted_bytes(session,store,future_iso):
    scan,plan=_context(session,store,future_iso)
    service=PoCExecutionService(session,store)
    run=service.execute_and_persist(plan)
    result=service.readback(run.run_id,investigation_id=scan.id)
    assert result['input_sha256']==run.input_sha256 and len(result['evidence'])==3
    with pytest.raises(LookupError):service.readback(run.run_id,investigation_id='another-case')
