from __future__ import annotations

import time
import pytest

from mobius.core.schemas import PoCCleanupStep, PoCStep
from mobius.services.poc_approval import PoCApprovalService
from mobius.services.poc_runner import PoCApprovalRequired, SafePoCRunner
from test_poc_execution import _context


def _approval_plan(session, store, future_iso):
    scan, base = _context(session, store, future_iso)
    from mobius.services.intake import IntakeService
    IntakeService(session,store)._ensure_user("reviewer-1")
    plan = base.model_copy(update={
        "safety_class": "non_destructive",
        "requires_approval": True,
        "cleanup_steps": (PoCCleanupStep(action="reset_local_harness", target_ref="local-context"),),
    })
    approval = PoCApprovalService(session).request(
        plan, requested_by="analyst-1",
        justification="Run bounded local harness controls.",
        risk_summary="In-process simulation only; no APK execution or network access.",
        expires_at=future_iso,
    )
    return scan, plan, approval


def test_non_read_only_poc_requires_matching_granted_approval(session, store, future_iso):
    scan, plan, approval = _approval_plan(session, store, future_iso)
    with pytest.raises(PoCApprovalRequired):
        SafePoCRunner(session).run(plan)
    PoCApprovalService(session).resolve(
        approval.id, investigation_id=scan.id, decision="granted",
        decided_by="reviewer-1", note="Approved for bounded local harness only.",
    )
    ready = plan.model_copy(update={"approval_id": approval.id})
    result = SafePoCRunner(session).run(ready)
    assert result.status == "passed"
    assert result.cleanup_results[0]["status"] == "completed"


def test_rejected_or_revoked_approval_cannot_authorize_execution(session, store, future_iso):
    scan, plan, approval = _approval_plan(session, store, future_iso)
    PoCApprovalService(session).resolve(
        approval.id, investigation_id=scan.id, decision="rejected",
        decided_by="reviewer-1", note="Not approved.",
    )
    with pytest.raises(PoCApprovalRequired):
        SafePoCRunner(session).run(plan.model_copy(update={"approval_id": approval.id}))
    scan, plan, approval = _approval_plan(session, store, future_iso)
    PoCApprovalService(session).cancel(approval.id, investigation_id=scan.id, cancelled_by="analyst-1")
    with pytest.raises(PoCApprovalRequired):
        SafePoCRunner(session).run(plan.model_copy(update={"approval_id": approval.id}))


def test_cooperative_cancel_runs_cleanup(session, store, future_iso):
    scan, plan, approval = _approval_plan(session, store, future_iso)
    PoCApprovalService(session).resolve(
        approval.id, investigation_id=scan.id, decision="granted",
        decided_by="reviewer-1", note="Approved.",
    )
    ready = plan.model_copy(update={"approval_id": approval.id})
    result = SafePoCRunner(session).run(ready, cancel_check=lambda: True)
    assert result.status == "cancelled"
    assert result.steps == ()
    assert result.cleanup_results[0]["status"] == "completed"


def test_step_timeout_runs_cleanup(session, store, future_iso):
    scan, base = _context(session, store, future_iso)
    from mobius.services.intake import IntakeService
    IntakeService(session,store)._ensure_user("reviewer-1")
    plan = base.model_copy(update={
        "safety_class": "non_destructive",
        "requires_approval": True,
        "steps": (PoCStep(action="invoke_local_harness", target_ref="unsafe_webview_forwarder_v1",
                          input_values={"url": "https://trusted.example"}, timeout_seconds=1),),
        "cleanup_steps": (PoCCleanupStep(action="reset_local_harness", target_ref="local-context"),),
        "max_duration_seconds": 2,
    })
    approval = PoCApprovalService(session).request(
        plan, requested_by="analyst-1",
        justification="Run the bounded timeout control.",
        risk_summary="In-process simulation only; cleanup resets local context.",
        expires_at=future_iso,
    )
    PoCApprovalService(session).resolve(
        approval.id, investigation_id=scan.id, decision="granted",
        decided_by="reviewer-1", note="Approved for timeout-path test.",
    )
    ready = plan.model_copy(update={"approval_id": approval.id})
    runner = SafePoCRunner(session)
    runner._harnesses["unsafe_webview_forwarder_v1"] = lambda values: (time.sleep(1.05) or {"sink_invoked": True})
    result = runner.run(ready)
    assert result.status == "timed_out"
    assert result.cleanup_results[0]["status"] == "completed"


def test_poc_runs_list_exposes_hypothesis_binding(session, store, future_iso):
    # The plan->hypothesis binding is persisted on the run row; the list
    # endpoint must expose it so evidence consumers (and the connected
    # journey check) can verify which hypothesis an approved run tested.
    from mobius.api.routes import list_poc_runs
    from mobius.services.poc_execution import PoCExecutionService

    scan, plan, approval = _approval_plan(session, store, future_iso)
    PoCApprovalService(session).resolve(
        approval.id, investigation_id=scan.id, decision="granted",
        decided_by="reviewer-1", note="Approved.",
    )
    PoCExecutionService(session, store).execute_and_persist(
        plan.model_copy(update={"approval_id": approval.id}))
    payload = list_poc_runs(scan.id, session=session, who="analyst-1")
    assert payload["items"], "a persisted run must be listed"
    assert payload["items"][0]["hypothesis_ids"] == list(plan.hypothesis_ids)


@pytest.mark.parametrize('decision',['granted','rejected'])
def test_resolution_retains_deciding_actor_on_row_and_event(session,store,future_iso,decision):
    from sqlalchemy import select
    from sqlalchemy.orm import Session
    from mobius.adapters.models import ApprovalRow,EventRow
    scan,plan,approval=_approval_plan(session,store,future_iso)
    row=PoCApprovalService(session).resolve(approval.id,investigation_id=scan.id,
        decision=decision,decided_by='reviewer-1',note='UNIT TEST actor attribution')
    assert row.decided_by=='reviewer-1'
    session.commit()
    with Session(bind=session.get_bind()) as fresh:
        stored=fresh.get(ApprovalRow,approval.id)
        assert stored.decided_by=='reviewer-1' and stored.state==decision
        event=fresh.execute(select(EventRow).where(EventRow.investigation_id==scan.id,
            EventRow.type=='approval_resolved')).scalar_one()
        assert event.actor==stored.decided_by
        assert event.payload['approval_id']==approval.id and event.payload['decision']==decision


def test_expiry_and_cancellation_preserve_actual_resolving_actor(session,store,future_iso):
    scan,plan,approval=_approval_plan(session,store,future_iso)
    approval.expires_at='2026-01-01T00:00:00Z'
    row=PoCApprovalService(session).resolve(approval.id,investigation_id=scan.id,
        decision='granted',decided_by='reviewer-1',note='UNIT TEST expired attempt')
    assert row.state=='expired' and row.decided_by=='reviewer-1'
    scan,plan,approval=_approval_plan(session,store,future_iso)
    row=PoCApprovalService(session).cancel(approval.id,investigation_id=scan.id,cancelled_by='analyst-1')
    assert row.state=='revoked' and row.decided_by=='analyst-1'
