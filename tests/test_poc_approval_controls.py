from __future__ import annotations

import time
import pytest

from mobius.core.schemas import PoCCleanupStep, PoCStep
from mobius.services.poc_approval import PoCApprovalService
from mobius.services.poc_runner import PoCApprovalRequired, SafePoCRunner
from test_poc_execution import _context


def _approval_plan(session, store, future_iso):
    scan, base = _context(session, store, future_iso)
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
    scan, plan, approval = _approval_plan(session, store, future_iso)
    PoCApprovalService(session).resolve(
        approval.id, investigation_id=scan.id, decision="granted",
        decided_by="reviewer-1", note="Approved.",
    )
    ready = plan.model_copy(update={
        "approval_id": approval.id,
        "steps": (PoCStep(action="invoke_local_harness", target_ref="unsafe_webview_forwarder_v1",
                          input_values={"url": "https://trusted.example"}, timeout_seconds=1),),
        "max_duration_seconds": 2,
    })
    runner = SafePoCRunner(session)
    runner._harnesses["unsafe_webview_forwarder_v1"] = lambda values: (time.sleep(1.05) or {"sink_invoked": True})
    result = runner.run(ready)
    assert result.status == "timed_out"
    assert result.cleanup_results[0]["status"] == "completed"
