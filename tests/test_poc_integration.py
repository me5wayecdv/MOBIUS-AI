from __future__ import annotations

from sqlalchemy import select

from mobius.adapters.models import FindingRow, PoCRunRow, VerdictRow
from mobius.core.ids import IdPrefix, new_id
from mobius.core.schemas import PoCStep
from mobius.services.poc_execution import PoCExecutionService
from test_poc_execution import _context


def test_positive_and_negative_poc_controls_persist_without_auto_confirming(session, store, future_iso):
    scan, base = _context(session, store, future_iso)
    positive = base.model_copy(update={
        "id": new_id(IdPrefix.POC_PLAN),
        "steps": (
            PoCStep(action="invoke_local_harness", target_ref="unsafe_webview_forwarder_v1",
                    input_values={"url": "javascript:alert(1)"}),
            PoCStep(action="assert_local_harness_result", target_ref="sink_invoked",
                    expected_value=True),
        ),
        "expected_outcome": "The positive control forwards an untrusted URL in the local harness simulation.",
    })
    negative = base.model_copy(update={
        "id": new_id(IdPrefix.POC_PLAN),
        "steps": (
            PoCStep(action="invoke_local_harness", target_ref="safe_webview_guard_v1",
                    input_values={"url": "javascript:alert(1)"}),
            PoCStep(action="assert_local_harness_result", target_ref="sink_invoked",
                    expected_value=False),
        ),
        "expected_outcome": "The negative control blocks the same untrusted URL in the local harness simulation.",
    })

    service = PoCExecutionService(session, store)
    positive_run = service.execute_and_persist(positive)
    negative_run = service.execute_and_persist(negative)

    assert positive_run.status == "passed"
    assert positive_run.result.output_json["steps"][0]["actual_value"]["sink_invoked"] is True
    assert negative_run.status == "passed"
    assert negative_run.result.output_json["steps"][0]["actual_value"]["sink_invoked"] is False
    assert positive_run.result.output_json["simulation_only"] is True
    assert negative_run.result.output_json["simulation_only"] is True

    persisted = list(session.execute(
        select(PoCRunRow).where(PoCRunRow.investigation_id == scan.id)
    ).scalars())
    assert {row.id for row in persisted} == {positive_run.run_id, negative_run.run_id}
    assert all(row.status == "passed" for row in persisted)
    # A local harness is a reproducible control, not an Android runtime verdict.
    assert session.execute(
        select(FindingRow.id).where(FindingRow.investigation_id == scan.id)
    ).first() is None
    assert session.execute(
        select(VerdictRow.id).join(FindingRow, VerdictRow.finding_id == FindingRow.id).where(FindingRow.investigation_id == scan.id)
    ).first() is None
