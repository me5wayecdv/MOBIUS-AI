from __future__ import annotations

import json

from mobius.adapters.models import PoCRunEvidenceRow, PoCRunRow
from mobius.core.enums import EvidenceKind
from mobius.core.ids import IdPrefix, new_id
from mobius.core.schemas import PoCStep, PoCTestPlan
from mobius.services.evidence import EvidenceService
from mobius.services.intake import IntakeService
from mobius.services.poc_execution import PoCExecutionService
from conftest import make_apk


def _context(session, store, future_iso):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "poc-persist.apk", uploaded_by="analyst-1")
    package = app.package_name or "com.example"
    auth = intake.create_authorization(
        apk_sha256=app.sha256, target_package=package,
        scope_text="Local harness execution only", statement="I own this APK",
        max_intensity=0, granted_by="analyst-1", expires_at=future_iso,
    )
    scan = intake.create_investigation(
        application_id=app.id, authorization_id=auth.id,
        objective="Persist local PoC evidence", intensity=0, created_by="analyst-1",
    )
    from mobius.adapters.models import HypothesisRow
    hyp = HypothesisRow(
        id=new_id(IdPrefix.HYPOTHESIS), investigation_id=scan.id,
        claim="Untrusted intent data reaches a WebView sink.",
        maswe=[], derived_from=[], required_evidence=["source", "sink"],
        satisfied_evidence=[], status="open", priority=0.8, depth=0,
        parent_id=None, created_at="2026-11-18T00:00:00Z",
    )
    session.add(hyp)
    session.flush()
    plan = PoCTestPlan(
        investigation_id=scan.id, authorization_id=auth.id,
        target_sha256=app.sha256, target_package=package,
        target_kind="local_harness", hypothesis_ids=(hyp.id,),
        steps=(
            PoCStep(action="invoke_local_harness", target_ref="unsafe_webview_forwarder_v1",
                    input_values={"url": "javascript:alert(1)"}),
            PoCStep(action="assert_local_harness_result", target_ref="sink_invoked",
                    expected_value=True),
            PoCStep(action="invoke_local_harness", target_ref="safe_webview_guard_v1",
                    input_values={"url": "javascript:alert(1)"}),
            PoCStep(action="assert_local_harness_result", target_ref="sink_invoked",
                    expected_value=False),
        ),
        expected_outcome="Positive harness forwards the URL; negative control blocks it.",
        max_duration_seconds=120, max_output_bytes=8192,
    )
    return scan, plan


def test_execution_persists_plan_result_log_hashes_and_tool_provenance(session, store, future_iso):
    scan, plan = _context(session, store, future_iso)
    persisted = PoCExecutionService(session, store).execute_and_persist(plan)
    row = session.get(PoCRunRow, persisted.run_id)
    assert row is not None
    assert row.investigation_id == scan.id
    assert row.plan_id == plan.id
    assert row.target_sha256 == plan.target_sha256
    assert row.status == "passed" and row.exit_status == "success"
    assert row.input_sha256 == persisted.input_sha256
    assert row.output_sha256 == persisted.output_sha256
    assert row.started_at and row.finished_at and row.duration_ms >= 0
    assert "mobius-local-harness/1.0.0" in row.tool_versions[0]
    links = list(session.query(PoCRunEvidenceRow).filter_by(run_id=persisted.run_id))
    assert {link.kind for link in links} == {"plan", "result", "log"}
    evidence = {item.kind for item in EvidenceService(session, store).list_for(scan.id)}
    assert {EvidenceKind.POC_PLAN, EvidenceKind.POC_RESULT, EvidenceKind.POC_LOG} <= evidence
    assert json.loads(json.dumps(row.output_json))["status"] == "passed"
    assert len(persisted.evidence_ids) == 3


def test_execution_event_contains_run_and_evidence_references(session, store, future_iso):
    scan, plan = _context(session, store, future_iso)
    persisted = PoCExecutionService(session, store).execute_and_persist(plan)
    from mobius.adapters.models import EventRow
    events = list(session.query(EventRow).filter_by(investigation_id=scan.id).order_by(EventRow.seq))
    event = next(item for item in events if item.type == "poc_completed")
    assert event.payload["run_id"] == persisted.run_id
    assert set(event.payload["evidence_ids"]) == set(persisted.evidence_ids)
