from __future__ import annotations

import pytest

from mobius.adapters.models import HypothesisRow, InvestigationRow
from mobius.core.enums import EvidenceKind
from mobius.core.ids import IdPrefix, new_id
from mobius.core.schemas import PoCStep, PoCTestPlan
from mobius.services.evidence import EvidenceService
from mobius.services.intake import IntakeService
from mobius.services.poc_runner import (
    PoCAdapterUnavailable, PoCApprovalRequired, PoCScopeRejected, SafePoCRunner,
)
from conftest import make_apk


def _context(session, store, future_iso):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "poc-lab.apk", uploaded_by="analyst-1")
    auth = intake.create_authorization(
        apk_sha256=app.sha256, target_package=app.package_name or "com.example",
        scope_text="Static analysis and local harness only.",
        statement="I own this fixture and authorize bounded testing.",
        max_intensity=0, granted_by="analyst-1", expires_at=future_iso,
    )
    scan = intake.create_investigation(
        application_id=app.id, authorization_id=auth.id,
        objective="Exercise a local safe PoC harness", intensity=0, created_by="analyst-1",
    )
    hyp = HypothesisRow(
        id=new_id(IdPrefix.HYPOTHESIS), investigation_id=scan.id,
        claim="Untrusted intent data can reach a WebView URL sink.",
        maswe=[], derived_from=[], required_evidence=["source", "sink"],
        satisfied_evidence=[], status="open", priority=0.8, depth=0,
        parent_id=None, created_at="2026-11-18T00:00:00Z",
    )
    session.add(hyp)
    session.flush()
    return app, auth, scan, hyp


def _plan(app, auth, scan, hyp, steps, **overrides):
    values = {
        "investigation_id": scan.id, "authorization_id": auth.id,
        "target_sha256": app.sha256, "target_package": app.package_name or "com.example",
        "target_kind": "local_harness", "hypothesis_ids": (hyp.id,),
        "steps": tuple(steps), "expected_outcome": "Vulnerable harness forwards an untrusted URL; negative control blocks it.",
        "safety_class": "read_only", "max_duration_seconds": 120, "max_output_bytes": 8192,
    }
    values.update(overrides)
    return PoCTestPlan(**values)


def test_local_harness_positive_and_negative_control_are_explicit_simulations(session, store, future_iso):
    app, auth, scan, hyp = _context(session, store, future_iso)
    steps = (
        PoCStep(action="invoke_local_harness", target_ref="unsafe_webview_forwarder_v1",
                input_values={"url": "javascript:alert(1)"}),
        PoCStep(action="assert_local_harness_result", target_ref="sink_invoked", expected_value=True),
        PoCStep(action="invoke_local_harness", target_ref="safe_webview_guard_v1",
                input_values={"url": "javascript:alert(1)"}),
        PoCStep(action="assert_local_harness_result", target_ref="sink_invoked", expected_value=False),
    )
    result = SafePoCRunner(session).run(_plan(app, auth, scan, hyp, steps))
    assert result.status == "passed"
    assert [step.passed for step in result.steps] == [True, True, True, True]
    assert result.output_json["simulation_only"] is True
    assert "mobius-local-harness/1.0.0" in result.tool_versions[0]
    assert any("not execution of the APK" in item for item in result.limitations)


def test_lab_apk_manifest_assertions_use_persisted_facts(session, store, future_iso):
    app, auth, scan, hyp = _context(session, store, future_iso)
    evidence = EvidenceService(session, store).record(
        investigation_id=scan.id, kind=EvidenceKind.MANIFEST,
        content=b"manifest-for-poc", summary="Manifest observation", produced_by="RECON",
    )
    from mobius.adapters.models import ObservationRow
    from mobius.core.enums import Fidelity, ObservationKind
    session.add(ObservationRow(
        id=new_id(IdPrefix.OBSERVATION), investigation_id=scan.id, agent="RECON",
        kind=ObservationKind.FACT.value, fidelity=Fidelity.BINARY_XML.value,
        subject_type="component", subject_ref="com.example.Entry",
        statement="Exported entry component", attributes={"exported": True, "permission": None},
        maswe=[], confidence=1.0, evidence_refs=[evidence.id],
        created_at="2026-11-18T00:00:00Z",
    ))
    session.flush()
    plan = _plan(app, auth, scan, hyp, (
        PoCStep(action="assert_manifest_component", target_ref="com.example.Entry", expected_value=True),
        PoCStep(action="assert_manifest_permission", target_ref="android.permission.READ_SMS", expected_value=False),
    ), target_kind="lab_apk")
    result = SafePoCRunner(session).run(plan)
    assert result.status == "passed"
    assert all(step.passed for step in result.steps)


def test_runner_rejects_wrong_target_scope_and_unregistered_harness(session, store, future_iso):
    app, auth, scan, hyp = _context(session, store, future_iso)
    runner = SafePoCRunner(session)
    bad_target = _plan(app, auth, scan, hyp, (
        PoCStep(action="invoke_local_harness", target_ref="unsafe_webview_forwarder_v1",
                input_values={"url": "https://evil.example"}),
    ), target_sha256="b" * 64)
    with pytest.raises(PoCScopeRejected, match="target identity"):
        runner.run(bad_target)
    unknown = _plan(app, auth, scan, hyp, (
        PoCStep(action="invoke_local_harness", target_ref="unregistered_harness"),
    ))
    with pytest.raises(PoCAdapterUnavailable, match="not registered"):
        runner.run(unknown)


def test_runner_rejects_emulator_and_approval_gated_plans(session, store, future_iso):
    app, auth, scan, hyp = _context(session, store, future_iso)
    runner = SafePoCRunner(session)
    emulator = _plan(app, auth, scan, hyp, (
        PoCStep(action="invoke_local_harness", target_ref="unsafe_webview_forwarder_v1"),
    ), target_kind="emulator")
    with pytest.raises(PoCAdapterUnavailable, match="emulator adapter"):
        runner.run(emulator)
    approved = _plan(app, auth, scan, hyp, (
        PoCStep(action="invoke_local_harness", target_ref="unsafe_webview_forwarder_v1"),
    ), requires_approval=True)
    with pytest.raises(PoCApprovalRequired):
        runner.run(approved)


def test_runner_rejects_revoked_authorization(session, store, future_iso):
    app, auth, scan, hyp = _context(session, store, future_iso)
    row = session.get(type(auth), auth.id)
    row.revoked_at = "2026-11-18T00:00:00Z"
    session.flush()
    plan = _plan(app, auth, scan, hyp, (
        PoCStep(action="invoke_local_harness", target_ref="unsafe_webview_forwarder_v1",
                input_values={"url": "https://evil.example"}),
    ))
    with pytest.raises(PoCScopeRejected, match="revoked"):
        SafePoCRunner(session).run(plan)
