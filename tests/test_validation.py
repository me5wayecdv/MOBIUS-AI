"""The confirmation path: gates decide, models only propose.

These are the tests a graduation committee should read first, because they are the
difference between this project and a wrapper around a scanner.
"""

from __future__ import annotations

import pytest

from mobius.adapters.events import SqlEventStore
from mobius.adapters.models import VerdictRow
from mobius.core.enums import FindingStatus, RejectionReason, Severity, Verdict
from mobius.services import errors
from mobius.services.intake import IntakeService
from mobius.services.validation import ValidationService

from conftest import make_apk

EXPORTED = "exported-component-no-permission"
ALL_TRUE = {
    "exported": True,
    "permission": None,
    "caller_check_absent": True,
    "sink_reachable": True,
}


@pytest.fixture()
def scan_id(session, store, future_iso):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "a.apk", uploaded_by="u")
    auth = intake.create_authorization(
        apk_sha256=app.sha256, target_package="com.example",
        scope_text="Static analysis of the supplied artefact only.",
        statement="s", max_intensity=2, granted_by="u", expires_at=future_iso,
    )
    inv = intake.create_investigation(
        application_id=app.id, authorization_id=auth.id,
        objective="Determine whether exported components reach a privileged sink.",
        intensity=0, created_by="u",
    )
    return inv.id


def _validate(session, scan_id, **kw):
    base = dict(
        investigation_id=scan_id,
        category=EXPORTED,
        attributes=dict(ALL_TRUE),
        title="Exported activity writes attacker-supplied path",
        description="MainActivity is exported and forwards EXTRA_PATH to FileOutputStream.",
        evidence_refs=("ev_1",),
        discovered_by="SPECTRE",
        validated_by="VERITAS",
    )
    base.update(kw)
    return ValidationService(session).validate(**base)


def test_all_clauses_true_confirms_the_finding(session, scan_id):
    finding, record = _validate(session, scan_id)
    assert record.verdict is Verdict.CONFIRMED
    assert record.gate_passed is True
    assert finding.status is FindingStatus.CONFIRMED
    assert finding.confidence == 1.0
    assert finding.severity is Severity.HIGH  # from the gate's severity hint


def test_same_model_cannot_discover_and_validate(session, scan_id):
    with pytest.raises(errors.ValidatorMustDiffer):
        _validate(session, scan_id, validated_by="SPECTRE", discovered_by="SPECTRE")


def test_validation_without_evidence_is_refused(session, scan_id):
    with pytest.raises(errors.MissingEvidence):
        _validate(session, scan_id, evidence_refs=())


def test_unestablished_clauses_mean_insufficient_evidence_not_safe(session, scan_id):
    # We know it is exported and unguarded, but not that a privileged sink is reachable.
    attrs = {"exported": True, "permission": None}
    finding, record = _validate(session, scan_id, attributes=attrs)
    assert record.verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert record.rejection_reason is None, "we did not refute it, so we give no reason"
    assert finding.status is FindingStatus.MANUAL_REVIEW_REQUIRED
    assert 0.0 < finding.confidence < 1.0


def test_a_failed_clause_rejects_with_a_taxonomy_reason(session, scan_id):
    attrs = dict(ALL_TRUE, sink_reachable=False)
    finding, record = _validate(session, scan_id, attributes=attrs)
    assert record.verdict is Verdict.REJECTED
    assert record.rejection_reason is RejectionReason.NOT_REACHABLE
    assert finding.status is FindingStatus.REJECTED
    assert finding.confidence == 0.0
    assert "sink_reachable" in record.rationale


def test_rejection_reason_can_be_supplied_explicitly(session, scan_id):
    attrs = dict(ALL_TRUE, sink_reachable=False)
    _, record = _validate(
        session, scan_id, attributes=attrs, rejection_reason=RejectionReason.MISREAD_CODE
    )
    assert record.rejection_reason is RejectionReason.MISREAD_CODE


def test_negative_control_launcher_activity_is_not_confirmed(session, scan_id):
    """The control that matters: an exported launcher with no privileged sink.

    If this confirmed, the tool would flag essentially every Android app.
    """
    attrs = {"exported": True, "permission": None, "caller_check_absent": True,
             "sink_reachable": False}
    _, record = _validate(session, scan_id, attributes=attrs)
    assert record.verdict is Verdict.REJECTED


def test_verdict_is_persisted_with_its_gate_detail(session, scan_id):
    finding, record = _validate(session, scan_id)
    row = session.get(VerdictRow, record.id)
    assert row is not None
    assert row.gate_passed is True
    # gate_detail records clause *outcomes*, not raw inputs: the permission clause is
    # satisfied (True) because no permission was declared (None). Storing the raw value
    # would make the audit trail depend on how a caller happened to spell "absent".
    assert row.gate_detail == {"exported": True, "permission": True,
                               "caller_check_absent": True, "sink_reachable": True}
    assert row.validated_by == "VERITAS"
    assert row.finding_id == finding.id


def test_validation_emits_audit_events(session, scan_id):
    _validate(session, scan_id)
    types = [e.type for e in SqlEventStore(session).read_after(scan_id, 0)]
    assert types == ["validation_started", "finding_created", "finding_confirmed"]


def test_rejection_emits_a_rejection_event(session, scan_id):
    _validate(session, scan_id, attributes=dict(ALL_TRUE, sink_reachable=False))
    types = [e.type for e in SqlEventStore(session).read_after(scan_id, 0)]
    assert types[-1] == "finding_rejected"


def test_unknown_category_raises_rather_than_confirming(session, scan_id):
    from mobius.core import gates

    with pytest.raises(gates.UnknownGate):
        _validate(session, scan_id, category="invented-category")
