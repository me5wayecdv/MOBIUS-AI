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
        validated_by="DETERMINISTIC_GATE",
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
    assert row.validated_by == "DETERMINISTIC_GATE"
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


def test_a_decisive_failure_is_not_described_as_a_deferral(session, scan_id):
    """Regression from a generated report: the verdict said `rejected`, the rationale said
    "could not be decided". Both were stored in the same row, and only a reader noticed."""
    finding, verdict = _validate(
        session,
        scan_id,
        attributes={
            "exported": True,
            "permission": None,
            "sink_reachable": False,  # decisive: refutes the hypothesis
            "caller_check_absent": None,  # never established
        },
    )

    row = session.get(VerdictRow, verdict.id)
    assert verdict.verdict.value == "rejected"
    assert "refuted" in row.rationale
    assert "could not be decided" not in row.rationale
    # ...and it still admits what was never established.
    assert "never established" in row.rationale


def _derived_secret_attrs(secret="00112233445566778899aabbccddeeff"):
    """Real detector output for a synthetic literal -> pure return-transform ->
    cross-class sink route (same shape as the uncrack1 key route). The default
    literal FAILS the format screen; pass a format-passing literal for the
    derived-only never-confirm guarantee."""
    from mobius.core.reachability import MethodRef
    from mobius.core.secrets import (
        FlowBlock, SInstruction, detect_hardcoded_secrets, gate_attributes,
    )

    class Idx:
        def __init__(self, strings): self.strings = strings

    caller = MethodRef("com.example.Foo", "check", "()V")
    decode = MethodRef("com.example.Foo", "decode", "(Ljava/lang/String;)[B")
    sink = MethodRef("com.example.Crypto", "a", "([B[B)[B")
    caller_flow = [FlowBlock(0, (
        SInstruction(0, "const-string", (1,), literal=secret),
        SInstruction(2, "invoke-static", (1,), invoke_class="Lcom/example/Foo;",
                     invoke_method="decode", invoke_descriptor="(Ljava/lang/String;)[B",
                     is_static=True),
        SInstruction(4, "move-result-object", (2,)),
        SInstruction(6, "invoke-static", (2, 3), invoke_class="Lcom/example/Crypto;",
                     invoke_method="a", invoke_descriptor="([B[B)[B", is_static=True),
        SInstruction(8, "move-result-object", (4,)),
    ), ())]
    decode_flow = [FlowBlock(0, (
        SInstruction(0, "invoke-virtual", (7,), invoke_class="Ljava/lang/String;",
                     invoke_method="length", invoke_descriptor="()I"),
        SInstruction(2, "move-result", (0,)),
        SInstruction(4, "new-array", (1, 0)),
        SInstruction(6, "invoke-virtual", (7,), invoke_class="Ljava/lang/String;",
                     invoke_method="charAt", invoke_descriptor="(I)C"),
        SInstruction(8, "move-result", (2,)),
        SInstruction(10, "aput-byte", (2, 1, 0)),
        SInstruction(12, "return-object", (1,)),
    ), ())]
    sink_flow = [FlowBlock(0, (
        SInstruction(0, "new-instance", (0,)),
        SInstruction(2, "const-string", (1,), literal="AES"),
        SInstruction(4, "invoke-direct", (0, 2, 1),
                     invoke_class="Ljavax/crypto/spec/SecretKeySpec;",
                     invoke_method="<init>", invoke_descriptor="([BLjava/lang/String;)V"),
        SInstruction(6, "return-object", (2,)),
    ), ())]
    cands = detect_hardcoded_secrets(
        Idx({caller: (secret,)}),
        {caller: caller_flow, decode: decode_flow, sink: sink_flow},
        frame_info={decode: (8, True), sink: (4, True)},
        dex_complete=True)
    hit = [c for c in cands if c.value == secret]
    assert len(hit) == 1, cands
    return gate_attributes(hit[0])


def test_derived_secret_route_maps_to_manual_review_not_confirmed(session, scan_id):
    attrs = _derived_secret_attrs()
    assert "format_and_entropy_ok" not in attrs          # inapplicable, left missing
    finding, record = _validate(
        session, scan_id, category="hardcoded-secret", attributes=attrs,
        title="Hardcoded key reaches SecretKeySpec via pure transform",
        description="Derived key-material route; decoded bytes not modelled.")
    assert record.verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert record.gate_passed is False
    assert finding.status is FindingStatus.MANUAL_REVIEW_REQUIRED
    assert finding.gate_evidence["format_and_entropy_ok"] is None   # never established
    assert finding.gate_evidence["used_in_security_context"] is True
    assert finding.gate_evidence["located"] is True
    assert 0.0 < finding.confidence < 1.0


def test_secret_format_refutation_would_reject(session, scan_id):
    """The contrast case: had the detector written format_and_entropy_ok=False
    for the same role-proven material, the report model REJECTS the weakness -
    which is exactly what the inapplicability rule prevents."""
    attrs = _derived_secret_attrs()
    attrs["format_and_entropy_ok"] = False
    finding, record = _validate(
        session, scan_id, category="hardcoded-secret", attributes=attrs,
        title="Hardcoded key reaches SecretKeySpec via pure transform",
        description="Contrast case: shape-based refutation of role-proven key material.")
    assert record.verdict is Verdict.REJECTED
    assert finding.status is FindingStatus.REJECTED


def test_derived_only_format_passing_literal_never_confirms(session, scan_id):
    """Whole report path: a derived-route candidate whose literal PASSES the
    format screen still lands MANUAL_REVIEW_REQUIRED - the format clause is
    missing (never True), so CONFIRMED is unreachable for derived-only
    evidence regardless of string shape."""
    attrs = _derived_secret_attrs(secret="kX9mZ2vB8qW4nR6pL0sT3yU7aC5dF1")
    assert "format_and_entropy_ok" not in attrs          # missing, not True
    assert attrs["used_in_security_context"] is True
    finding, record = _validate(
        session, scan_id, category="hardcoded-secret", attributes=attrs,
        title="Derived key route, format-passing literal",
        description="String shape passes; route evidence is may-depend only.")
    assert record.verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert record.gate_passed is False
    assert finding.status is FindingStatus.MANUAL_REVIEW_REQUIRED
    assert finding.gate_evidence["format_and_entropy_ok"] is None
    assert 0.0 < finding.confidence < 1.0
