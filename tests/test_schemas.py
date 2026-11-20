"""Invariants that must hold in the type system rather than in a code review."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mobius.core.enums import (
    AssertionLevel,
    Fidelity,
    ObservationKind,
    EvidenceKind,
    FindingStatus,
    RejectionReason,
    Severity,
    Verdict,
)
from mobius.core.schemas import (
    Authorization,
    Evidence,
    Finding,
    Observation,
    SourceRef,
    VerdictRecord,
)


def _evidence(**kw):
    base = dict(investigation_id="inv_1", kind=EvidenceKind.MANIFEST, sha256="a" * 64,
                object_key="k", byte_size=10, summary="manifest", produced_by="RECON")
    base.update(kw)
    return Evidence(**base)


def _finding(**kw):
    base = dict(
        investigation_id="inv_1",
        title="Exported activity reaches file write",
        category="exported-component-no-permission",
        description="d",
        evidence_refs=("ev_1",),
        severity=Severity.HIGH,
        confidence=1.0,
        status=FindingStatus.CONFIRMED,
        discovered_by="SPECTRE",
        validated_by="DETERMINISTIC_GATE",
        gate_evidence={"exported": True, "permission": True, "caller_check_absent": True,
                       "sink_reachable": True},
    )
    base.update(kw)
    return Finding(**base)


def test_confidence_is_not_merged_with_severity():
    f = _finding(severity=Severity.LOW, confidence=0.42)
    assert f.severity is Severity.LOW and f.confidence == 0.42


def test_confirmed_finding_requires_a_different_validator():
    with pytest.raises(ValidationError):
        _finding(validated_by="SPECTRE")
    with pytest.raises(ValidationError):
        _finding(validated_by=None)


def test_confirmed_finding_requires_evidence():
    with pytest.raises(ValidationError):
        _finding(evidence_refs=())


def test_confirmed_finding_requires_every_gate_clause_true():
    with pytest.raises(ValidationError):
        _finding(gate_evidence={"exported": True, "permission": False})


def test_rejected_verdict_requires_a_reason():
    with pytest.raises(ValidationError):
        VerdictRecord(finding_id="f_1", verdict=Verdict.REJECTED, rationale="r",
                      gate_passed=False, validated_by="DETERMINISTIC_GATE")
    ok = VerdictRecord(finding_id="f_1", verdict=Verdict.REJECTED,
                       rejection_reason=RejectionReason.TEST_ONLY_VALUE, rationale="r",
                       gate_passed=False, validated_by="DETERMINISTIC_GATE")
    assert ok.rejection_reason is RejectionReason.TEST_ONLY_VALUE


def _observation(**kw):
    base = dict(
        investigation_id="inv_1",
        agent="RECON",
        kind=ObservationKind.ANOMALY,
        fidelity=Fidelity.BINARY_XML,
        statement="a statement",
        confidence=0.5,
    )
    base.update(kw)
    return Observation(**base)


def test_fact_must_cite_evidence():
    """A fact with no evidence is an opinion with a confident label."""
    with pytest.raises(ValidationError):
        _observation(kind=ObservationKind.FACT, evidence_refs=(), confidence=1.0)
    ok = _observation(kind=ObservationKind.FACT, evidence_refs=("ev_1",), confidence=1.0)
    assert ok.kind is ObservationKind.FACT


def test_fact_must_be_certain():
    # A "fact" holding confidence 0.7 is a contradiction the schema refuses to store.
    with pytest.raises(ValidationError):
        _observation(kind=ObservationKind.FACT, evidence_refs=("ev_1",), confidence=0.7)


def test_anomaly_may_be_uncertain_without_evidence():
    a = _observation(kind=ObservationKind.ANOMALY, evidence_refs=(), confidence=0.2)
    assert a.confidence == 0.2


def test_assertion_levels_are_ordered():
    assert AssertionLevel.CONFIRMED.rank > AssertionLevel.OBSERVED.rank
    assert AssertionLevel.OBSERVED.rank > AssertionLevel.HYPOTHESIS.rank
    assert AssertionLevel.HYPOTHESIS.rank > AssertionLevel.REJECTED.rank


def test_unknown_fields_are_rejected_not_ignored():
    with pytest.raises(ValidationError):
        Evidence(investigation_id="inv_1", kind=EvidenceKind.MANIFEST, sha256="a" * 64,
                 object_key="k", byte_size=1, summary="s", produced_by="RECON", unexpected=1)


def test_evidence_rejects_non_hex_digest():
    with pytest.raises(ValidationError):
        _evidence(sha256="z" * 64)


def test_authorization_grant_cannot_widen_the_request():
    a = Authorization(apk_sha256="b" * 64, target_package="com.example",
                      scope_text="x" * 40, statement="s", max_intensity=1,
                      granted_by="u", expires_at="2030-01-01T00:00:00Z")
    assert a.max_intensity == 1


def test_pause_fields_are_coherent():
    with pytest.raises(ValidationError):
        from mobius.core.schemas import Investigation

        Investigation(application_id="app", authorization_id="ath", created_by="u",
                      objective="o", intensity=0, paused_at="2026-01-01T00:00:00Z")


def test_source_ref_lines_are_ordered():
    ok = SourceRef(file="a/b.java", lines=(3, 9))
    assert ok.lines == (3, 9)
    with pytest.raises(ValidationError):
        SourceRef(file="a/b.java", lines=(9, 3))


def test_source_ref_accepts_the_class_alias():
    ref = SourceRef(file="a/b.java", **{"class": "com.example.MainActivity"})
    assert ref.class_name == "com.example.MainActivity"


def test_verdict_is_four_valued():
    # Binary verdicts manufacture false certainty: "could not establish" is not "safe".
    assert {v.value for v in Verdict} == {
        "confirmed",
        "rejected",
        "needs_manual_review",
        "insufficient_evidence",
    }
