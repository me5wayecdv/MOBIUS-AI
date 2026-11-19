"""Adversarial tests for the secrets phase-1 payload contract: the worker is
an untrusted producer, and CONFIRMED/REJECTED must be unreachable by
construction for ANY accepted payload - proven here against the real gate,
not measured on a corpus."""
from __future__ import annotations

import json

import pytest

from mobius.adapters.secrets_payload import (
    MAX_CANDIDATES,
    derive_candidate_attributes,
    validate_secrets_analysis_payload,
)
from mobius.core import gates

SHA = "a" * 64
OTHER_SHA = "b" * 64

SINK = ("javax.crypto.spec.SecretKeySpec", "<init>", "([BLjava/lang/String;)V")
XFORM = ("com.example.Foo", "decode", "(Ljava/lang/String;)[B")


def _ledger(methods=15, status="parsed", ambiguous=False, duplicates=0, entry="classes.dex"):
    return [{"entry": entry, "status": status, "size_bytes": 100, "methods": methods,
             "duplicates": duplicates, "ambiguous": ambiguous}]


def _candidate(offset=4, screening="not-placeholder", evidence=None, cls="com.example.Foo"):
    return {
        "method_class": cls,
        "method_name": "check",
        "method_descriptor": "()V",
        "literal_offset": offset,
        "placeholder_screening": screening,
        "flow_complete": True,
        "evidence": evidence if evidence is not None else [_direct_evidence()],
    }


def _direct_evidence():
    return {"kind": "key-material-argument", "container_class": "com.example.Foo",
            "container_method": "check", "container_descriptor": "()V",
            "sink_class": SINK[0],
            "sink_method": SINK[1], "sink_descriptor": SINK[2],
            "sink_offset": 12, "arg_position": 1}


def _derived_evidence():
    return {"kind": "key-material-argument-derived",
            "container_class": "com.example.Foo",
            "container_method": "check", "container_descriptor": "()V",
            "sink_class": SINK[0],
            "sink_method": SINK[1], "sink_descriptor": SINK[2],
            "sink_offset": 12, "arg_position": 1,
            "transform_class": XFORM[0], "transform_method": XFORM[1],
            "transform_descriptor": XFORM[2], "transform_offset": 8}


def _payload(candidates=None, **kw):
    cands = [_candidate()] if candidates is None else candidates
    body = {
        "schema_version": 1,
        "artifact_sha256": SHA,
        "package_name": "com.example.app",
        "methods_adapted": 15,
        "dex_coverage": _ledger(),
        "candidates": cands,
        "counts": {"screened_total": len(cands), "evidence_less": 0},
    }
    body.update(kw)
    return json.dumps(body).encode()


def _valid_result():
    return validate_secrets_analysis_payload(_payload(), SHA)


# --- anchor and schema boundary ---

def test_valid_payload_roundtrip():
    r = _valid_result()
    assert r.package_name == "com.example.app"
    assert r.dex_complete is True
    assert len(r.candidates) == 1
    assert r.candidates[0].candidate_id == ("com.example.Foo", "check", "()V", 4)


def test_tampered_sha256_rejected():
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(_payload(), OTHER_SHA)


def test_smuggled_gate_attribute_rejected():
    c = _candidate()
    c["used_in_security_context"] = True   # verdict channel in another shape
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(_payload(candidates=[c]), SHA)


def test_smuggled_verdict_field_rejected():
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(_payload(passed=True), SHA)


def test_worker_prose_rejected():
    c = _candidate()
    c["evidence"] = [_direct_evidence() | {"detail": "literal was s3cr3t!!"}]
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(_payload(candidates=[c]), SHA)


def test_hostile_string_in_bounded_fields_rejected():
    c = _candidate()
    c["method_class"] = 'com.example.Foo"; DROP TABLE findings; --'
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(_payload(candidates=[c]), SHA)


def test_unknown_evidence_kind_rejected():
    c = _candidate()
    c["evidence"] = [_direct_evidence() | {"kind": "definitely-a-key-trust-me"}]
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(_payload(candidates=[c]), SHA)


def test_duplicate_candidate_identity_rejected():
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(candidates=[_candidate(), _candidate()]), SHA)


def test_same_offset_distinct_method_is_distinct_identity():
    r = validate_secrets_analysis_payload(
        _payload(candidates=[_candidate(), _candidate(cls="com.example.Other")]), SHA)
    assert len(r.candidates) == 2


def test_over_cap_candidates_rejected():
    cands = [_candidate(offset=i) for i in range(MAX_CANDIDATES + 1)]
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(_payload(candidates=cands), SHA)


def test_truncated_flag_preserved_and_surfaced():
    r = validate_secrets_analysis_payload(_payload(truncated=True), SHA)
    assert r.truncated is True
    derived = derive_candidate_attributes(r)
    assert "TRUNCATED" in derived[0].description


def test_candidate_without_evidence_rejected():
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(candidates=[_candidate(evidence=[])]), SHA)


# --- ledger consistency (internal, never proof of truthful parse) ---

def test_unknown_ledger_status_rejected():
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(dex_coverage=_ledger(status="trust-me")), SHA)


def test_duplicate_entry_row_without_counted_original_rejected():
    rows = _ledger() + [{"entry": "classes2.dex", "status": "duplicate-entry",
                         "size_bytes": 100, "methods": 0, "duplicates": 0,
                         "ambiguous": False}]
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(_payload(dex_coverage=rows), SHA)


def test_methods_adapted_sum_mismatch_rejected():
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(methods_adapted=999), SHA)


def test_ambiguous_ledger_recomputes_incomplete():
    r = validate_secrets_analysis_payload(
        _payload(dex_coverage=_ledger(ambiguous=True, duplicates=3)), SHA)
    assert r.dex_complete is False


def test_derived_evidence_on_incomplete_ledger_rejected():
    c = _candidate(evidence=[_derived_evidence()])
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(candidates=[c],
                     dex_coverage=_ledger(ambiguous=True, duplicates=1)), SHA)


def test_derived_evidence_missing_transform_ref_rejected():
    e = _derived_evidence()
    del e["transform_class"]
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(candidates=[_candidate(evidence=[e])]), SHA)


def test_direct_evidence_carrying_transform_ref_rejected():
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(candidates=[_candidate(
                evidence=[_direct_evidence() | {"transform_offset": 8}])]), SHA)


def test_derived_evidence_on_consistent_ledger_accepted():
    r = validate_secrets_analysis_payload(
        _payload(candidates=[_candidate(evidence=[_derived_evidence()])]), SHA)
    assert r.candidates[0].security_use_basis == "may-depend-derived-route-only"


# --- the phase-1 invariant: CONFIRMED and REJECTED unreachable ---

def _gate_result_for(evidence):
    r = validate_secrets_analysis_payload(
        _payload(candidates=[_candidate(evidence=[evidence])]), SHA)
    derived = derive_candidate_attributes(r)
    assert len(derived) == 1 and not derived[0].dropped
    return derived[0], gates.evaluate("hardcoded-secret", derived[0].attributes)


def test_invariant_direct_evidence_never_confirms_or_rejects():
    d, result = _gate_result_for(_direct_evidence())
    assert result.passed is False
    assert result.failed_decisively == ()
    assert "format_and_entropy_ok" in result.missing_attributes
    assert d.attributes["used_in_security_context"] is True
    assert d.candidate.security_use_basis == "direct-key-material-evidence"
    assert "direct key-material evidence" in d.description


def test_invariant_derived_evidence_never_confirms_or_rejects():
    d, result = _gate_result_for(_derived_evidence())
    assert result.passed is False
    assert result.failed_decisively == ()
    assert "MAY-depend" in d.description
    assert "unmodelled" in d.description


def test_invariant_flow_incomplete_recorded_not_refuted():
    c = _candidate(evidence=[_derived_evidence()])
    c["flow_complete"] = False
    r = validate_secrets_analysis_payload(_payload(candidates=[c]), SHA)
    d = derive_candidate_attributes(r)[0]
    assert d.attributes["flow_incomplete"] is True   # recorded explicitly
    assert "INCOMPLETE" in d.description
    result = gates.evaluate("hardcoded-secret", d.attributes)
    assert result.passed is False
    assert result.failed_decisively == ()            # incompleteness is not a refutation


def test_placeholder_screened_candidate_dropped_and_counted():
    r = validate_secrets_analysis_payload(
        _payload(candidates=[_candidate(screening="placeholder")]), SHA)
    derived = derive_candidate_attributes(r)
    assert len(derived) == 1 and derived[0].dropped is True
    assert derived[0].attributes == {}   # never written with not_placeholder False


def test_unknown_placeholder_screening_rejected():
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(candidates=[_candidate(screening="looks-fine")]), SHA)


def test_review_signal_only_candidate_has_no_security_use():
    e = {"kind": "access-comparison-suspect", "sink_class": "java.lang.String",
         "sink_method": "equals", "sink_descriptor": "(Ljava/lang/Object;)Z",
         "sink_offset": 4, "container_class": "com.example.Foo",
         "container_method": "check", "container_descriptor": "()V"}
    d, result = _gate_result_for(e)
    assert "used_in_security_context" not in d.attributes
    assert result.passed is False
    assert result.failed_decisively == ()
    assert "not established" in d.description


def test_result_strings_are_structural_only():
    """Every worker-supplied string that survives validation matches the
    strict structural patterns - no free text anywhere in the result."""
    import re as _re
    r = _valid_result()
    assert _re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+", r.package_name)
    for c in r.candidates:
        cls, name, desc, off = c.candidate_id
        assert _re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)+", cls)
        assert _re.fullmatch(r"[A-Za-z_$<][A-Za-z0-9_$>]*", name)
        assert _re.fullmatch(r"\(.*\).*", desc)
        assert isinstance(off, int)
        for e in c.evidence:
            for v in (e.sink_class, e.sink_method, e.sink_descriptor):
                assert _re.fullmatch(r"[A-Za-z0-9_.$/;()\[\]<>]+", v)
    assert isinstance(r.ledger[0].entry, str) and r.ledger[0].entry.endswith(".dex")


# --- repair: sink enumeration, strict types, bounds, counts ---

def test_key_evidence_sink_outside_detector_vocabulary_rejected():
    e = _direct_evidence()
    e["sink_class"], e["sink_method"] = "com.example.Crypto", "a"
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(candidates=[_candidate(evidence=[e])]), SHA)


def test_key_evidence_wrong_argument_position_rejected():
    e = _direct_evidence()  # SecretKeySpec.<init> accepts only position 1
    e["arg_position"] = 0
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(candidates=[_candidate(evidence=[e])]), SHA)


def test_comparison_sink_outside_detector_vocabulary_rejected():
    e = {"kind": "access-comparison-suspect", "sink_class": "java.lang.String",
         "sink_method": "startsWith", "sink_descriptor": "(Ljava/lang/String;)Z",
         "sink_offset": 4, "container_class": "com.example.Foo",
         "container_method": "check", "container_descriptor": "()V"}
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(candidates=[_candidate(evidence=[e])]), SHA)


def test_hostile_text_in_comparison_sink_fields_rejected():
    e = {"kind": "access-comparison-suspect",
         "sink_class": 'java.lang.String"><script>', "sink_method": "equals",
         "sink_descriptor": "(Ljava/lang/Object;)Z", "sink_offset": 4,
         "container_class": "com.example.Foo", "container_method": "check",
         "container_descriptor": "()V"}
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(candidates=[_candidate(evidence=[e])]), SHA)


def test_oversized_strings_rejected():
    c = _candidate()
    c["method_class"] = "a." + "b" * 1000
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(_payload(candidates=[c]), SHA)
    e = _direct_evidence()
    e["sink_descriptor"] = "(" + "Lx;" * 1000 + ")V"
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(candidates=[_candidate(evidence=[e])]), SHA)


def test_stringly_typed_scalars_rejected():
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(_payload(truncated="true"), SHA)
    c = _candidate()
    c["literal_offset"] = "4"
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(_payload(candidates=[c]), SHA)


def test_counts_inconsistent_with_payload_rejected():
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(counts={"screened_total": 7, "evidence_less": 0}), SHA)


def test_counts_undercounted_when_truncated_rejected():
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(truncated=True, counts={"screened_total": 0,
                                             "evidence_less": 0}), SHA)


def test_counts_accepts_untransported_evidence_less_candidates():
    r = validate_secrets_analysis_payload(
        _payload(counts={"screened_total": 5, "evidence_less": 4}), SHA)
    assert r.screened_total == 5 and r.evidence_less == 4


def test_accounting_names_the_source_of_each_number():
    from mobius.adapters.secrets_payload import accounting
    r = validate_secrets_analysis_payload(
        _payload(candidates=[_candidate(), _candidate(offset=9,
                                                      screening="placeholder")],
                 counts={"screened_total": 6, "evidence_less": 4}), SHA)
    derived = derive_candidate_attributes(r)
    acc = accounting(r, derived)
    assert acc.screened_total == 6      # worker-asserted
    assert acc.evidence_less == 4       # worker-asserted, NOT transported
    assert acc.conversion_failed == 0       # worker-asserted; nonzero = incomplete transport
    assert acc.transported == 2         # API-counted
    assert acc.placeholder_dropped == 1  # API-counted at derivation
    assert acc.truncated is False


# --- R1: no free text in ledger or package name ---

def test_ledger_error_prose_rejected():
    rows = _ledger()[0] | {"error": "parse blew up at 0x1f <details>"}
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(_payload(dex_coverage=[rows]), SHA)


def test_hostile_ledger_entry_rejected():
    for entry in ('classes.dex"><script>', "res/raw/classes.dex",
                  "classes.dex;rm -rf", "../classes.dex", "not-a-dex.txt"):
        with pytest.raises(ValueError):
            validate_secrets_analysis_payload(
                _payload(dex_coverage=_ledger(entry=entry)), SHA)


def test_multidex_entry_names_accepted():
    rows = _ledger(entry="classes.dex", methods=10) + _ledger(
        entry="classes2.dex", methods=5)
    r = validate_secrets_analysis_payload(
        _payload(dex_coverage=rows, methods_adapted=15), SHA)
    assert [b.entry for b in r.ledger] == ["classes.dex", "classes2.dex"]


def test_hostile_package_name_rejected():
    for pkg in ('com.example.app"; DROP TABLE findings; --',
                "com.example..app", "com.example.app extra"):
        with pytest.raises(ValueError):
            validate_secrets_analysis_payload(
                _payload(package_name=pkg), SHA)


def test_hostile_container_fields_rejected():
    e = _direct_evidence()
    e["container_class"] = 'com.example.Foo"><script>'
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(candidates=[_candidate(evidence=[e])]), SHA)
    e = _direct_evidence()
    del e["container_method"]
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(candidates=[_candidate(evidence=[e])]), SHA)


def test_package_names_allow_ascii_case_measured_need():
    # a2dp.Vol is a real corpus app; ASCII case is accepted, nothing wider.
    r = validate_secrets_analysis_payload(_payload(package_name="a2dp.Vol"), SHA)
    assert r.package_name == "a2dp.Vol"
    with pytest.raises(ValueError):
        validate_secrets_analysis_payload(
            _payload(package_name="a2dp.Völ"), SHA)  # non-ASCII stays closed


def test_conversion_failed_surfaces_incomplete_transport_in_description():
    r = validate_secrets_analysis_payload(
        _payload(candidates=[_candidate()],
                 counts={"screened_total": 3, "evidence_less": 1,
                         "conversion_failed": 1}), SHA)
    d = derive_candidate_attributes(r)[0]
    assert "Payload transport INCOMPLETE: 1" in d.description
    assert "not a complete scan" in d.description
    result = gates.evaluate("hardcoded-secret", d.attributes)
    assert result.failed_decisively == ()  # incomplete transport never refutes


def test_transport_complete_empty_failed_vs_empty_clean():
    from mobius.adapters.secrets_payload import accounting
    # Empty but FAILED transport: scan-level incomplete even with zero
    # candidates to carry a description marker.
    r = validate_secrets_analysis_payload(
        _payload(candidates=[],
                 counts={"screened_total": 3, "evidence_less": 0,
                         "conversion_failed": 3}), SHA)
    assert r.transport_complete is False
    acc = accounting(r, derive_candidate_attributes(r))
    assert acc.transport_complete is False
    # Empty and CLEAN: complete transport - still never a no-secrets claim.
    r = validate_secrets_analysis_payload(
        _payload(candidates=[],
                 counts={"screened_total": 5, "evidence_less": 5}), SHA)
    assert r.transport_complete is True
    acc = accounting(r, derive_candidate_attributes(r))
    assert acc.transport_complete is True
    # Truncated transport is never complete, even with zero failed.
    r = validate_secrets_analysis_payload(
        _payload(candidates=[], truncated=True,
                 counts={"screened_total": 5, "evidence_less": 4}), SHA)
    assert r.transport_complete is False
