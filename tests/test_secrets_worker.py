"""Worker-side payload construction: deterministic mapping, fail-closed
evidence transport, truthful accounting, and no literal material in the
output. Every built payload is run through the real API validator."""
from __future__ import annotations

import json

import pytest

from mobius.adapters.flow_adapt import DexBlobCoverage
from mobius.adapters.secrets_payload import (
    MAX_CANDIDATES,
    derive_candidate_attributes,
    validate_secrets_analysis_payload,
)
from mobius.core import gates
from mobius.core.flow import FlowBlock, FlowEvidence, SInstruction
from mobius.core.reachability import MethodRef
from mobius.core.secrets import SecretCandidate
from mobius.worker.secrets_analysis import (
    WorkerError,
    build_secrets_payload,
)

SHA = "c" * 64
LIT = "kX9mZ2vB8qW4nR6pL0sT3yU7aC5dF1"  # format-passing screening literal
FOO = "com.example.Foo"
SKS = "Ljavax/crypto/spec/SecretKeySpec;"
SKS_DOTTED = "javax.crypto.spec.SecretKeySpec"
SKS_DESC = "([BLjava/lang/String;)V"
STR_DESC = "(Ljava/lang/Object;)Z"

KM_BASE = (
    "const-string literal flows via byte/char conversion into the key/password "
    f"argument (register position 1) of {SKS}-><init> at offset {{off}}")
CMP_BASE = (
    f"const-string literal compared by Ljava/lang/String;->equals against "
    "external input (p1); result consumed by if-eqz at offset {off}. "
    "Comparison+branch shape is shared with UI routing/dispatch; review-only.")
DERIVED_MID = (
    "[derived: literal is an argument of the closed-world pure transform "
    "Lcom/example/Foo;->decode at offset 3 (no field reads, no external "
    "sources, single return); bounded static over-approximation shows the "
    "transform's return MAY depend on the literal's content and reaches this "
    "sink. Transform output bytes are not modelled: no assertion that the "
    "output is valid decoded key bytes, its length, or its exact value] ")


def _ref(name="check", cls=FOO, desc="()V"):
    return MethodRef(cls, name, desc)


def _invoke(offset, cls=SKS, name="<init>", desc=SKS_DESC):
    return SInstruction(offset=offset, opcode="invoke-direct",
                        invoke_class=cls, invoke_method=name,
                        invoke_descriptor=desc)


def _flows(*, const_offsets=(4,), extra_instructions=(), extra_methods=()):
    instructions = [
        SInstruction(offset=o, opcode="const-string", literal=LIT)
        for o in const_offsets
    ]
    instructions += list(extra_instructions)
    flows = {_ref(): (FlowBlock(start=0, instructions=tuple(instructions)),)}
    for ref, ins in extra_methods:
        flows[ref] = (FlowBlock(start=0, instructions=tuple(ins)),)
    return flows


def _candidate(kind="key-material-argument", detail=None, ref=None, value=LIT,
               literal=LIT, flow_complete=True, evidence="default"):
    if evidence == "default":
        if detail is None:
            detail = KM_BASE.format(off=12)
        evidence = (FlowEvidence(kind, detail),)
    return SecretCandidate(
        method=ref or _ref(), literal=literal, value=value,
        basis=("entropy:4.91",),
        evidence=evidence,
        flow_complete=flow_complete)


def _ledger(methods=1):
    return [DexBlobCoverage(entry="classes.dex", status="parsed",
                            size_bytes=100, methods=methods)]


def _build(flows, candidates, ledger=None):
    return build_secrets_payload(
        artifact_sha256=SHA, package_name="com.example.app",
        flows=flows,
        ledger=_ledger(len(flows)) if ledger is None else ledger,
        candidates=candidates)


def _validate(payload):
    return validate_secrets_analysis_payload(
        json.dumps(payload).encode(), SHA)


# --- transport and contract roundtrip ---

def test_direct_evidence_roundtrip_through_api_validator():
    flows = _flows(extra_instructions=[_invoke(12)])
    payload = _build(flows, [_candidate()])
    result = _validate(payload)
    assert len(result.candidates) == 1
    cand = result.candidates[0]
    assert cand.candidate_id == (FOO, "check", "()V", 4)
    ev = cand.evidence[0]
    assert (ev.kind, ev.sink_class, ev.sink_method) == (
        "key-material-argument", SKS_DOTTED, "<init>")
    assert ev.sink_descriptor == SKS_DESC
    assert ev.arg_position == 1 and ev.sink_offset == 12
    assert (ev.container_class, ev.container_method,
            ev.container_descriptor) == (FOO, "check", "()V")
    derived = derive_candidate_attributes(result)
    gate = gates.evaluate("hardcoded-secret", derived[0].attributes)
    assert gate.passed is False and gate.failed_decisively == ()


def test_lowest_offset_is_the_identity_for_repeated_literals():
    flows = _flows(const_offsets=(9, 4, 21), extra_instructions=[_invoke(12)])
    payload = _build(flows, [_candidate()])
    assert _validate(payload).candidates[0].candidate_id[3] == 4


def test_derived_evidence_full_prefix_chain_resolves_transform():
    # Derived route allows a CROSS-CLASS sink hop: the callee is resolved
    # through the call instruction at the stated call offset, not by name.
    helper = _ref("helper", cls="com.example.Crypto", desc="(I)V")
    flows = _flows(
        extra_instructions=[
            _invoke(3, cls="Lcom/example/Foo;", name="decode",
                    desc="(Ljava/lang/String;)[B"),
            _invoke(5, cls="Lcom/example/Crypto;", name="helper", desc="(I)V")],
        extra_methods=[(helper, [_invoke(7)])])
    detail = ("[via internal call helper at offset 5 in com.example.Foo.check] "
              + DERIVED_MID + KM_BASE.format(off=7))
    payload = _build(flows, [_candidate("key-material-argument-derived", detail)])
    ev = _validate(payload).candidates[0].evidence[0]
    assert ev.kind == "key-material-argument-derived"
    assert (ev.sink_class, ev.sink_offset) == (SKS_DOTTED, 7)
    assert ev.transform_class == FOO and ev.transform_method == "decode"
    assert ev.transform_descriptor == "(Ljava/lang/String;)[B"
    assert ev.transform_offset == 3


def test_in_prefix_constructor_literal_resolves_sibling_sink():
    init = _ref("<init>")
    check = _ref("check")
    flows = {
        init: (FlowBlock(start=0, instructions=(
            SInstruction(offset=2, opcode="const-string", literal=LIT),)),),
        check: (FlowBlock(start=0, instructions=(_invoke(30),)),),
    }
    detail = "[in com.example.Foo.check] " + KM_BASE.format(off=30)
    payload = _build(flows, [_candidate(ref=init, detail=detail)])
    cand = _validate(payload).candidates[0]
    assert cand.candidate_id == (FOO, "<init>", "()V", 2)
    assert cand.evidence[0].sink_offset == 30


def test_comparison_evidence_descriptor_from_unique_invoke():
    flows = _flows(extra_instructions=[
        _invoke(8, cls="Ljava/lang/String;", name="equals", desc=STR_DESC),
        SInstruction(offset=20, opcode="if-eqz", registers=(0,))])
    payload = _build(flows, [_candidate("access-comparison-suspect",
                                        CMP_BASE.format(off=20))])
    ev = _validate(payload).candidates[0].evidence[0]
    assert ev.kind == "access-comparison-suspect"
    assert ev.sink_class == "java.lang.String"
    assert ev.sink_descriptor == STR_DESC and ev.sink_offset == 20


def test_placeholder_screening_outcome_transported():
    flows = _flows(extra_instructions=[_invoke(12)])
    payload = _build(flows, [_candidate(value="aaaaaaaa")])
    cand = _validate(payload).candidates[0]
    assert cand.placeholder_screening == "placeholder"
    derived = derive_candidate_attributes(
        _validate(payload))
    assert derived[0].dropped is True  # API-side drop, API-counted


# --- fail-closed: untransportable evidence becomes evidence_less ---

def _assert_untransported(payload):
    # Detector DID supply evidence; the mapping failure is its own category.
    result = _validate(payload)
    assert result.candidates == ()
    assert result.screened_total == 1
    assert result.conversion_failed == 1 and result.evidence_less == 0


def test_ambiguous_comparison_invokes_drop_candidate():
    # Two matching invokes with DIFFERENT descriptors: the worker cannot know
    # which one the detector saw, so it refuses to guess.
    flows = _flows(extra_instructions=[
        _invoke(8, cls="Ljava/lang/String;", name="equals", desc=STR_DESC),
        _invoke(9, cls="Ljava/lang/String;", name="equals", desc="(I)Z")])
    _assert_untransported(
        _build(flows, [_candidate("access-comparison-suspect",
                                  CMP_BASE.format(off=20))]))


def test_template_drift_drops_candidate():
    _assert_untransported(
        _build(_flows(extra_instructions=[_invoke(12)]),
               [_candidate(detail="key argument of SecretKeySpec at 12")]))


def test_kind_structure_mismatch_drops_candidate():
    # Claims derived without the derived prefix: not transportable.
    _assert_untransported(
        _build(_flows(extra_instructions=[_invoke(12)]),
               [_candidate("key-material-argument-derived",
                           KM_BASE.format(off=12))]))


def test_chained_callee_resolved_by_call_instruction_not_name():
    # Overloaded callees are NOT ambiguous: the call instruction at the call
    # offset names the exact class/method/descriptor.
    h1 = _ref("helper", cls="com.example.Crypto", desc="()V")
    h2 = _ref("helper", cls="com.example.Crypto", desc="(I)V")
    flows = _flows(
        extra_instructions=[_invoke(5, cls="Lcom/example/Crypto;",
                                    name="helper", desc="(I)V")],
        extra_methods=[(h1, []), (h2, [_invoke(7)])])
    detail = ("[via internal call helper at offset 5 in com.example.Foo.check] "
              + KM_BASE.format(off=7))
    payload = _build(flows, [_candidate(detail=detail)])
    ev = _validate(payload).candidates[0].evidence[0]
    assert ev.kind == "key-material-argument" and ev.sink_offset == 7


def test_call_offset_inconsistent_with_prefix_drops_candidate():
    flows = _flows(extra_instructions=[
        _invoke(5, cls="Lcom/example/Crypto;", name="other", desc="()V")])
    detail = ("[via internal call helper at offset 5 in com.example.Foo.check] "
              + KM_BASE.format(off=7))
    _assert_untransported(_build(flows, [_candidate(detail=detail)]))


def test_prefix_naming_another_declaring_method_drops_candidate():
    flows = _flows(extra_instructions=[_invoke(5, cls="Lcom/example/Crypto;",
                                               name="helper", desc="()V")])
    detail = ("[via internal call helper at offset 5 in com.example.Foo.store] "
              + KM_BASE.format(off=7))
    _assert_untransported(_build(flows, [_candidate(detail=detail)]))


def test_sink_offset_without_matching_invoke_drops_candidate():
    flows = _flows(extra_instructions=[_invoke(99, cls="Ljava/lang/String;",
                                               name="length", desc="()I")])
    _assert_untransported(_build(flows, [_candidate()]))  # offset 12 absent


def test_identity_locates_literal_declared_in_a_sibling_method():
    # Fallback candidates can be attached to <clinit> while the literal sits
    # in a sibling: the wire identity must name the sibling's instruction.
    init = _ref("<clinit>")
    sibling = _ref("store")
    flows = {
        init: (FlowBlock(start=0, instructions=(_invoke(30),)),),
        sibling: (FlowBlock(start=0, instructions=(
            SInstruction(offset=7, opcode="const-string", literal=LIT),)),),
    }
    detail = "[in com.example.Foo.<clinit>] " + KM_BASE.format(off=30)
    payload = _build(flows, [_candidate(ref=init, detail=detail)])
    cand = _validate(payload).candidates[0]
    assert cand.candidate_id == (FOO, "store", "()V", 7)


def test_missing_literal_occurrence_is_a_worker_error():
    flows = _flows()
    flows[_ref()] = (FlowBlock(start=0, instructions=(_invoke(12),)),)
    with pytest.raises(WorkerError):
        _build(flows, [_candidate()])


# --- accounting and determinism ---

def test_truncation_caps_transport_and_accounts():
    cands = [
        _candidate(ref=_ref(f"m{i}"), detail=KM_BASE.format(off=12))
        for i in range(MAX_CANDIDATES + 5)
    ]
    flows = {
        _ref(f"m{i}"): (FlowBlock(start=0, instructions=(
            SInstruction(offset=4, opcode="const-string", literal=LIT),
            _invoke(12))),)
        for i in range(MAX_CANDIDATES + 5)
    }
    payload = _build(flows, cands)
    assert payload["truncated"] is True
    assert len(payload["candidates"]) == MAX_CANDIDATES
    assert payload["counts"] == {"screened_total": MAX_CANDIDATES + 5,
                                 "evidence_less": 0, "conversion_failed": 0,
                                 "merged": 0}
    _validate(payload)  # truncated consistency: screened >= transported + less


def test_output_is_deterministic_regardless_of_candidate_order():
    c1 = _candidate(ref=_ref("a"), detail=KM_BASE.format(off=12))
    c2 = _candidate(ref=_ref("b"), detail=KM_BASE.format(off=12))
    flows = {
        _ref("a"): (FlowBlock(start=0, instructions=(
            SInstruction(offset=4, opcode="const-string", literal=LIT),
            _invoke(12))),),
        _ref("b"): (FlowBlock(start=0, instructions=(
            SInstruction(offset=6, opcode="const-string", literal=LIT),
            _invoke(12))),),
    }
    first = json.dumps(_build(flows, [c1, c2]), sort_keys=True)
    second = json.dumps(_build(flows, [c2, c1]), sort_keys=True)
    assert first == second


def test_no_literal_material_anywhere_in_payload():
    flows = _flows(extra_instructions=[_invoke(12)])
    payload = _build(flows, [_candidate()])
    blob = json.dumps(payload)
    assert LIT not in blob and "kX9m" not in blob


def test_same_literal_two_attachment_methods_merge_explicitly():
    # The detector keys candidates by (method, value); a literal admitted
    # under its declaring method AND via constructor-merge fallback is ONE
    # secret at ONE const-string instruction: one wire candidate, merged=1.
    init = _ref("<clinit>")
    store = _ref("store")
    flows = {
        init: (FlowBlock(start=0, instructions=(_invoke(30),)),),
        store: (FlowBlock(start=0, instructions=(
            SInstruction(offset=7, opcode="const-string", literal=LIT),
            _invoke(21))),),
    }
    c_fallback = _candidate(ref=init,
                            detail="[in com.example.Foo.<clinit>] "
                                   + KM_BASE.format(off=30))
    c_declaring = _candidate(ref=store, detail=KM_BASE.format(off=21))
    payload = _build(flows, [c_fallback, c_declaring])
    assert payload["counts"] == {"screened_total": 2, "evidence_less": 0,
                                 "conversion_failed": 0, "merged": 1}
    result = _validate(payload)
    assert len(result.candidates) == 1
    cand = result.candidates[0]
    assert cand.candidate_id == (FOO, "store", "()V", 7)
    assert {e.sink_offset for e in cand.evidence} == {21, 30}  # union


def test_merge_ands_flow_completeness():
    init = _ref("<clinit>")
    store = _ref("store")
    flows = {
        init: (FlowBlock(start=0, instructions=(_invoke(30),)),),
        store: (FlowBlock(start=0, instructions=(
            SInstruction(offset=7, opcode="const-string", literal=LIT),
            _invoke(21))),),
    }
    c1 = _candidate(ref=init, detail="[in com.example.Foo.<clinit>] "
                                     + KM_BASE.format(off=30),
                    flow_complete=False)
    c2 = _candidate(ref=store, detail=KM_BASE.format(off=21))
    payload = _build(flows, [c1, c2])
    assert _validate(payload).candidates[0].flow_complete is False


def test_candidate_without_any_detector_evidence_is_evidence_less():
    flows = _flows(extra_instructions=[_invoke(12)])
    payload = _build(flows, [_candidate(evidence=())])
    result = _validate(payload)
    assert result.candidates == ()
    assert result.evidence_less == 1 and result.conversion_failed == 0


def test_same_sink_from_two_containers_is_not_deduplicated():
    # Identical sink class/method/offset reachable from two different
    # containers: both items survive the merge union, locatable by container.
    init = _ref("<clinit>")
    store = _ref("store")
    flows = {
        init: (FlowBlock(start=0, instructions=(
            SInstruction(offset=7, opcode="const-string", literal=LIT),
            _invoke(30)),),),
        store: (FlowBlock(start=0, instructions=(
            SInstruction(offset=7, opcode="const-string", literal=LIT),
            _invoke(30)),),),
    }
    c1 = _candidate(ref=init, detail=KM_BASE.format(off=30))
    c2 = _candidate(ref=store, detail=KM_BASE.format(off=30))
    payload = _build(flows, [c1, c2])
    result = _validate(payload)
    # sink-only identity must NOT collapse them: two candidates, each keeping
    # its own container provenance
    assert len(result.candidates) == 2
    by_method = {c.candidate_id[1]: c for c in result.candidates}
    assert by_method["<clinit>"].evidence[0].container_method == "<clinit>"
    assert by_method["store"].evidence[0].container_method == "store"


def _fallback_flows(call_offset=5, real_desc=(" (I)V",)):
    real = _ref("real", desc="(I)V")
    init = _ref("<clinit>")
    helper = _ref("helper", cls="com.example.Crypto", desc="(I)V")
    return init, real, helper, {
        init: (FlowBlock(start=0, instructions=()),),
        real: (FlowBlock(start=0, instructions=(
            SInstruction(offset=7, opcode="const-string", literal=LIT),
            _invoke(call_offset, cls="Lcom/example/Crypto;",
                    name="helper", desc="(I)V")),),),
        helper: (FlowBlock(start=0, instructions=(_invoke(9),)),),
    }


def test_via_prefix_fallback_same_class_unique_method_recovers():
    # Attached to <clinit> (fallback) while the prefix names the carrying
    # method in the SAME class, uniquely: re-anchor, verify the rest exactly.
    init, real, helper, flows = _fallback_flows()
    detail = ("[via internal call helper at offset 5 in com.example.Foo.real] "
              + KM_BASE.format(off=9))
    payload = _build(flows, [_candidate(detail=detail, ref=init)])
    result = _validate(payload)
    assert result.conversion_failed == 0 and len(result.candidates) == 1
    ev = result.candidates[0].evidence[0]
    assert (ev.container_class, ev.container_method) == (
        "com.example.Crypto", "helper")
    assert (ev.sink_class, ev.sink_offset) == (SKS_DOTTED, 9)
    # identity: the literal's canonical occurrence, in the real method
    assert result.candidates[0].candidate_id == (FOO, "real", "(I)V", 7)


def test_via_prefix_fallback_cross_class_not_recovered():
    init, real, helper, flows = _fallback_flows()
    detail = ("[via internal call helper at offset 5 in com.example.Other.real] "
              + KM_BASE.format(off=9))
    payload = _build(flows, [_candidate(detail=detail, ref=init)])
    result = _validate(payload)
    assert result.conversion_failed == 1 and not result.candidates


def test_via_prefix_fallback_overloaded_name_not_recovered():
    init, real, helper, flows = _fallback_flows()
    overload = _ref("real", desc="()V")
    flows[overload] = (FlowBlock(start=0, instructions=()),)
    detail = ("[via internal call helper at offset 5 in com.example.Foo.real] "
              + KM_BASE.format(off=9))
    payload = _build(flows, [_candidate(detail=detail, ref=init)])
    result = _validate(payload)
    assert result.conversion_failed == 1 and not result.candidates


def test_via_prefix_fallback_wrong_call_offset_not_recovered():
    init, real, helper, flows = _fallback_flows(call_offset=6)
    detail = ("[via internal call helper at offset 5 in com.example.Foo.real] "
              + KM_BASE.format(off=9))
    payload = _build(flows, [_candidate(detail=detail, ref=init)])
    result = _validate(payload)
    assert result.conversion_failed == 1 and not result.candidates


# -- explicit service method bound (provider-worker pattern) ------------------

def _flows_of_size(n):
    return {MethodRef(f"com.synthetic.C{i}", "m", "()V"): [] for i in range(n)}


def test_run_refuses_over_methods_bound_before_detection(monkeypatch):
    from types import SimpleNamespace

    from mobius.worker import secrets_analysis as entry

    detected = []
    monkeypatch.setattr(entry, "parse_apk",
                        lambda apk: SimpleNamespace(package_name="com.example.app"))
    monkeypatch.setattr(entry, "adapt_code",
                        lambda apk: (_flows_of_size(50001), {}, {}, [], [], {}))
    monkeypatch.setattr(entry, "detect_hardcoded_secrets",
                        lambda *a, **k: detected.append(True))
    with pytest.raises(entry.MethodsBoundExceeded) as excinfo:
        entry.run(b"apk-bytes")
    assert excinfo.value.methods == 50001
    assert not detected  # refused BEFORE any detection work


def test_run_accepts_exactly_at_methods_bound(monkeypatch):
    from types import SimpleNamespace

    from mobius.worker import secrets_analysis as entry

    monkeypatch.setattr(entry, "parse_apk",
                        lambda apk: SimpleNamespace(package_name="com.example.app"))
    monkeypatch.setattr(entry, "adapt_code",
                        lambda apk: (_flows_of_size(50000), {}, {}, [], [], {}))
    monkeypatch.setattr(entry, "_static_flags", lambda apk, flows: {})
    monkeypatch.setattr(entry, "detect_hardcoded_secrets", lambda *a, **k: [])
    monkeypatch.setattr(entry, "build_secrets_payload", lambda **k: {"ok": True})
    monkeypatch.setattr(entry, "validate_secrets_analysis_payload",
                        lambda raw, digest: None)
    assert entry.run(b"apk-bytes") == {"ok": True}  # the bound itself is inclusive


def test_main_reports_explicit_method_bound_refusal(tmp_path, monkeypatch, capsys):
    import sys

    from mobius.worker import secrets_analysis as entry

    staged = tmp_path / "input.apk"
    staged.write_bytes(b"apk-bytes")
    monkeypatch.setattr(entry, "_STAGED_INPUT", staged)

    def _raise(_apk):
        raise entry.MethodsBoundExceeded(88350)

    monkeypatch.setattr(entry, "run", _raise)
    argv = sys.argv
    try:
        sys.argv = ["mobius-secrets-analysis", "--input", str(staged)]
        assert entry.main() == 4
    finally:
        sys.argv = argv
    err = capsys.readouterr().err
    assert "too large" in err
    assert "service method bound" in err
    assert "88350" in err            # structural accounting, never app data
    assert "Traceback" not in err
