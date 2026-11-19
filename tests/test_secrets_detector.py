"""Adversarial tests for the secrets prototype: evidence must come from actual
register-level flow with correct kill/join semantics, never from co-occurrence,
method names, or format alone."""
from __future__ import annotations

from mobius.core import gates
from mobius.core.reachability import MethodRef
from mobius.core.secrets import (
    FlowBlock,
    SInstruction,
    detect_hardcoded_secrets,
    gate_attributes,
    scan_method_flow,
)


class FakeIndex:
    def __init__(self, strings):
        self.strings = strings


def M(name="access", cls="com.example.Foo"):
    return MethodRef(cls, name, "()V")


def cs(reg, value, off):
    return SInstruction(off, "const-string", (reg,), literal=value)


def inv(off, cls, name, regs, static=False):
    return SInstruction(off, "invoke-static" if static else "invoke-virtual",
                        tuple(regs), invoke_class=cls, invoke_method=name, is_static=static)


def mr(reg, off):
    return SInstruction(off, "move-result-object", (reg,))


def mv(d, s, off):
    return SInstruction(off, "move-object", (d, s))


def ifz(reg, off, op="if-eqz"):
    return SInstruction(off, op, (reg,))


SECRET = "s3cr3t-Vend0r-K3y!!"
EXT = ("Landroid/widget/EditText;", "getText")
EQUALS = ("Ljava/lang/String;", "equals")
SECRETKEYSPEC = ("Ljavax/crypto/spec/SecretKeySpec;", "<init>")
GETBYTES = ("Ljava/lang/String;", "getBytes")


def flat(flow):
    """Linear flows are single blocks."""
    return flow


def test_key_material_flow_confirms():
    m = M(name="initCrypto")
    flow = [
        cs(1, SECRET, 0),
        inv(4, *GETBYTES, (1,)),
        mr(2, 8),                                    # lit -> keybytes
        inv(10, *SECRETKEYSPEC, (3, 2, 4)),          # new SecretKeySpec(bytes, "AES")
    ]
    scan = scan_method_flow(flat(flow))
    assert SECRET in scan.evidence
    assert scan.evidence[SECRET][0].kind == "key-material-argument"
    cands = detect_hardcoded_secrets(FakeIndex({m: (SECRET,)}), {m: [FlowBlock(0, tuple(flow), ())]})
    assert len(cands) == 1 and cands[0].used_in_security_context is True


def test_algorithm_literal_is_not_key_material():
    # adversarial: "AES" arrives UNCONVERTED at SecretKeySpec (the String
    # algorithm parameter). Key-material evidence requires byte/char conversion.
    m = M(name="initCrypto")
    flow = [
        cs(1, "AES", 0),
        cs(2, SECRET, 4),
        inv(8, *GETBYTES, (2,)),
        mr(3, 12),
        inv(14, *SECRETKEYSPEC, (4, 3, 1)),          # (receiver, keyBytes, "AES")
    ]
    scan = scan_method_flow(flat(flow))
    assert "AES" not in scan.evidence
    assert SECRET in scan.evidence


def test_iv_and_digest_payload_are_not_evidence():
    # adversarial per review: IV bytes, salts and digested payloads are not
    # automatically secret key material.
    m = M(name="derive")
    flow = [
        cs(1, SECRET, 0),
        inv(4, *GETBYTES, (1,)),
        mr(2, 8),
        inv(10, "Ljavax/crypto/spec/IvParameterSpec;", "<init>", (3, 2)),
        inv(14, "Ljava/security/MessageDigest;", "digest", (5, 2)),
        inv(18, "Ljavax/crypto/spec/PBEParameterSpec;", "<init>", (6, 2, 7)),
    ]
    scan = scan_method_flow(flat(flow))
    assert SECRET not in scan.evidence


def test_access_comparison_is_review_only_not_confirmation():
    # a compared external string feeding a branch is not necessarily auth/access
    m = M()
    flow = [
        cs(1, SECRET, 0),
        inv(4, *EXT, (2,)),
        mr(3, 8),
        inv(10, *EQUALS, (1, 3)),
        mr(4, 14),
        ifz(4, 16),
    ]
    cands = detect_hardcoded_secrets(FakeIndex({m: (SECRET,)}), {m: [FlowBlock(0, tuple(flow), ())]})
    assert len(cands) == 1
    assert cands[0].used_in_security_context is None          # NOT confirmed
    attrs = gate_attributes(cands[0])
    assert "used_in_security_context" not in attrs
    assert attrs["access_comparison_suspect"] is True         # raised for review


def test_ui_routing_comparison_is_review_only():
    # adversarial: ordinary UI routing has the identical compare+branch shape
    m = M(name="onSubmit")
    flow = [
        cs(1, "Submit", 0),
        inv(4, *EXT, (2,)),
        mr(3, 8),
        inv(10, *EQUALS, (1, 3)),
        mr(4, 14),
        ifz(4, 16),
    ]
    scan = scan_method_flow(flat(flow))
    kinds = {e.kind for e in scan.evidence.get("Submit", ())}
    assert kinds == {"access-comparison-suspect"}
    cands = detect_hardcoded_secrets(FakeIndex({m: ("Submit",)}), {m: [FlowBlock(0, tuple(flow), ())]})
    assert not cands or all(c.used_in_security_context is None for c in cands)


def test_action_dispatch_with_access_like_name_not_evidenced():
    # adversarial: getAction() is dispatch metadata, even in access-like names
    m = M(name="checkAccess", cls="com.example.UnlockReceiver")
    flow = [
        cs(1, "xK9#mQ2$vL8&nB4@", 0),
        inv(4, "Landroid/content/Intent;", "getAction", (2,)),
        mr(3, 8),
        inv(10, *EQUALS, (3, 1)),
        mr(4, 14),
        ifz(4, 16),
    ]
    scan = scan_method_flow(flat(flow))
    assert "xK9#mQ2$vL8&nB4@" not in scan.evidence


def test_overwritten_register_kills_provenance():
    # adversarial: arbitrary register write between literal load and use
    m = M()
    flow = [
        cs(1, SECRET, 0),
        SInstruction(4, "add-int", (1, 2, 3)),       # v1 overwritten by arithmetic
        inv(8, *GETBYTES, (1,)),
        mr(4, 12),
        inv(14, *SECRETKEYSPEC, (5, 4, 6)),
    ]
    scan = scan_method_flow(flat(flow))
    assert SECRET not in scan.evidence


def test_mutually_exclusive_paths_do_not_confirm():
    # adversarial: v1 is SECRET on one branch, a label on the other; the join
    # may-flows both into a comparison, which is review-only regardless.
    m = M()
    b0 = FlowBlock(0, (cs(1, SECRET, 0),), (10, 20))
    b1 = FlowBlock(10, (mv(2, 1, 10),), (30,))       # path A: keep SECRET
    b2 = FlowBlock(20, (cs(1, "title", 20),), (30,)) # path B: overwrite
    b3 = FlowBlock(30, (
        inv(30, *EXT, (3,)),
        mr(4, 34),
        inv(36, *EQUALS, (1, 4)),
        mr(5, 40),
        ifz(5, 42),
    ), ())
    scan = scan_method_flow([b0, b1, b2, b3])
    kinds = {e.kind for e in scan.evidence.get(SECRET, ())}
    assert kinds <= {"access-comparison-suspect"}
    cands = detect_hardcoded_secrets(FakeIndex({m: (SECRET, "title")}), {m: [b0, b1, b2, b3]})
    assert all(c.used_in_security_context is None for c in cands)


def test_branch_unrelated_comparison_not_evidenced():
    m = M()
    flow = [
        cs(1, SECRET, 0),
        inv(4, *EXT, (2,)),
        mr(3, 8),
        inv(10, *EQUALS, (1, 3)),
        mr(4, 14),
        inv(16, "Landroid/util/Log;", "d", (5, 4)),  # logged, never branched
    ]
    scan = scan_method_flow(flat(flow))
    assert SECRET not in scan.evidence


def test_unrelated_string_same_method_as_crypto_not_confirmed():
    m = M()
    google = "AIzaSyD4iE4XvB6kC0mD8nF2gH5jL9pQ1rS3tU7v"
    flow = [
        cs(1, google, 0),                            # never flows anywhere
        cs(5, SECRET, 4),
        inv(8, *GETBYTES, (5,)),
        mr(6, 12),
        inv(14, *SECRETKEYSPEC, (7, 6, 8)),
    ]
    cands = detect_hardcoded_secrets(FakeIndex({m: (google, SECRET)}), {m: [FlowBlock(0, tuple(flow), ())]})
    by_value = {c.value: c for c in cands}
    assert by_value[google].used_in_security_context is None
    assert by_value[SECRET].used_in_security_context is True


def test_public_identifier_screened_out():
    m = M()
    idx = FakeIndex({m: ("android.speech.extra.RESULTS_PENDING_INTENT",)})
    assert detect_hardcoded_secrets(idx, {m: []}) == []


def test_high_entropy_constant_without_use_not_confirmed():
    m = M()
    value = "Zx9#Qw2$Er7&Ty5*Ui8!"
    flow = [cs(1, value, 0), inv(4, "Landroid/util/Log;", "d", (2, 1))]
    cands = detect_hardcoded_secrets(FakeIndex({m: (value,)}), {m: [FlowBlock(0, tuple(flow), ())]})
    assert len(cands) == 1 and cands[0].used_in_security_context is None


def test_pure_digit_pin_gets_review_evidence_not_placeholder_filtered():
    # no blanket pure-digit-never-key: a compared PIN is admitted and reviewed
    m = M(name="unlockPin")
    flow = [
        cs(1, "8842", 0),
        inv(4, *EXT, (2,)),
        mr(3, 8),
        inv(10, *EQUALS, (1, 3)),
        mr(4, 14),
        ifz(4, 16, op="if-nez"),
    ]
    cands = detect_hardcoded_secrets(FakeIndex({m: ("8842",)}), {m: [FlowBlock(0, tuple(flow), ())]})
    assert len(cands) == 1
    assert cands[0].used_in_security_context is None
    assert gate_attributes(cands[0])["access_comparison_suspect"] is True


def test_format_inapplicable_left_unestablished_for_role_proven_key():
    m = M()
    value = "vendorsecretkey"
    flow = [
        cs(1, value, 0),
        inv(4, *GETBYTES, (1,)),
        mr(2, 8),
        inv(10, *SECRETKEYSPEC, (3, 2, 4)),
    ]
    cands = detect_hardcoded_secrets(FakeIndex({m: (value,)}), {m: [FlowBlock(0, tuple(flow), ())]})
    attrs = gate_attributes(cands[0])
    assert attrs["used_in_security_context"] is True   # key-material evidence
    # Credential-shape assessment is inapplicable to role-proven key material:
    # the clause is left UNESTABLISHED (never forced True, never refuted on
    # shape) and the gate reports it missing, not decisively failed.
    assert "format_and_entropy_ok" not in attrs
    assert "inapplicable" in attrs["format_assessment"]
    result = gates.evaluate("hardcoded-secret", attrs)
    assert not result.passed
    assert result.missing_attributes == ("format_and_entropy_ok",)
    assert result.failed_decisively == ()


def test_move_chain_and_check_cast_preserve_provenance():
    m = M(name="verifyToken")
    flow = [
        cs(7, SECRET, 0),
        mv(1, 7, 4),
        SInstruction(8, "check-cast", (1,)),
        inv(12, *GETBYTES, (1,)),
        mr(2, 16),
        inv(18, *SECRETKEYSPEC, (3, 2, 4)),
    ]
    scan = scan_method_flow(flat(flow))
    assert SECRET in scan.evidence


def test_invoke_range_marks_flow_incomplete_without_guessing():
    m = M()
    flow = [
        cs(1, SECRET, 0),
        SInstruction(4, "invoke-virtual/range", (), invoke_class="Ljavax/crypto/spec/SecretKeySpec;",
                     invoke_method="<init>", unsupported=True),
    ]
    scan = scan_method_flow(flat(flow))
    assert scan.complete is False
    assert SECRET not in scan.evidence


def test_cycle_marks_incomplete():
    m = M()
    b0 = FlowBlock(0, (cs(1, SECRET, 0),), (10,))
    b1 = FlowBlock(10, (mv(2, 1, 10),), (10,))       # self-loop
    scan = scan_method_flow([b0, b1])
    assert scan.complete is False


FIELD = ("Lcom/example/Foo;", "key", "[B")
STRFIELD = ("Lcom/example/Foo;", "keyString", "Ljava/lang/String;")


def iput(v, obj, off, ref=STRFIELD):
    return SInstruction(off, "iput-object", (v, obj), field_ref=ref)


def iget(d, obj, off, ref=STRFIELD):
    return SInstruction(off, "iget-object", (d, obj), field_ref=ref)


def test_field_carried_key_material_evidence_with_uncertainty():
    """CryptoClass shape: const-string stored to a field, read back in a later
    block, converted and consumed as key material. Evidence must survive the
    field round-trip."""
    flow = [
        FlowBlock(0, (
            cs(1, SECRET, 0),
            iput(1, 0, 4),                           # this.keyString = SECRET
        ), (10,)),
        FlowBlock(10, (
            iget(2, 0, 10),                          # v2 = this.keyString
            inv(14, *GETBYTES, (2,)),
            mr(3, 18),
            inv(20, *SECRETKEYSPEC, (4, 3, 5)),
        ), ()),
    ]
    scan = scan_method_flow(flow)
    assert scan.complete is True
    assert SECRET in scan.evidence
    assert scan.evidence[SECRET][0].kind == "key-material-argument"


def test_field_read_without_local_store_is_unknown_not_literal():
    """A field never stored within the scanned method yields an opaque field
    origin marker: no evidence, but the scan stays structurally complete
    (same contract as unmodelled invoke returns)."""
    flow = [
        iget(2, 0, 0),
        inv(4, *GETBYTES, (2,)),
        mr(3, 8),
        inv(10, *SECRETKEYSPEC, (4, 3, 5)),
    ]
    scan = scan_method_flow(flat(flow))
    assert scan.complete is True
    assert scan.evidence == {}


def test_field_op_without_resolved_reference_marks_incomplete():
    flow = [
        cs(1, SECRET, 0),
        SInstruction(4, "iput-object", (1, 0)),      # field_ref=None
        iget(2, 0, 8),
        inv(12, *GETBYTES, (2,)),
    ]
    scan = scan_method_flow(flat(flow))
    assert scan.complete is False


def test_static_field_round_trip():
    flow = [
        FlowBlock(0, (
            cs(1, SECRET, 0),
            SInstruction(4, "sput-object", (1,), field_ref=STRFIELD),
        ), (10,)),
        FlowBlock(10, (
            SInstruction(10, "sget-object", (2,), field_ref=STRFIELD),
            inv(14, *GETBYTES, (2,)),
            mr(3, 18),
            inv(20, *SECRETKEYSPEC, (4, 3, 5)),
        ), ()),
    ]
    scan = scan_method_flow(flow)
    assert scan.complete is True
    assert SECRET in scan.evidence


# -- review-hardening: field dependence and dispatch exactness ------------------

def test_field_carried_evidence_is_candidate_only_not_confirmed():
    """Field-carried key material still produces evidence, but the candidate
    must NOT be flow_complete: sibling writes/setters/aliases are unmodelled."""
    ctor = M(name="<init>")
    user = M(name="use")
    ctor_flow = [FlowBlock(0, (cs(1, SECRET, 0), iput(1, 0, 4)), ())]
    user_flow = [FlowBlock(0, (
        iget(2, 0, 0),
        inv(4, *GETBYTES, (2,)),
        mr(3, 8),
        inv(10, *SECRETKEYSPEC, (4, 3, 5)),
    ), ())]
    cands = detect_hardcoded_secrets(
        FakeIndex({ctor: (SECRET,)}), {ctor: ctor_flow, user: user_flow})
    hit = [c for c in cands if c.value == SECRET]
    assert len(hit) == 1
    assert hit[0].used_in_security_context is True   # evidence exists
    assert hit[0].flow_complete is False             # but stays candidate-only


def test_virtual_call_is_never_chained():
    """invoke-virtual on a same-class method can resolve to an override:
    no chaining, no evidence, no guessing."""
    ctor = M(name="<init>")
    user = M(name="use")
    helper = MethodRef("com.example.Foo", "helper", "([B)V")  # descriptor MATCHES the call
    ctor_flow = [FlowBlock(0, (cs(1, SECRET, 0), iput(1, 0, 4)), ())]
    user_flow = [FlowBlock(0, (
        iget(2, 0, 0),
        inv(4, *GETBYTES, (2,)),
        mr(3, 8),
        SInstruction(10, "invoke-virtual", (5, 3),
                     invoke_class="Lcom/example/Foo;", invoke_method="helper",
                     invoke_descriptor="([B)V"),
    ), ())]
    helper_flow = [FlowBlock(0, (
        inv(0, *SECRETKEYSPEC, (4, 5, 6)),           # would flag v5 if seeded
    ), ())]
    # frame metadata present, so ONLY the virtual opcode may block chaining
    cands = detect_hardcoded_secrets(
        FakeIndex({ctor: (SECRET,)}),
        {ctor: ctor_flow, user: user_flow, helper: helper_flow},
        frame_info={helper: (8, False)})
    hit = [c for c in cands if c.value == SECRET]
    assert not hit or all(
        "helper" not in e.detail for c in hit for e in c.evidence)


def test_overload_descriptor_mismatch_is_not_chained():
    """Same name, different descriptor: no exact dispatch, no chaining."""
    caller = M(name="caller")
    callee = M(name="helper")                        # descriptor ()V, call site ([B)V
    caller_flow = [FlowBlock(0, (
        cs(1, SECRET, 0),
        inv(4, *GETBYTES, (1,)),
        mr(2, 8),
        SInstruction(10, "invoke-static", (2,),
                     invoke_class="Lcom/example/Foo;", invoke_method="helper",
                     invoke_descriptor="([B)V", is_static=True),
    ), ())]
    callee_flow = [FlowBlock(0, (cs(3, "irrelevant", 0),), ())]
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET,)}), {caller: caller_flow, callee: callee_flow})
    assert all("helper" not in e.detail for c in cands for e in c.evidence)


def test_branch_overwrite_unions_both_provenances():
    """A field written on two branches keeps BOTH literals at the read
    (may-flow union; no arbitrary winner)."""
    flow = [
        FlowBlock(0, (cs(1, SECRET, 0), iput(1, 0, 4)), (10, 20)),
        FlowBlock(10, (SInstruction(10, "goto", ()),), (30,)),
        FlowBlock(20, (cs(1, "Alt3rnate-K3y!!", 20), iput(1, 0, 24)), (30,)),
        FlowBlock(30, (
            iget(2, 0, 30),
            inv(34, *GETBYTES, (2,)),
            mr(3, 38),
            inv(40, *SECRETKEYSPEC, (4, 3, 5)),
        ), ()),
    ]
    scan = scan_method_flow(flow)
    assert SECRET in scan.evidence and "Alt3rnate-K3y!!" in scan.evidence
    assert scan.field_dependent is True


def test_missing_constructor_keeps_field_read_opaque():
    """No constructor in the flow map: field read yields the opaque marker,
    no evidence, no literal masquerade."""
    user = M(name="use")
    user_flow = [FlowBlock(0, (
        iget(2, 0, 0),
        inv(4, *GETBYTES, (2,)),
        mr(3, 8),
        inv(10, *SECRETKEYSPEC, (4, 3, 5)),
    ), ())]
    cands = detect_hardcoded_secrets(FakeIndex({user: ()}), {user: user_flow})
    assert all(c.value != SECRET for c in cands)


def test_one_hop_incomplete_callee_downgrades_candidate():
    """If the chained callee scan is incomplete, the merged candidate must
    say flow_incomplete."""
    ctor = M(name="<init>")
    user = M(name="use")
    helper = MethodRef("com.example.Foo", "helper", "([B)V")
    ctor_flow = [FlowBlock(0, (cs(1, SECRET, 0), iput(1, 0, 4)), ())]
    user_flow = [FlowBlock(0, (
        iget(2, 0, 0),
        inv(4, *GETBYTES, (2,)),
        mr(3, 8),
        SInstruction(10, "invoke-static", (3,),
                     invoke_class="Lcom/example/Foo;", invoke_method="helper",
                     invoke_descriptor="([B)V", is_static=True),
    ), ())]
    helper_flow = [FlowBlock(0, (
        SInstruction(0, "invoke-custom", (5, 6, 7),   # unresolvable invoke
                     invoke_class=None, invoke_method=None),
        inv(10, *SECRETKEYSPEC, (4, 7, 6)),           # v7 = seeded param register
    ), ())]
    cands = detect_hardcoded_secrets(
        FakeIndex({ctor: (SECRET,)}),
        {ctor: ctor_flow, user: user_flow, helper: helper_flow},
        frame_info={helper: (8, True)})
    hit = [c for c in cands if c.value == SECRET]
    assert len(hit) == 1 and hit[0].flow_complete is False


def test_chaining_with_wide_parameters():
    """A wide (J) parameter must consume TWO register words before the byte
    array: androguard invoke lists are words. Wrong word arithmetic seeds the
    key bytes into the wide slot and the SecretKeySpec flow is missed."""
    caller = M(name="m")
    helper = MethodRef("com.example.Foo", "h", "(J[B)V")
    caller_flow = [FlowBlock(0, (
        cs(1, SECRET, 0),
        inv(4, *GETBYTES, (1,)),
        mr(2, 8),
        SInstruction(10, "const-wide", (4, 5)),
        SInstruction(12, "invoke-static", (4, 5, 2),
                     invoke_class="Lcom/example/Foo;", invoke_method="h",
                     invoke_descriptor="(J[B)V", is_static=True),
    ), ())]
    # registers_size 8, static, widths [2,1] -> params v5 (J low), v7 ([B)
    helper_flow = [FlowBlock(0, (
        inv(0, *SECRETKEYSPEC, (3, 7, 4)),
    ), ())]
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET,)}),
        {caller: caller_flow, helper: helper_flow},
        frame_info={helper: (8, True)})
    hit = [c for c in cands if c.value == SECRET]
    assert len(hit) == 1
    assert any(e.kind == "key-material-argument" for e in hit[0].evidence)


def test_staticness_disagreement_is_never_chained():
    """Call site says static, owning method's access flags say instance (or
    vice versa): the register arithmetic would be wrong, so no chaining."""
    caller = M(name="m")
    helper = MethodRef("com.example.Foo", "h", "([B)V")
    caller_flow = [FlowBlock(0, (
        cs(1, SECRET, 0),
        inv(4, *GETBYTES, (1,)),
        mr(2, 8),
        SInstruction(10, "invoke-static", (2,),
                     invoke_class="Lcom/example/Foo;", invoke_method="h",
                     invoke_descriptor="([B)V", is_static=True),
    ), ())]
    helper_flow = [FlowBlock(0, (
        inv(0, *SECRETKEYSPEC, (3, 7, 4)),           # would flag v7 if seeded
    ), ())]
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET,)}),
        {caller: caller_flow, helper: helper_flow},
        frame_info={helper: (8, False)})              # instance method: disagrees
    hit = [c for c in cands if c.value == SECRET]
    assert not hit or all("via internal call" not in e.detail for c in hit for e in c.evidence)


def test_frame_metadata_mismatch_is_never_chained():
    """A declared frame that disagrees with the call site (trailing extra
    register shifting the parameter base to v8, or a frame too small to hold
    the call's registers) must produce an honest miss, never a guessed hit."""
    caller = M(name="m")
    helper = MethodRef("com.example.Foo", "h", "([B)V")
    caller_flow = [FlowBlock(0, (
        cs(1, SECRET, 0),
        inv(4, *GETBYTES, (1,)),
        mr(2, 8),
        SInstruction(10, "invoke-static", (2,),
                     invoke_class="Lcom/example/Foo;", invoke_method="h",
                     invoke_descriptor="([B)V", is_static=True),
    ), ())]
    helper_flow = [FlowBlock(0, (
        inv(0, *SECRETKEYSPEC, (3, 7, 4)),           # reads v7 only
    ), ())]
    for bad_size in (9, 1):                          # 9: trailing slot shifts base; 1: frame too small
        cands = detect_hardcoded_secrets(
            FakeIndex({caller: (SECRET,)}),
            {caller: caller_flow, helper: helper_flow},
            frame_info={helper: (bad_size, True)})
        hit = [c for c in cands if c.value == SECRET]
        assert not hit or all("via internal call" not in e.detail for c in hit for e in c.evidence)


def test_missing_frame_metadata_is_never_chained():
    """Exact static dispatch but no owning-method register metadata: honest
    unsupported, never an inferred parameter base."""
    caller = M(name="m")
    helper = MethodRef("com.example.Foo", "h", "([B)V")
    caller_flow = [FlowBlock(0, (
        cs(1, SECRET, 0),
        inv(4, *GETBYTES, (1,)),
        mr(2, 8),
        SInstruction(10, "invoke-static", (2,),
                     invoke_class="Lcom/example/Foo;", invoke_method="h",
                     invoke_descriptor="([B)V", is_static=True),
    ), ())]
    helper_flow = [FlowBlock(0, (
        inv(0, *SECRETKEYSPEC, (3, 7, 4)),
    ), ())]
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET,)}),
        {caller: caller_flow, helper: helper_flow})  # no frame_info at all
    hit = [c for c in cands if c.value == SECRET]
    assert not hit or all("via internal call" not in e.detail for c in hit for e in c.evidence)


def test_descriptor_normalization_against_androguard_forms():
    """Real androguard MethodAnalysis.full_name renders descriptors WITH
    spaces; the invoke-adapter regex must still capture them, and chaining
    must match a spaced flow key to a compact descriptor."""
    from mobius.core.flow import _INVOKE_RE, _FIELD_RE

    # verbatim-spaced forms produced by androguard (spaces after commas and
    # around the arrow in full_name-style rendering)
    m = _INVOKE_RE.search(
        "invoke-static {v1, v0, v2}, Lcom/android/insecurebankv2/CryptoClass;"
        "->aes256decrypt([B [B [B)[B")
    assert m is not None
    assert m.group(1) == "Lcom/android/insecurebankv2/CryptoClass;"
    assert m.group(2) == "aes256decrypt"
    assert "([B[B[B)[B" == m.group(3).replace(" ", "")

    m = _INVOKE_RE.search(
        "invoke-direct {v0, v1, v2}, Ljavax/crypto/spec/SecretKeySpec;"
        "-><init>([B Ljava/lang/String;)V")
    assert m is not None and m.group(2) == "<init>"

    m = _FIELD_RE.search(
        "iput-object v0, v1, Lcom/android/insecurebankv2/CryptoClass;->key Ljava/lang/String;")
    assert m is not None
    assert m.group(1) == "Lcom/android/insecurebankv2/CryptoClass;"
    assert m.group(2) == "key"


# -- derived-key route: literal -> pure return-transform -> cross-class sink ---

CT = "dGVzdC1jaXBoZXJ0ZXh0LXZhbHVlLWZvcg=="
DECODE = ("Lcom/example/Foo;", "decode")
SINK = ("Lcom/example/Crypto;", "a")
IVSPEC = ("Ljavax/crypto/spec/IvParameterSpec;", "<init>")


def inv2(off, opcode, cls, name, desc, regs, static):
    return SInstruction(off, opcode, tuple(regs), invoke_class=cls, invoke_method=name,
                        invoke_descriptor=desc, is_static=static)


def _derived_fixture(transform_extra=(), transform_replace=None, sink_opcode="invoke-static",
                     sink_spec=SECRETKEYSPEC, sink_desc="([B[B)[B"):
    """caller: const v1=SECRET; v2=decode(v1); a(v2, v3=CT). decode: pure hex-ish
    transform over param v7. sink: SecretKeySpec.<init>(receiver, p0, 'AES')."""
    caller = M(name="check")
    decode = MethodRef("com.example.Foo", "decode", "(Ljava/lang/String;)[B")
    sink = MethodRef("com.example.Crypto", "a", sink_desc)
    caller_flow = [FlowBlock(0, (
        cs(1, SECRET, 0),
        cs(3, CT, 2),
        inv2(4, "invoke-static", *DECODE, "(Ljava/lang/String;)[B", (1,), True),
        mr(2, 6),
        inv2(8, sink_opcode, *SINK, sink_desc, (2, 3), True),
        mr(4, 10),
    ), ())]
    transform_body = (
        SInstruction(0, "invoke-virtual", (7,), invoke_class="Ljava/lang/String;",
                     invoke_method="length", invoke_descriptor="()I"),
        SInstruction(2, "move-result", (0,)),
        SInstruction(4, "const/4", (1,), const_value=0),
        SInstruction(6, "new-array", (1, 0)),
        SInstruction(8, "if-ge", (4, 0), branch_target=34),
        SInstruction(10, "invoke-virtual", (7, 4), invoke_class="Ljava/lang/String;",
                     invoke_method="charAt", invoke_descriptor="(I)C"),
        SInstruction(12, "move-result", (2,)),
        SInstruction(14, "const/16", (3,), const_value=16),
        SInstruction(16, "invoke-static", (2, 3), invoke_class="Ljava/lang/Character;",
                     invoke_method="digit", invoke_descriptor="(CI)I", is_static=True),
        SInstruction(18, "move-result", (2,)),
        SInstruction(20, "shl-int/lit8", (2, 2), const_value=4),
        SInstruction(22, "add-int/lit8", (5, 4), const_value=1),
        SInstruction(24, "invoke-virtual", (7, 5), invoke_class="Ljava/lang/String;",
                     invoke_method="charAt", invoke_descriptor="(I)C"),
        SInstruction(26, "move-result", (5,)),
        SInstruction(28, "invoke-static", (5, 3), invoke_class="Ljava/lang/Character;",
                     invoke_method="digit", invoke_descriptor="(CI)I", is_static=True),
        SInstruction(30, "move-result", (5,)),
        SInstruction(32, "add-int/2addr", (2, 5)),
        SInstruction(34, "int-to-byte", (2, 2)),
        SInstruction(36, "aput-byte", (2, 1, 4)),
        SInstruction(38, "add-int/lit8", (4, 4), const_value=2),
        SInstruction(40, "goto", (), branch_target=8),
        SInstruction(42, "return-object", (1,)),
    )
    if transform_replace is not None:
        transform_body = transform_replace
    transform_flow = [FlowBlock(0, transform_body + tuple(transform_extra), ())]
    sink_flow = [FlowBlock(0, (
        SInstruction(0, "new-instance", (0,)),
        cs(1, "AES", 2),
        inv2(4, "invoke-direct", *(("Ljavax/crypto/spec/IvParameterSpec;", "<init>")
             if sink_spec == IVSPEC else SECRETKEYSPEC),
             "([B)V" if sink_spec == IVSPEC else "([BLjava/lang/String;)V",
             (0, 2) if sink_spec == IVSPEC else (0, 2, 1), False),
        SInstruction(6, "return-object", (2,)),
    ), ())]
    return caller, decode, sink, caller_flow, transform_flow, sink_flow


def _run_derived(frame=True, dex=True, **kw):
    caller, decode, sink, cf, tf, sf = _derived_fixture(**kw)
    fi = {decode: (8, True), sink: (4, True)} if frame else None
    return detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: cf, decode: tf, sink: sf},
        frame_info=fi,
        dex_complete=dex)


def test_derived_route_key_material_evidence_cross_class():
    cands = _run_derived()
    hit = [c for c in cands if c.value == SECRET]
    assert len(hit) == 1
    kinds = [e.kind for e in hit[0].evidence]
    assert "key-material-argument-derived" in kinds
    assert hit[0].used_in_security_context is True
    assert hit[0].flow_complete is True
    attrs = gate_attributes(hit[0])
    assert attrs["used_in_security_context"] is True
    assert "format_and_entropy_ok" not in attrs        # inapplicable, left missing
    assert "inapplicable" in attrs["format_assessment"]
    result = gates.evaluate("hardcoded-secret", attrs)
    assert not result.passed
    assert result.missing_attributes == ("format_and_entropy_ok",)
    assert result.failed_decisively == ()              # manual review, never refuted


def test_derived_route_gives_ciphertext_literal_no_key_evidence():
    cands = _run_derived()
    ct = [c for c in cands if c.value == CT]
    assert not ct or all("key-material" not in e.kind for c in ct for e in c.evidence)


def test_derived_route_rejects_field_read_in_transform():
    dirty = (
        SInstruction(0, "sget", (5,), field_ref=("Lcom/example/Foo;", "f", "I")),
    )
    cands = _run_derived(transform_extra=dirty)
    hit = [c for c in cands if c.value == SECRET]
    assert not hit or all("derived" not in e.kind for c in hit for e in c.evidence)


def test_derived_route_rejects_disallowed_call_in_transform():
    dirty = (
        SInstruction(0, "invoke-static", (), invoke_class="Ljava/lang/System;",
                     invoke_method="currentTimeMillis", invoke_descriptor="()J",
                     is_static=True),
        SInstruction(2, "move-result-wide", (5,)),
    )
    cands = _run_derived(transform_extra=dirty)
    hit = [c for c in cands if c.value == SECRET]
    assert not hit or all("derived" not in e.kind for c in hit for e in c.evidence)


def test_derived_route_rejects_const_string_in_transform():
    dirty = (cs(5, "injected-constant", 0),)
    cands = _run_derived(transform_extra=dirty)
    hit = [c for c in cands if c.value == SECRET]
    assert not hit or all("derived" not in e.kind for c in hit for e in c.evidence)


def test_derived_route_rejects_virtual_sink_call():
    cands = _run_derived(sink_opcode="invoke-virtual")
    hit = [c for c in cands if c.value == SECRET]
    assert not hit or all("derived" not in e.kind for c in hit for e in c.evidence)


def test_derived_route_requires_frame_info():
    cands = _run_derived(frame=False)
    hit = [c for c in cands if c.value == SECRET]
    assert not hit or all("derived" not in e.kind for c in hit for e in c.evidence)


def test_derived_route_iv_only_use_is_not_key_evidence():
    cands = _run_derived(sink_spec=IVSPEC)
    hit = [c for c in cands if c.value == SECRET]
    assert not hit or all("key-material" not in e.kind for c in hit for e in c.evidence)


def test_derived_route_rejects_two_literal_mixing():
    caller = M(name="check")
    decode = MethodRef("com.example.Foo", "decode", "(Ljava/lang/String;Ljava/lang/String;)[B")
    sink = MethodRef("com.example.Crypto", "a", "([B[B)[B")
    caller_flow = [FlowBlock(0, (
        cs(1, SECRET, 0),
        cs(2, "another-literal-value", 2),
        cs(3, CT, 4),
        inv2(6, "invoke-static", *DECODE, "(Ljava/lang/String;Ljava/lang/String;)[B", (1, 2), True),
        mr(2, 8),
        inv2(10, "invoke-static", *SINK, "([B[B)[B", (2, 3), True),
        mr(4, 12),
    ), ())]
    _, _, _, _, tf, sf = _derived_fixture()
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: caller_flow, decode: tf, sink: sf},
        frame_info={decode: (8, True), sink: (4, True)},
        dex_complete=True)
    hit = [c for c in cands if c.value == SECRET]
    assert not hit or all("derived" not in e.kind for c in hit for e in c.evidence)


def test_derived_route_rejects_ambiguous_callee_resolution():
    caller, decode, sink, cf, tf, sf = _derived_fixture()
    dup = MethodRef("com.example.Foo", "decode", "( Ljava/lang/String; )[B")  # normalises equal
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: cf, decode: tf, dup: tf, sink: sf},
        frame_info={decode: (8, True), dup: (8, True), sink: (4, True)},
        dex_complete=True)
    hit = [c for c in cands if c.value == SECRET]
    assert not hit or all("derived" not in e.kind for c in hit for e in c.evidence)


def test_format_clause_still_decisive_without_key_evidence():
    """A value failing format/entropy WITHOUT key-role evidence still reports
    format_and_entropy_ok False (decisive): the inapplicability rule is scoped
    to role-proven key material only."""
    m = M()
    value = 'api_key: "vendorsecretkey"'   # labeled: admitted, extract fails format
    flow = [cs(1, value, 0)]
    cands = detect_hardcoded_secrets(FakeIndex({m: (value,)}), {m: [FlowBlock(0, tuple(flow), ())]})
    assert len(cands) == 1 and cands[0].value == "vendorsecretkey"
    attrs = gate_attributes(cands[0])
    assert attrs["format_and_entropy_ok"] is False
    result = gates.evaluate("hardcoded-secret", attrs)
    assert "format_and_entropy_ok" in result.failed_decisively


def test_derived_route_incomplete_sink_scan_keeps_flow_incomplete():
    caller, decode, sink, cf, tf, _ = _derived_fixture()
    broken_sink = [FlowBlock(0, (
        SInstruction(0, "new-instance", (0,)),
        cs(1, "AES", 2),
        inv2(4, "invoke-direct", *SECRETKEYSPEC, "([BLjava/lang/String;)V", (0, 2, 1), False),
        SInstruction(6, "invoke-custom", (5,), invoke_class=None, invoke_method=None),
        SInstruction(8, "return-object", (2,)),
    ), ())]
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: cf, decode: tf, sink: broken_sink},
        frame_info={decode: (8, True), sink: (4, True)},
        dex_complete=True)
    hit = [c for c in cands if c.value == SECRET]
    assert len(hit) == 1
    assert any(e.kind == "key-material-argument-derived" for e in hit[0].evidence)
    assert hit[0].flow_complete is False


def _assert_no_derived(cands, value=SECRET):
    hit = [c for c in cands if c.value == value]
    assert not hit or all("derived" not in e.kind for c in hit for e in c.evidence)


def test_derived_route_suppressed_without_ledger_metadata():
    """Default is UNKNOWN: absent (None) or incomplete (False) DEX-completeness
    metadata suppresses the derived tier entirely. The direct tier is
    untouched by the flag."""
    caller, decode, sink, cf, tf, sf = _derived_fixture()
    for dex_complete in (None, False):
        cands = detect_hardcoded_secrets(
            FakeIndex({caller: (SECRET, CT)}),
            {caller: cf, decode: tf, sink: sf},
            frame_info={decode: (8, True), sink: (4, True)},
            dex_complete=dex_complete)
        _assert_no_derived(cands)
    # control: same fixture with a verified-complete ledger yields the evidence
    assert any("derived" in e.kind for c in _run_derived() for e in c.evidence)


# --- Return-dependence counterexamples: reading the parameter is not proof ---
# Each body below READS the literal-carrying parameter register v7 (the old
# read-check accepted them) yet its return value does NOT depend on the
# parameter's content. The bounded content-dependence fixpoint must reject all.

def test_derived_route_rejects_const_filled_array_sized_by_param():
    """Array contents are constants; only the SIZE depends on the parameter.
    A tainted size must not taint the contents."""
    body = (
        SInstruction(0, "invoke-virtual", (7,), invoke_class="Ljava/lang/String;",
                     invoke_method="length", invoke_descriptor="()I"),
        SInstruction(2, "move-result", (0,)),
        SInstruction(4, "const/4", (1,), const_value=0),
        SInstruction(6, "new-array", (1, 0)),          # tainted size, fresh contents
        SInstruction(8, "const/4", (2,), const_value=65),
        SInstruction(10, "const/4", (3,), const_value=0),
        SInstruction(12, "aput-byte", (2, 1, 3)),       # untainted value stored
        SInstruction(14, "return-object", (1,)),
    )
    _assert_no_derived(_run_derived(transform_replace=body))


def test_derived_route_rejects_branch_only_param_read():
    """The parameter feeds only a branch condition; the returned array is
    constant-filled. A branch read is not content dependence."""
    body = (
        SInstruction(0, "if-eqz", (7,), branch_target=12),
        SInstruction(2, "const/4", (0,), const_value=4),
        SInstruction(4, "new-array", (1, 0)),
        SInstruction(6, "const/4", (2,), const_value=65),
        SInstruction(8, "aput-byte", (2, 1, 0)),
        SInstruction(10, "return-object", (1,)),
    )
    _assert_no_derived(_run_derived(transform_replace=body))


def test_derived_route_rejects_overwritten_param_register():
    """The parameter register is overwritten before any use; everything
    downstream is constant. Overwrite kills provenance."""
    body = (
        SInstruction(0, "const/4", (7,), const_value=0),   # kill v7
        SInstruction(2, "move", (0, 7)),
        SInstruction(4, "new-array", (1, 0)),
        SInstruction(6, "const/4", (2,), const_value=65),
        SInstruction(8, "aput-byte", (2, 1, 0)),
        SInstruction(10, "return-object", (1,)),
    )
    _assert_no_derived(_run_derived(transform_replace=body))


# --- Route-shape controls ---

def test_derived_route_rejects_chained_second_transform():
    """caller: decode(lit) -> decode2(result) -> sink. The producer decode2 is
    fed a prior call RESULT, not a literal: one transform hop only."""
    caller, decode, sink, _, tf, sf = _derived_fixture()
    decode2 = MethodRef("com.example.Foo", "decode2", "([B)[B")
    caller_flow = [FlowBlock(0, (
        cs(1, SECRET, 0),
        cs(3, CT, 2),
        inv2(4, "invoke-static", *DECODE, "(Ljava/lang/String;)[B", (1,), True),
        mr(2, 6),
        inv2(8, "invoke-static", "Lcom/example/Foo;", "decode2", "([B)[B", (2,), True),
        mr(5, 10),
        inv2(12, "invoke-static", *SINK, "([B[B)[B", (5, 3), True),
        mr(4, 14),
    ), ())]
    decode2_flow = [FlowBlock(0, (
        SInstruction(0, "array-length", (0, 3)),
        SInstruction(2, "new-array", (1, 0)),
        SInstruction(4, "aget-byte", (2, 3, 0)),
        SInstruction(6, "aput-byte", (2, 1, 0)),
        SInstruction(8, "return-object", (1,)),
    ), ())]
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: caller_flow, decode: tf, decode2: decode2_flow, sink: sf},
        frame_info={decode: (8, True), decode2: (4, True), sink: (4, True)},
        dex_complete=True)
    _assert_no_derived(cands)


def test_derived_route_rejects_external_mixing_at_call_site():
    """The transform is called with (literal, external input): the literal is
    not the sole value entering it."""
    caller, decode, sink, _, tf, sf = _derived_fixture()
    caller_flow = [FlowBlock(0, (
        cs(1, SECRET, 0),
        cs(3, CT, 2),
        inv(6, *EXT, (4,)),
        mr(5, 8),
        inv2(10, "invoke-static", *DECODE,
             "(Ljava/lang/String;Ljava/lang/String;)[B", (1, 5), True),
        mr(2, 12),
        inv2(14, "invoke-static", *SINK, "([B[B)[B", (2, 3), True),
        mr(4, 16),
    ), ())]
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: caller_flow, decode: tf, sink: sf},
        frame_info={decode: (8, True), sink: (4, True)},
        dex_complete=True)
    _assert_no_derived(cands)


def test_derived_route_reaching_non_key_sink_is_not_key_evidence():
    """Derived material reaching MessageDigest.digest (not a key-material
    sink) yields no key evidence and no security-context use."""
    caller, decode, sink, _, tf, _ = _derived_fixture()
    digest = MethodRef("java.security.MessageDigest", "digest", "([B)[B")
    caller_flow = [FlowBlock(0, (
        cs(1, SECRET, 0),
        inv2(4, "invoke-static", *DECODE, "(Ljava/lang/String;)[B", (1,), True),
        mr(2, 6),
        inv2(8, "invoke-static", "Ljava/security/MessageDigest;", "digest",
             "([B)[B", (2,), True),
        mr(4, 10),
    ), ())]
    digest_flow = [FlowBlock(0, (SInstruction(0, "return-object", (3,)),), ())]
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET,)}),
        {caller: caller_flow, decode: tf, digest: digest_flow},
        frame_info={decode: (8, True), digest: (4, True)},
        dex_complete=True)
    hit = [c for c in cands if c.value == SECRET]
    assert not hit or all("key-material" not in e.kind for c in hit for e in c.evidence)
    assert not hit or all(c.used_in_security_context is not True for c in hit)


def test_derived_route_direct_cross_class_literal_gets_no_derived_evidence():
    """A literal passed DIRECTLY to a cross-class sink (no transform) stays
    unauthorized: the derived route is the only cross-class path and it
    requires the transform hop."""
    caller, decode, sink, _, tf, sf = _derived_fixture()
    caller_flow = [FlowBlock(0, (
        cs(1, SECRET, 0),
        cs(3, CT, 2),
        inv2(4, "invoke-static", *SINK, "([B[B)[B", (1, 3), True),
        mr(4, 6),
    ), ())]
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: caller_flow, decode: tf, sink: sf},
        frame_info={decode: (8, True), sink: (4, True)},
        dex_complete=True)
    hit = [c for c in cands if c.value == SECRET]
    assert not hit or all("key-material" not in e.kind for c in hit for e in c.evidence)


def test_derived_route_branch_union_external_and_transform_suppressed():
    """Two branches merge: one feeds the sink argument from external input,
    the other from the transform. The unioned origins are not exactly one
    call-result origin, so the position is suppressed."""
    caller, decode, sink, _, tf, sf = _derived_fixture()
    caller_flow = [
        FlowBlock(0, (
            cs(1, SECRET, 0),
            cs(3, CT, 2),
            ifz(4, 4),
        ), (10, 20)),
        FlowBlock(10, (
            inv(10, *EXT, (4,)),
            mr(2, 12),
        ), (30,)),
        FlowBlock(20, (
            inv2(20, "invoke-static", *DECODE, "(Ljava/lang/String;)[B", (1,), True),
            mr(2, 22),
        ), (30,)),
        FlowBlock(30, (
            inv2(30, "invoke-static", *SINK, "([B[B)[B", (2, 3), True),
            mr(4, 32),
        ), ()),
    ]
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: caller_flow, decode: tf, sink: sf},
        frame_info={decode: (8, True), sink: (4, True)},
        dex_complete=True)
    _assert_no_derived(cands)


def test_derived_route_rejects_staticness_mismatch_frame():
    """Frame metadata says the producer is an instance method while the call
    site is invoke-static: never guess."""
    caller, decode, sink, cf, tf, sf = _derived_fixture()
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: cf, decode: tf, sink: sf},
        frame_info={decode: (8, False), sink: (4, True)},
        dex_complete=True)
    _assert_no_derived(cands)


def test_derived_route_rejects_param_metadata_mismatch():
    """registers_size 0 admits no parameter register: metadata mismatch
    suppresses the route."""
    caller, decode, sink, cf, tf, sf = _derived_fixture()
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: cf, decode: tf, sink: sf},
        frame_info={decode: (0, True), sink: (4, True)},
        dex_complete=True)
    _assert_no_derived(cands)


def test_derived_route_hex_vector_and_short_key_stay_manual_review():
    """A hex test-vector literal and a short sequential key with proven
    derived key-role evidence surface as manual-review candidates: role
    evidence never auto-confirms and shape never refutes."""
    for lit in ("000102030405060708090a0b0c0d0e0f", "1234567890123456"):
        caller, decode, sink, _, tf, sf = _derived_fixture()
        cf = [FlowBlock(0, (
            cs(1, lit, 0),
            cs(3, CT, 2),
            inv2(4, "invoke-static", *DECODE, "(Ljava/lang/String;)[B", (1,), True),
            mr(2, 6),
            inv2(8, "invoke-static", *SINK, "([B[B)[B", (2, 3), True),
            mr(4, 10),
        ), ())]
        cands = detect_hardcoded_secrets(
            FakeIndex({caller: (lit, CT)}),
            {caller: cf, decode: tf, sink: sf},
            frame_info={decode: (8, True), sink: (4, True)},
            dex_complete=True)
        hit = [c for c in cands if c.value == lit]
        assert len(hit) == 1, (lit, cands)
        assert any(e.kind == "key-material-argument-derived" for e in hit[0].evidence)
        attrs = gate_attributes(hit[0])
        result = gates.evaluate("hardcoded-secret", attrs)
        assert not result.passed                  # never auto-confirmed
        assert result.failed_decisively == ()     # never refuted on shape


def test_derived_route_suppressed_by_adapter_duplicate_class_ledger():
    """End-to-end through the REAL adapter path: the same dex fixture packed
    as classes.dex + classes2.dex makes the coverage ledger ambiguous
    (first-wins duplicate classes), dex_ledger_complete is False, and the
    derived tier is suppressed. A clean single-dex package keeps it active."""
    from io import BytesIO
    from pathlib import Path
    import zipfile
    from mobius.adapters.flow_adapt import adapt_code
    from mobius.adapters.provider_payload import dex_ledger_complete

    raw = (Path(__file__).parent / "fixtures" / "dex" / "AnalysisTest.dex").read_bytes()

    def ledger_for(names):
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for name in names:
                z.writestr(name, raw)
        return adapt_code(buf.getvalue())[-1]

    clean = dex_ledger_complete(ledger_for(["classes.dex"]))
    dup_ledger = ledger_for(["classes.dex", "classes2.dex"])
    dup = dex_ledger_complete(dup_ledger)
    assert clean is True
    assert dup is False
    assert any(b.ambiguous or b.duplicates for b in dup_ledger)

    caller, decode, sink, cf, tf, sf = _derived_fixture()

    def has_derived(ledger_complete):
        cands = detect_hardcoded_secrets(
            FakeIndex({caller: (SECRET, CT)}),
            {caller: cf, decode: tf, sink: sf},
            frame_info={decode: (8, True), sink: (4, True)},
            dex_complete=ledger_complete)
        return any("derived" in e.kind for c in cands for e in c.evidence)

    assert has_derived(clean) is True
    assert has_derived(dup) is False


FORMAT_OK_LITERAL = "kX9mZ2vB8qW4nR6pL0sT3yU7aC5dF1"   # passes format_and_entropy_ok


def _derived_fixture_with_literal(lit):
    """The standard derived fixture with the caller's literal swapped."""
    caller, decode, sink, _, tf, sf = _derived_fixture()
    cf = [FlowBlock(0, (
        cs(1, lit, 0),
        cs(3, CT, 2),
        inv2(4, "invoke-static", *DECODE, "(Ljava/lang/String;)[B", (1,), True),
        mr(2, 6),
        inv2(8, "invoke-static", *SINK, "([B[B)[B", (2, 3), True),
        mr(4, 10),
    ), ())]
    return caller, decode, sink, cf, tf, sf


def test_derived_only_evidence_never_confirms_even_when_format_passes():
    """BLOCKER A: a derived literal whose own string PASSES the format screen
    must still leave the format clause missing - shape can never upgrade
    may-depend evidence - and the whole gate can never pass."""
    caller, decode, sink, cf, tf, sf = _derived_fixture_with_literal(FORMAT_OK_LITERAL)
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (FORMAT_OK_LITERAL, CT)}),
        {caller: cf, decode: tf, sink: sf},
        frame_info={decode: (8, True), sink: (4, True)},
        dex_complete=True)
    hit = [c for c in cands if c.value == FORMAT_OK_LITERAL]
    assert len(hit) == 1
    assert any(e.kind == "key-material-argument-derived" for e in hit[0].evidence)
    assert not any(e.kind == "key-material-argument" for e in hit[0].evidence)
    attrs = gate_attributes(hit[0])
    assert "format_and_entropy_ok" not in attrs      # missing even though ok=True
    assert "inapplicable" in attrs["format_assessment"]
    assert attrs["security_use_basis"] == "may-depend-derived-route-only"
    result = gates.evaluate("hardcoded-secret", attrs)
    assert not result.passed
    assert result.failed_decisively == ()


def test_direct_evidence_with_format_passing_literal_keeps_reviewed_behavior():
    """The format-passing + format-set behavior is preserved for INDEPENDENT
    direct key-role evidence (same-method literal -> getBytes -> SecretKeySpec):
    only derived-only evidence is forced inapplicable."""
    m = M()
    flow = [
        cs(1, FORMAT_OK_LITERAL, 0),
        inv(4, *GETBYTES, (1,)),
        mr(2, 8),
        inv(10, *SECRETKEYSPEC, (3, 2, 4)),
    ]
    cands = detect_hardcoded_secrets(FakeIndex({m: (FORMAT_OK_LITERAL,)}),
                                     {m: [FlowBlock(0, tuple(flow), ())]},
                                     dex_complete=True)
    assert len(cands) == 1
    attrs = gate_attributes(cands[0])
    assert attrs["format_and_entropy_ok"] is True    # direct behavior unchanged
    assert attrs["security_use_basis"] == "direct-key-material-evidence"


def test_derived_route_union_return_is_may_depend_candidate_only():
    """B1: one branch returns the param-derived array, the other a
    constant-filled array; the union taints the return. The candidate is
    reported as MAY-depend evidence and can never pass the gate."""
    caller, decode, sink, cf, _, sf = _derived_fixture()
    tf = [
        FlowBlock(0, (
            SInstruction(0, "if-eqz", (6,), branch_target=20),
            SInstruction(2, "const/4", (0,), const_value=4),
            SInstruction(4, "new-array", (1, 0)),
            SInstruction(6, "invoke-virtual", (7,), invoke_class="Ljava/lang/String;",
                         invoke_method="charAt", invoke_descriptor="(I)C"),
            SInstruction(8, "move-result", (2,)),
            SInstruction(10, "aput-byte", (2, 1, 0)),
            SInstruction(12, "goto", (), branch_target=30),
        ), (20, 30)),
        FlowBlock(20, (
            SInstruction(20, "const/4", (0,), const_value=4),
            SInstruction(22, "new-array", (1, 0)),
            SInstruction(24, "const/4", (2,), const_value=65),
            SInstruction(26, "aput-byte", (2, 1, 0)),
        ), (30,)),
        FlowBlock(30, (
            SInstruction(30, "return-object", (1,)),
        ), ()),
    ]
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: cf, decode: tf, sink: sf},
        frame_info={decode: (8, True), sink: (4, True)},
        dex_complete=True)
    hit = [c for c in cands if c.value == SECRET]
    assert len(hit) == 1
    derived = [e for e in hit[0].evidence if e.kind == "key-material-argument-derived"]
    assert derived and "MAY depend" in derived[0].detail
    result = gates.evaluate("hardcoded-secret", gate_attributes(hit[0]))
    assert not result.passed


def test_derived_route_length_only_dependence_is_not_content_provenance():
    """B2: arr[i] = param.length(); return arr - the key depends only on the
    literal's LENGTH, not its content. Suppressed."""
    caller, decode, sink, cf, _, sf = _derived_fixture()
    body = (
        SInstruction(0, "invoke-virtual", (7,), invoke_class="Ljava/lang/String;",
                     invoke_method="length", invoke_descriptor="()I"),
        SInstruction(2, "move-result", (0,)),
        SInstruction(4, "const/4", (1,), const_value=4),
        SInstruction(6, "new-array", (1, 2)),
        SInstruction(8, "aput-byte", (0, 1, 2)),     # stores the LENGTH as content
        SInstruction(10, "return-object", (1,)),
    )
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: cf, decode: [FlowBlock(0, body, ())], sink: sf},
        frame_info={decode: (8, True), sink: (4, True)},
        dex_complete=True)
    _assert_no_derived(cands)


def test_derived_route_full_array_overwrite_stays_may_depend_candidate_only():
    """B3: param content is stored, then every element is overwritten with a
    constant. Weak updates keep the array tainted: reported as MAY-depend
    evidence, never gate-passing (over-approximation stated, not hidden)."""
    caller, decode, sink, cf, _, sf = _derived_fixture()
    body = (
        SInstruction(0, "const/4", (0,), const_value=1),
        SInstruction(2, "new-array", (1, 0)),
        SInstruction(4, "invoke-virtual", (7,), invoke_class="Ljava/lang/String;",
                     invoke_method="charAt", invoke_descriptor="(I)C"),
        SInstruction(6, "move-result", (2,)),
        SInstruction(8, "aput-byte", (2, 1, 0)),
        SInstruction(10, "const/4", (2,), const_value=65),
        SInstruction(12, "aput-byte", (2, 1, 0)),    # full overwrite with constant
        SInstruction(14, "return-object", (1,)),
    )
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: cf, decode: [FlowBlock(0, body, ())], sink: sf},
        frame_info={decode: (8, True), sink: (4, True)},
        dex_complete=True)
    hit = [c for c in cands if c.value == SECRET]
    assert len(hit) == 1
    derived = [e for e in hit[0].evidence if e.kind == "key-material-argument-derived"]
    assert derived and "MAY depend" in derived[0].detail
    result = gates.evaluate("hardcoded-secret", gate_attributes(hit[0]))
    assert not result.passed


def test_derived_route_invalid_output_length_is_candidate_only():
    """D: a transform emitting a 3-byte array (invalid AES key length) is
    still reported - output bytes are unmodelled - but stays a may-depend
    candidate and never passes the gate."""
    caller, decode, sink, cf, _, sf = _derived_fixture()
    body = (
        SInstruction(0, "const/4", (0,), const_value=3),
        SInstruction(2, "new-array", (1, 0)),
        SInstruction(4, "invoke-virtual", (7,), invoke_class="Ljava/lang/String;",
                     invoke_method="charAt", invoke_descriptor="(I)C"),
        SInstruction(6, "move-result", (2,)),
        SInstruction(8, "aput-byte", (2, 1, 0)),
        SInstruction(10, "return-object", (1,)),
    )
    cands = detect_hardcoded_secrets(
        FakeIndex({caller: (SECRET, CT)}),
        {caller: cf, decode: [FlowBlock(0, body, ())], sink: sf},
        frame_info={decode: (8, True), sink: (4, True)},
        dex_complete=True)
    hit = [c for c in cands if c.value == SECRET]
    assert len(hit) == 1
    derived = [e for e in hit[0].evidence if e.kind == "key-material-argument-derived"]
    assert derived and "MAY depend" in derived[0].detail
    result = gates.evaluate("hardcoded-secret", gate_attributes(hit[0]))
    assert not result.passed
