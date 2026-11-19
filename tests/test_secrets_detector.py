"""Adversarial tests for the secrets prototype: evidence must come from actual
register-level flow with correct kill/join semantics, never from co-occurrence,
method names, or format alone."""
from __future__ import annotations

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


def test_format_and_entropy_genuine_not_forced_true():
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
    assert attrs["format_and_entropy_ok"] is False     # gate decides what this means


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
