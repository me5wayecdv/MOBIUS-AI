"""Provider exposure detector: per-operation evidence, guard enforcement
analysis (enforcing / ignored / non-dominating), coverage honesty, and the
protection chain from the verified manifest model."""
from __future__ import annotations

from mobius.core.manifest import (
    Component,
    DeclaredPermission,
    ExportSource,
    ManifestSurface,
    PathPermission,
)
from mobius.core.providers import (
    detect_provider_exposures,
    parameter_registers,
    uri_matcher_patterns,
)
from mobius.core.reachability import MethodRef
from mobius.core.flow import FlowBlock, SInstruction


def surface(*components: Component) -> ManifestSurface:
    return ManifestSurface(package_name="com.example", components=tuple(components))


def provider(name, exported=True, permission=None, **kw):
    return Component(kind="provider", name=name, exported=exported,
                     export_source=ExportSource.DECLARED, permission=permission, **kw)


def cs(reg, value, off):
    return SInstruction(off, "const-string", (reg,), literal=value)


def inv(off, cls, name, regs, descriptor=None, opcode="invoke-virtual"):
    return SInstruction(off, opcode, tuple(regs), invoke_class=cls,
                        invoke_method=name, invoke_descriptor=descriptor)


QUERY_REF = MethodRef("com.example.NotesProvider", "query",
                      "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;"
                      "Ljava/lang/String;)Landroid/database/Cursor;")
DELETE_REF = MethodRef("com.example.NotesProvider", "delete",
                       "(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I")
QBUILDER_QUERY = ("Landroid/database/sqlite/SQLiteQueryBuilder;", "query",
                  "(Landroid/database/sqlite/SQLiteDatabase;[Ljava/lang/String;Ljava/lang/String;"
                  "[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)"
                  "Landroid/database/Cursor;")
CHECK_PERM = ("Landroid/content/Context;", "checkCallingPermission",
              "(Ljava/lang/String;)I")
ENFORCE_PERM = ("Landroid/content/Context;", "enforceCallingPermission",
                "(Ljava/lang/String;)V")


def query_flow_block(with_enforce_guard=False, with_ignored_check=False):
    """One block: [guard] setTables, QueryBuilder.query with selection (v11) at
    the whereClause argument position."""
    ins = []
    if with_enforce_guard:
        ins.append(inv(0, ENFORCE_PERM[0], ENFORCE_PERM[1], (2, 3), ENFORCE_PERM[2]))
        ins.append(inv(2, "Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", (0, 1)))
    elif with_ignored_check:
        ins.append(inv(0, CHECK_PERM[0], CHECK_PERM[1], (2, 3), CHECK_PERM[2]))
        ins.append(SInstruction(2, "move-result", (3,)))  # result never consumed
        ins.append(inv(4, "Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", (0, 1)))
        ins.append(inv(6, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
                       QBUILDER_QUERY[2]))
        return (FlowBlock(0, tuple(ins), ()),)
    else:
        ins.append(inv(0, "Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", (0, 1)))
    ins.append(inv(4 if not with_enforce_guard else 4, QBUILDER_QUERY[0], QBUILDER_QUERY[1],
                   (0, 4, 5, 11, 6, 7, 8), QBUILDER_QUERY[2]))
    return (FlowBlock(0, tuple(ins), ()),)


def delete_flow_block():
    ins = (
        inv(0, "Landroid/database/sqlite/SQLiteDatabase;", "delete", (0, 1, 9),
            "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I"),
    )
    return (FlowBlock(0, ins, ()),)


def op(exposure, operation):
    return next(o for o in exposure.operations if o.operation == operation)


def test_caller_controlled_selection_reaches_whereclause():
    exposures = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: query_flow_block()},
        {QUERY_REF: 14},
    )
    assert len(exposures) == 1
    e = exposures[0]
    read = op(e, "read")
    assert read.caller_check_absent is True
    assert read.sink_flows, "param->whereClause flow must be evidenced"
    attrs = read.gate_attributes()
    assert attrs["protection_status"] == "unprotected"
    assert attrs["caller_check_absent"] is True
    assert attrs["sink_reachable"] is True
    assert e.exported is True


def test_range_invoke_carries_sink_flow():
    # invoke-*/range operands are expanded registers like any other invoke;
    # the engine must not discard them or mark the scan incomplete.
    blocks = (FlowBlock(0, (
        inv(0, QBUILDER_QUERY[0], "setTables", (0, 1)),
        inv(2, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2], opcode="invoke-virtual/range"),
    ), ()),)
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: blocks},
        {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert read.flow_complete is True
    assert read.sink_flows, "range invoke sink flow must be evidenced"


def test_read_protected_write_open_split():
    # Same flowing provider: readPermission set, nothing else. Read is
    # protected (own-declared signature); write falls through the whole chain
    # to UNPROTECTED, and its sink flow is still recorded as evidence.
    e = detect_provider_exposures(
        ManifestSurface(
            package_name="com.example",
            declared_permissions=(DeclaredPermission("com.example.READ", "signature"),),
            components=(provider("com.example.NotesProvider",
                                 read_permission="com.example.READ"),)),
        {QUERY_REF: query_flow_block(), DELETE_REF: delete_flow_block()},
        {QUERY_REF: 14, DELETE_REF: 11},
    )[0]
    read, write = op(e, "read"), op(e, "write")
    assert read.protection_status == "protected"
    assert read.protection_permission == "com.example.READ"
    assert write.protection_status == "unprotected"
    assert write.sink_flows, "write flow evidence still recorded; protection is the split"


def test_non_exported_variant_records_flows_but_not_exported():
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider", exported=False)),
        {QUERY_REF: query_flow_block()}, {QUERY_REF: 14},
    )[0]
    assert e.exported is False
    assert e.gate_attributes()["exported"] is False
    assert op(e, "read").sink_flows, "flow evidence still recorded; non-export is the refutation"


def test_enforcing_void_guard_refutes_absence():
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: query_flow_block(with_enforce_guard=True)}, {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert read.caller_check_absent is False
    assert read.guard_findings[0].outcome == "enforcing"
    assert read.gate_attributes()["caller_check_absent"] is False


def test_ignored_guard_return_does_not_refute():
    # checkCallingPermission whose int result is never consumed cannot deny
    # anything: recorded as ignored, absence of an enforcing check still True.
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: query_flow_block(with_ignored_check=True)}, {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert read.guard_findings[0].outcome == "ignored"
    assert read.caller_check_absent is True


def test_decisive_check_guard_refutes_absence():
    # check guard whose result gates the only path to the sink: enforcing.
    check_block = FlowBlock(0, (
        inv(0, CHECK_PERM[0], CHECK_PERM[1], (2, 3), CHECK_PERM[2]),
        SInstruction(2, "move-result", (3,)),
        SInstruction(4, "if-eqz", (3,), branch_target=10),
    ), (10, 20))
    sink_block = FlowBlock(10, (
        inv(10, "Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", (0, 1)),
        inv(14, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2]),
    ), ())
    denial_block = FlowBlock(20, (SInstruction(20, "throw", (1,)),), ())
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: (check_block, sink_block, denial_block)}, {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert read.guard_findings[0].outcome == "enforcing"
    assert read.caller_check_absent is False


def test_checked_but_not_dominating_guard_stays_unknown_free():
    # The check gates a branch, but the sink is reachable before/around it:
    # not enforcing; with complete coverage the enforcing-absence is True and
    # the weak guard is on record.
    sink_block = FlowBlock(0, (
        inv(0, "Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", (0, 1)),
        inv(4, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2]),
    ), (10,))
    check_block = FlowBlock(10, (
        inv(10, CHECK_PERM[0], CHECK_PERM[1], (2, 3), CHECK_PERM[2]),
        SInstruction(12, "move-result", (3,)),
        SInstruction(14, "if-eqz", (3,), branch_target=20),
    ), (20, 30))
    FlowBlock(20, (), ())
    tail_a = FlowBlock(20, (SInstruction(20, "return-void", ()),), ())
    tail_b = FlowBlock(30, (SInstruction(30, "return-void", ()),), ())
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: (sink_block, check_block, tail_a, tail_b)}, {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert read.guard_findings[0].outcome == "checked-not-dominating"
    assert read.caller_check_absent is True


def test_helper_guard_keeps_absence_unknown():
    # Guard lives in a same-class helper: coverage counts it, but dominance
    # across the call boundary is not proven -> unknown, never refuted/safe.
    helper_ref = MethodRef("com.example.NotesProvider", "guardHelper", "()V")
    helper = (FlowBlock(0, (
        inv(0, ENFORCE_PERM[0], ENFORCE_PERM[1], (2, 3), ENFORCE_PERM[2]),
    ), ()),)
    query = (FlowBlock(0, (
        inv(0, "Lcom/example/NotesProvider;", "guardHelper", (0,), "()V"),
        inv(2, "Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", (0, 1)),
        inv(4, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2]),
    ), ()),)
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: query, helper_ref: helper}, {QUERY_REF: 14, helper_ref: 4},
    )[0]
    read = op(e, "read")
    assert read.coverage_complete is True
    assert read.guard_findings[0].outcome == "helper-unresolved"
    assert read.caller_check_absent is None


def test_unadapted_call_keeps_absence_unknown():
    query = (FlowBlock(0, (
        inv(0, "Lcom/example/NotesProvider;", "mystery", (0,), "()V"),
        inv(2, "Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", (0, 1)),
        inv(4, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2]),
    ), ()),)
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: query}, {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert read.coverage_complete is False
    assert read.caller_check_absent is None
    assert "caller_check_absent" not in read.gate_attributes()


def test_missing_methods_claim_nothing():
    e = detect_provider_exposures(
        surface(provider("com.example.GhostProvider")), {}, {},
    )[0]
    for operation in e.operations:
        assert operation.flow_complete is False
        assert operation.caller_check_absent is None
        assert "caller_check_absent" not in operation.gate_attributes()
        assert "sink_reachable" not in operation.gate_attributes()


def test_unlisted_descriptor_yields_no_position_claim():
    # an overload the table does not know: no whereClause evidence guessed
    odd = (FlowBlock(0, (
        inv(0, "Landroid/database/sqlite/SQLiteDatabase;", "query", (0, 1, 2, 11),
            "(Landroid/database/CursorFactory;...)Landroid/database/Cursor;"),
    ), ()),)
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: odd}, {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert not read.sink_flows
    assert "sink_reachable" not in read.gate_attributes()


def test_path_permission_protects_discovered_literal_path():
    clinit_ref = MethodRef("com.example.NotesProvider", "<clinit>", "()V")
    clinit = (FlowBlock(0, (
        cs(1, "com.example.provider", 0),
        cs(2, "notes", 4),
        inv(8, "Landroid/content/UriMatcher;", "addURI", (0, 1, 2, 3)),
    ), ()),)
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider",
                         path_permissions=(
                             PathPermission("/notes", "literal",
                                            read_permission="com.example.LOCKED"),
                         ))),
        {QUERY_REF: query_flow_block(), clinit_ref: clinit},
        {QUERY_REF: 14},
    )[0]
    read, write = op(e, "read"), op(e, "write")
    assert e.uri_patterns == ("notes",)
    # the discovered literal path IS protected, but other instances/paths are
    # unverified -> the operation verdict stays unknown, never safe
    assert read.protection_status == "unknown"
    # write side of the path-permission has no permission: skipped -> open
    assert write.protection_status == "unprotected"


def test_parameter_registers_skips_this_and_wide_types():
    # instance method, (int, long, String): this=v9, p1=v10, p2=v11-12, p3=v13
    regs = parameter_registers("(IJLjava/lang/String;)V", 14, is_static=False)
    assert regs == (10, 11, 13)
    assert parameter_registers("(I)V", 2, is_static=True) == (1,)


def test_uri_matcher_numeric_bound_extracted():
    clinit = (FlowBlock(0, (
        cs(1, "com.example.provider", 0),
        cs(2, "notes", 4),
        inv(8, "Landroid/content/UriMatcher;", "addURI", (0, 1, 2, 3)),
        cs(2, "notes/#", 12),
        inv(16, "Landroid/content/UriMatcher;", "addURI", (0, 1, 2, 3)),
    ), ()),)
    patterns, numeric = uri_matcher_patterns(clinit)
    assert patterns == ("notes",)
    assert numeric == ("notes/#",)


def test_polarity_inverted_check_stays_unknown():
    # if-eqz branches to the SINK on PERMISSION_GRANTED... but here the branch
    # target is the denial block and the sink is on the denied path: the
    # check grants nothing, so absence must stay unknown, never refuted.
    check_block = FlowBlock(0, (
        inv(0, CHECK_PERM[0], CHECK_PERM[1], (2, 3), CHECK_PERM[2]),
        SInstruction(2, "move-result", (3,)),
        SInstruction(4, "if-eqz", (3,), branch_target=20),  # granted -> denial!
    ), (10, 20))
    sink_block = FlowBlock(10, (
        inv(10, "Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", (0, 1)),
        inv(14, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2]),
    ), ())
    denial_block = FlowBlock(20, (SInstruction(20, "throw", (1,)),), ())
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: (check_block, sink_block, denial_block)}, {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert read.guard_findings[0].outcome == "polarity-inverted"
    assert read.caller_check_absent is True  # check cannot deny the sink path


def test_check_against_nonzero_constant_stays_unknown():
    # comparing the checkPermission result against 1 has no
    # PERMISSION_GRANTED == 0 polarity reading.
    check_block = FlowBlock(0, (
        inv(0, CHECK_PERM[0], CHECK_PERM[1], (2, 3), CHECK_PERM[2]),
        SInstruction(2, "move-result", (3,)),
        SInstruction(4, "const/4", (4,), const_value=1),
        SInstruction(6, "if-eq", (3, 4), branch_target=10),
    ), (10, 20))
    sink_block = FlowBlock(10, (
        inv(10, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2]),
    ), ())
    denial_block = FlowBlock(20, (SInstruction(20, "throw", (1,)),), ())
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: (check_block, sink_block, denial_block)}, {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert read.guard_findings[0].outcome == "unknown-polarity"
    assert read.caller_check_absent is None  # unresolvable -> unknown


def test_enforce_guard_inside_try_is_catch_unknown():
    # enforcePermission throws, but the call sits inside a try region whose
    # handler may swallow the SecurityException before the sink.
    check_block = FlowBlock(0, (
        inv(0, ENFORCE_PERM[0], ENFORCE_PERM[1], (2, 3), ENFORCE_PERM[2]),
    ), (10,))
    sink_block = FlowBlock(10, (
        inv(10, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2]),
    ), ())
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: (check_block, sink_block)}, {QUERY_REF: 14},
        try_regions={QUERY_REF: ((0, 16),)},
    )[0]
    read = op(e, "read")
    assert read.guard_findings[0].outcome == "catch-unknown"
    assert read.caller_check_absent is None


def test_androidx_helper_callee_is_not_auto_harmless():
    # androidx/kotlin/gms helpers are bundled app code, not platform code:
    # without flow blocks for the callee the caller's coverage is incomplete.
    q = FlowBlock(0, (
        inv(0, "Landroidx/core/content/PermissionChecker;",
            "checkSelfPermission", (1, 2)),
        inv(4, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2]),
    ), ())
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: (q,)}, {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert read.coverage_complete is False
    assert read.caller_check_absent is None


def test_numeric_pattern_without_path_permission_stays_open_or_unknown():
    # '/notes/#' synthesized as '/notes/0': no path-permission at all -> the
    # provider chain decides every path uniformly -> still unprotected.
    clinit = FlowBlock(0, (
        cs(1, "com.example.provider", 0),
        cs(2, "notes", 4),
        inv(8, "Landroid/content/UriMatcher;", "addURI", (0, 1, 2, 3)),
        cs(2, "notes/#", 12),
        inv(16, "Landroid/content/UriMatcher;", "addURI", (0, 1, 2, 3)),
    ), ())
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: query_flow_block(),
         MethodRef("com.example.NotesProvider", "<clinit>", "()V"): (clinit,)},
        {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert read.protection_status == "unprotected"


def test_mixed_path_protection_stays_unknown():
    # One literal pattern protected by a path-permission, another not: without
    # a mapping from UriMatcher branch to sink flow, the open path must NOT
    # confirm an operation-level exposure.
    clinit = FlowBlock(0, (
        cs(1, "com.example.provider", 0),
        cs(2, "notes", 4),
        inv(8, "Landroid/content/UriMatcher;", "addURI", (0, 1, 2, 3)),
        cs(2, "admin", 12),
        inv(16, "Landroid/content/UriMatcher;", "addURI", (0, 1, 2, 3)),
    ), ())
    surface_ = surface(provider("com.example.NotesProvider",
                                path_permissions=(
                                    PathPermission("/admin", "literal",
                                                   read_permission="com.example.LOCKED"),
                                )))
    e = detect_provider_exposures(
        surface_,
        {QUERY_REF: query_flow_block(),
         MethodRef("com.example.NotesProvider", "<clinit>", "()V"): (clinit,)},
        {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert read.protection_status == "unknown"
    assert "branch mapping" in read.protection_basis


def test_all_open_paths_with_unrelated_path_permission_stay_open():
    # A path-permission that matches nothing discovered leaves every
    # representative open: whichever branch carries the sink flow is open.
    clinit = FlowBlock(0, (
        cs(1, "com.example.provider", 0),
        cs(2, "notes", 4),
        inv(8, "Landroid/content/UriMatcher;", "addURI", (0, 1, 2, 3)),
        cs(2, "notes/#", 12),
        inv(16, "Landroid/content/UriMatcher;", "addURI", (0, 1, 2, 3)),
    ), ())
    surface_ = surface(provider("com.example.NotesProvider",
                                path_permissions=(
                                    PathPermission("/internal", "literal",
                                                   read_permission="com.example.LOCKED"),
                                )))
    e = detect_provider_exposures(
        surface_,
        {QUERY_REF: query_flow_block(),
         MethodRef("com.example.NotesProvider", "<clinit>", "()V"): (clinit,)},
        {QUERY_REF: 14},
    )[0]
    assert op(e, "read").protection_status == "unprotected"


FIELD_SELECTION = ("Lcom/example/NotesProvider;", "selection", "Ljava/lang/String;")


def test_field_carried_sink_flow_cannot_satisfy_provider_proof():
    """A sink argument carried through an instance field is candidate-only:
    cross-method writes are unmodelled, so the flow must NOT appear in the
    operation's sink evidence and flow_complete must drop to False."""
    blocks = (FlowBlock(0, (
        cs(5, "name=?", 0),
        SInstruction(2, "iput-object", (5, 0), field_ref=FIELD_SELECTION),
        SInstruction(4, "iget-object", (11, 0), field_ref=FIELD_SELECTION),
        inv(6, "Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", (0, 1)),
        inv(8, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2]),
    ), ()),)
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: blocks},
        {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert read.sink_flows == (), "field-carried flow must not satisfy sink_reachable"
    assert read.flow_complete is False
    attrs = read.gate_attributes()
    assert "sink_reachable" not in attrs
    assert read.caller_check_absent is None  # unresolved, not claimed absent


def test_identity_check_keeps_caller_check_unknown_not_absent():
    """Binder.getCallingUid is a real check whose enforcement contract this
    engine does not model: never blanket-harmless, never a false absence."""
    blocks = (FlowBlock(0, (
        inv(0, "Landroid/os/Binder;", "getCallingUid", (),
            "()I", opcode="invoke-static"),
        SInstruction(2, "move-result", (3,)),
        SInstruction(4, "if-eqz", (3,), branch_target=20),
        inv(6, "Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", (0, 1)),
        inv(8, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2]),
    ), (20,)),)
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: blocks},
        {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert read.caller_check_absent is None
    outcomes = {g.outcome for g in read.guard_findings}
    assert "unmodelled-check" in outcomes


def test_check_result_clobbered_before_conditional_is_not_enforcing():
    """The register holding the check result is rewritten before the if: the
    conditional tests a different value, so no enforcement may be claimed."""
    blocks = (FlowBlock(0, (
        inv(0, CHECK_PERM[0], CHECK_PERM[1], (2, 3), CHECK_PERM[2]),
        SInstruction(2, "move-result", (3,)),
        SInstruction(4, "const/4", (3,)),          # clobber v3
        SInstruction(6, "if-eqz", (3,), branch_target=40),
        inv(8, "Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", (0, 1)),
        inv(10, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2]),
    ), ()),)
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: blocks},
        {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert all(g.outcome != "enforcing" for g in read.guard_findings)
    assert read.caller_check_absent is True  # complete evidence, result truly ignored


def test_earlier_conditional_on_same_register_is_not_the_guard_branch():
    """An if BEFORE the check on the same register number tested an older
    value; associating it with the check invents enforcement."""
    blocks = (FlowBlock(0, (
        SInstruction(0, "const/4", (3,)),
        SInstruction(2, "if-eqz", (3,), branch_target=40),   # unrelated earlier branch
        inv(4, CHECK_PERM[0], CHECK_PERM[1], (2, 3), CHECK_PERM[2]),
        SInstruction(6, "move-result", (3,)),
        inv(8, "Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", (0, 1)),
        inv(10, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2]),
    ), ()),)
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: blocks},
        {QUERY_REF: 14},
    )[0]
    read = op(e, "read")
    assert all(g.outcome != "enforcing" for g in read.guard_findings)


def test_enforcing_guard_in_query_does_not_refute_unguarded_delete():
    """Per-method aggregation: an enforcing check in query must not refute the
    write operation when delete reaches a sink with no guard at all."""
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: query_flow_block(with_enforce_guard=True),
         DELETE_REF: delete_flow_block()},
        {QUERY_REF: 14, DELETE_REF: 11},
    )[0]
    write = op(e, "write")
    assert write.sink_flows, "delete sink flow must be evidenced"
    assert write.caller_check_absent is True, "unguarded delete path is proven open"


def test_open_method_with_partial_global_flags_emits_unknown_not_true():
    """One completely evidenced open method while ANOTHER sink method's flow
    is incomplete: the operation-level flags are partial, so absence must be
    UNKNOWN. Emitting True here would contradict the flags and be rejected by
    the payload validator, terminally failing a legitimate analysis."""
    UPDATE_REF = MethodRef("com.example.NotesProvider", "update",
                           "(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;"
                           "[Ljava/lang/String;)I")
    open_update = (
        FlowBlock(0, (
            inv(0, "Landroid/database/sqlite/SQLiteDatabase;", "update", (0, 1, 2, 9, 10),
                "(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;"
                "[Ljava/lang/String;)I"),
        ), ()),
    )
    partial_delete = (
        FlowBlock(0, (
            inv(0, "Lcom/example/Helper;", "resolve", (1,), "(I)Ljava/lang/Object;"),
            inv(4, "Landroid/database/sqlite/SQLiteDatabase;", "delete", (0, 1, 9),
                "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I"),
        ), ()),
    )
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {UPDATE_REF: open_update, DELETE_REF: partial_delete},
        {UPDATE_REF: 14, DELETE_REF: 11},
    )[0]
    write = op(e, "write")
    # update is completely evidenced and open; delete's helper is unadapted
    # app code, so the operation-level coverage flag is partial.
    assert not write.coverage_complete
    assert write.caller_check_absent is None  # UNKNOWN, never a rejected True


def test_evidence_classes_name_provider_and_helper_classes():
    # A resolved guard helper in ANOTHER app class: both classes' adapted
    # bytecode backs the operation's claims, so both are named.
    helper_ref = MethodRef("com.example.Guard", "check", "()V")
    helper = (FlowBlock(0, (
        inv(0, ENFORCE_PERM[0], ENFORCE_PERM[1], (2, 3), ENFORCE_PERM[2]),
    ), ()),)
    query = (FlowBlock(0, (
        inv(0, "Lcom/example/Guard;", "check", (0,), "()V"),
        inv(2, "Landroid/database/sqlite/SQLiteQueryBuilder;", "setTables", (0, 1)),
        inv(4, QBUILDER_QUERY[0], QBUILDER_QUERY[1], (0, 4, 5, 11, 6, 7, 8),
            QBUILDER_QUERY[2]),
    ), ()),)
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")),
        {QUERY_REF: query, helper_ref: helper}, {QUERY_REF: 14, helper_ref: 4},
    )[0]
    read = op(e, "read")
    assert set(read.evidence_classes) == {"com.example.NotesProvider", "com.example.Guard"}


def test_evidence_classes_empty_without_adapted_crud():
    # No adapted provider methods: nothing backs a claim, no classes named,
    # and no caller-check claim is made in either direction.
    e = detect_provider_exposures(
        surface(provider("com.example.NotesProvider")), {}, None,
    )[0]
    for operation in e.operations:
        assert operation.evidence_classes == ()
        assert operation.caller_check_absent is None
