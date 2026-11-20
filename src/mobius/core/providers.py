"""Exported content-provider exposure evidence, per operation.

Generic, evidence-backed detection - no per-app verdicts. Verdicts stay
CANDIDATE-only: an exported provider with caller-controlled input reaching a
where-clause argument is intentional ContentProvider API surface until the
protection and guard evidence is resolved.

* Protection facts come from the verified manifest model:
  ``effective_protection`` mirrors ContentProvider.enforceRead/WritePermission-
  Inner (AOSP) - operation-specific, all-matching path-permissions, never
  first-match override, unknown patterns UNKNOWN rather than unprotected.
* Guard evidence distinguishes ENFORCING guards from mere guard calls:
  - enforce* (void, throws on denial): enforcing iff its block dominates every
    sink block of the operation.
  - check* (int return): enforcing iff the result is consumed by a conditional
    whose block dominates every sink block AND exactly one of its successors
    can reach the sink blocks (the other is the denial path). An ignored
    return value is recorded and never refutes.
* Coverage honesty: guard-absence is claimed only when every invoke in the
  operation's methods is a framework call or resolves to an adapted same-class
  helper (which is then guard-scanned too). Unresolved calls, unadapted
  methods, or incomplete flow scans keep absence UNKNOWN (None).
* Sink evidence is FLOW evidence: caller arguments seeded as external
  provenance, tracked into the whereClause/selection argument of an SQL sink
  invoke matched by full descriptor.
* UriMatcher constraints from <clinit> are extracted (literal patterns and
  numeric ``#`` segments); protection is consulted per literal path, and
  pattern paths defer to the provider-level chain (documented in
  effective_protection).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from .manifest import (
    ManifestSurface,
    ProtectionStatus,
    ProtectionVerdict,
    effective_protection,
)
from .reachability import MethodRef
from .flow import FlowBlock, scan_method_flow
from .sinks import GUARDS

# Identity/signature calls whose enforcement contract this engine does NOT
# model. They are real checks, never blanket-harmless framework calls: their
# presence must keep caller_check_absent unknown unless enforcement is proven.
# Only the Context.check*/enforce* permission family has a modeled contract
# (PERMISSION_GRANTED == 0 polarity / throw semantics); that modeled set is
# finite and declared here by reference, not by prefix matching.
_UNMODELLED_CHECKS: frozenset[tuple[str, str]] = frozenset({
    ("Landroid/os/Binder;", "getCallingUid"),
    ("Landroid/os/Binder;", "getCallingPid"),
    ("Landroid/app/ActivityManager;", "getCallingPackage"),
    ("Landroid/content/pm/PackageManager;", "checkSignatures"),
})

# Opcode families that WRITE their first register (used to detect a clobbered
# guard-result register between the check and its consuming conditional).
_REGISTER_WRITERS: tuple[str, ...] = (
    "const", "move", "new-", "iget", "sget", "aget", "fill-array",
    "neg-", "not-", "int-to", "long-to", "float-to", "double-to",
    "add-", "sub-", "mul-", "div-", "rem-", "and-", "or-", "xor-",
    "shl-", "shr-", "ushr-",
)

_READ_OPS: tuple[str, ...] = ("query",)
_WRITE_OPS: tuple[str, ...] = ("insert", "update", "delete")
# bulkInsert/call/openFile are real provider operations but out of scope for
# this detector's operation model; their absence here is declared, not missed.

# Descriptor-exact whereClause/predicate argument positions (register tuple is
# receiver-first for instance calls). An invoke whose descriptor is not listed
# yields no position claim.
_WHERECLAUSE_ARGS: Mapping[tuple[str, str, str], tuple[int, ...]] = {
    ("Landroid/database/sqlite/SQLiteDatabase;", "delete",
     "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I"): (2,),
    ("Landroid/database/sqlite/SQLiteDatabase;", "update",
     "(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I"): (3,),
    ("Landroid/database/sqlite/SQLiteDatabase;", "updateWithOnConflict",
     "(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;I)I"): (3,),
    ("Landroid/database/sqlite/SQLiteDatabase;", "query",
     "(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;"): (3,),
    ("Landroid/database/sqlite/SQLiteDatabase;", "query",
     "(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;"): (3,),
    ("Landroid/database/sqlite/SQLiteDatabase;", "query",
     "(ZLjava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;"): (4,),
    ("Landroid/database/sqlite/SQLiteDatabase;", "rawQuery",
     "(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"): (1,),
    ("Landroid/database/sqlite/SQLiteDatabase;", "execSQL",
     "(Ljava/lang/String;)V"): (1,),
    ("Landroid/database/sqlite/SQLiteQueryBuilder;", "appendWhere",
     "(Ljava/lang/CharSequence;)V"): (1,),
    ("Landroid/database/sqlite/SQLiteQueryBuilder;", "query",
     "(Landroid/database/sqlite/SQLiteDatabase;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;"): (3,),
}

_DESCRIPTOR_PARAMS = re.compile(r"\(([^)]*)\)")
_PARAM_TYPE = re.compile(r"(\[*)([ZBSCIJFD]|L[^;]+;)")
_URIMATCHER_ADDURI = ("Landroid/content/UriMatcher;", "addURI")
_FLOW_OFFSET = re.compile(r" at offset (\d+)$")
# True platform namespaces: code that ships with the OS, never bundled into an
# APK. Bundled libraries (androidx, kotlin, gms, third-party) are APP code:
# when they are not adapted, coverage is unknown rather than assumed harmless.
_FRAMEWORK_PREFIXES = ("Ljava/", "Ljavax/", "Landroid/", "Ldalvik/")
_FRAMEWORK_DOTTED = tuple(p[1:].replace("/", ".") for p in _FRAMEWORK_PREFIXES)


@dataclass(frozen=True, slots=True)
class SinkFlowEvidence:
    method: str
    sink: str
    detail: str


@dataclass(frozen=True, slots=True)
class GuardFinding:
    api: str          # e.g. "Landroid/content/Context;->checkCallingPermission"
    outcome: str      # "enforcing" | "ignored" | "checked-not-dominating" | "non-dominating"
    detail: str


@dataclass(frozen=True, slots=True)
class OperationExposure:
    operation: str                       # "read" | "write"
    protection_status: str               # ProtectionStatus value
    protection_permission: str | None
    protection_basis: str
    caller_check_absent: bool | None     # enforcing-check absence; None = unknown
    guard_findings: tuple[GuardFinding, ...]
    coverage_complete: bool
    sink_flows: tuple[SinkFlowEvidence, ...]
    flow_complete: bool
    evidence_classes: tuple[str, ...] = ()  # provider class + guard-helper classes
                                           # whose adapted bytecode backs this
                                           # operation's claims

    def gate_attributes(self) -> dict[str, object]:
        """Missing evidence stays missing: None is never written."""
        attributes: dict[str, object] = {
            "operation": self.operation,
            "protection_status": self.protection_status,
        }
        if self.protection_permission is not None:
            attributes["protection_permission"] = self.protection_permission
        if self.caller_check_absent is not None:
            attributes["caller_check_absent"] = self.caller_check_absent
        if self.sink_flows:
            attributes["sink_reachable"] = True
        return attributes


@dataclass(frozen=True, slots=True)
class ProviderExposure:
    provider: str
    exported: bool
    grant_uri_permissions: bool
    uri_patterns: tuple[str, ...]
    numeric_uri_patterns: tuple[str, ...]
    operations: tuple[OperationExposure, ...]

    @property
    def exported_and_enabled(self) -> bool:
        return self.exported

    def gate_attributes(self) -> dict[str, object]:
        attributes: dict[str, object] = {
            "exported": self.exported,
            "operations": [op.gate_attributes() for op in self.operations],
        }
        if self.grant_uri_permissions:
            attributes["grant_uri_permissions"] = True
        return attributes


def parameter_registers(descriptor: str, registers_size: int, is_static: bool) -> tuple[int, ...]:
    """Register indexes of the method's arguments (excluding `this`)."""
    match = _DESCRIPTOR_PARAMS.search(descriptor)
    if match is None or registers_size <= 0:
        return ()
    widths = [2 if t in ("J", "D") else 1 for _, t in _PARAM_TYPE.findall(match.group(1))]
    this_width = 0 if is_static else 1
    first = registers_size - sum(widths) - this_width
    if first < 0:
        return ()
    regs: list[int] = []
    cursor = first + this_width
    for width in widths:
        regs.append(cursor)
        cursor += width
    return tuple(regs)


def uri_matcher_patterns(
    clinit_blocks: Sequence[FlowBlock] | None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Path patterns registered via UriMatcher.addURI, split by numeric ``#``."""
    patterns: list[str] = []
    numeric: list[str] = []
    if not clinit_blocks:
        return (), ()
    for block in clinit_blocks:
        strings: dict[int, str] = {}
        for ins in block.instructions:
            if ins.opcode.startswith("const-string") and ins.registers and ins.literal is not None:
                strings[ins.registers[0]] = ins.literal
            elif ins.opcode.startswith("move") and len(ins.registers) >= 2:
                if ins.registers[1] in strings:
                    strings[ins.registers[0]] = strings[ins.registers[1]]
                else:
                    strings.pop(ins.registers[0], None)
            elif (ins.invoke_class, ins.invoke_method) == _URIMATCHER_ADDURI and len(ins.registers) >= 3:
                # addURI(authority, path, code): path is the second argument
                path = strings.get(ins.registers[2])
                if path:
                    if "#" in path:
                        numeric.append(path)  # matcher-constrained to a numeric segment
                    else:
                        patterns.append(path)
    return tuple(patterns), tuple(numeric)


# -- CFG helpers -------------------------------------------------------------


def _dominators(blocks: Sequence[FlowBlock]) -> dict[int, set[int]]:
    """Iterative dominator sets over a small method CFG."""
    starts = {b.start for b in blocks}
    preds: dict[int, set[int]] = {s: set() for s in starts}
    for b in blocks:
        for succ in b.successors:
            if succ in preds:
                preds[succ].add(b.start)
    entry = min(starts)
    dom: dict[int, set[int]] = {s: set(starts) for s in starts}
    dom[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for s in starts - {entry}:
            ps = preds[s]
            if ps:
                new = {s} | set.intersection(*(dom[p] for p in ps))
            else:
                new = {s}
            if new != dom[s]:
                dom[s] = new
                changed = True
    return dom


def _reachable_from(start: int, blocks: Mapping[int, FlowBlock]) -> set[int]:
    seen: set[int] = set()
    stack = [start]
    while stack:
        s = stack.pop()
        if s in seen or s not in blocks:
            continue
        seen.add(s)
        stack.extend(blocks[s].successors)
    return seen


def _block_of_offset(blocks: Sequence[FlowBlock], offset: int) -> int | None:
    for b in blocks:
        for ins in b.instructions:
            if ins.offset == offset:
                return b.start
    return None


def _analyze_guards(
    blocks: Sequence[FlowBlock],
    sink_block_starts: set[int],
    extra_blocks: Sequence[FlowBlock] = (),
    try_ranges: Sequence[tuple[int, int]] = (),
) -> tuple[GuardFinding, ...]:
    """Classify guard calls in ONE method's blocks.

    A guard is evidence of enforcement only within the API contract:
    check* guards return PERMISSION_GRANTED == 0 on success, so the sink must
    be reachable only through the branch the comparison identifies as the
    granted outcome; enforce* guards throw, but a throw caught before the sink
    is no enforcement, so a guard inside a try region with a handler is
    "catch-unknown". Helpers are reported but never resolved across the call
    boundary.
    """
    findings: list[GuardFinding] = []
    by_start = {b.start: b for b in blocks}
    dom = _dominators(blocks) if sink_block_starts & set(by_start) else {}

    def in_try(offset: int) -> bool:
        return any(start <= offset < end for start, end in try_ranges)

    def const_registers(block: FlowBlock, before: int) -> dict[int, int]:
        values: dict[int, int] = {}
        for ins in block.instructions:
            if ins.offset >= before:
                break
            if ins.const_value is not None and ins.registers:
                values[ins.registers[0]] = ins.const_value
        return values

    def classify(ins, block_start: int, dominates_sinks: bool) -> GuardFinding:
        api = f"{ins.invoke_class}->{ins.invoke_method}"
        returns_void = bool(ins.invoke_descriptor and ins.invoke_descriptor.endswith(")V"))
        if returns_void:
            if in_try(ins.offset):
                return GuardFinding(api, "catch-unknown",
                                    f"void guard at offset {ins.offset} sits inside a try "
                                    "region; a handler may catch the SecurityException "
                                    "before the sink")
            outcome = "enforcing" if dominates_sinks else "non-dominating"
            return GuardFinding(api, outcome,
                                f"void guard at offset {ins.offset}; dominance over sink "
                                f"blocks: {dominates_sinks}")
        # check*-style: the int result must gate a decisive conditional whose
        # polarity matches the PERMISSION_GRANTED == 0 contract.
        result_reg: int | None = None
        moveresult_offset: int | None = None
        block = by_start[block_start]
        for follow in block.instructions:
            if follow.offset <= ins.offset:
                continue
            if follow.opcode.startswith("move-result"):
                result_reg = follow.registers[0] if follow.registers else None
                moveresult_offset = follow.offset
                break
        if result_reg is None or moveresult_offset is None:
            return GuardFinding(api, "ignored",
                                f"return value of guard at offset {ins.offset} is not consumed")
        cross_block_consumption = False
        for b in blocks:
            for candidate in b.instructions:
                if not candidate.opcode.startswith("if-") or result_reg not in candidate.registers:
                    continue
                if b.start != block_start:
                    # A conditional in another block reads the register: with no
                    # def-use ordering across blocks we cannot prove it tests
                    # THIS check's value rather than a rewritten one.
                    cross_block_consumption = True
                    continue
                if candidate.offset <= moveresult_offset:
                    continue  # an earlier conditional tested an older value
                if any(
                    moveresult_offset < mid.offset < candidate.offset
                    and mid.registers and mid.registers[0] == result_reg
                    and mid.opcode.startswith(_REGISTER_WRITERS)
                    for mid in block.instructions
                ):
                    continue  # register clobbered between check and conditional
                if not sink_block_starts:
                    return GuardFinding(api, "checked-not-dominating",
                                        "result checked but no sink blocks to dominate")
                op = candidate.opcode
                target = candidate.branch_target
                if target is None or target not in b.successors or len(b.successors) != 2:
                    return GuardFinding(api, "unknown-polarity",
                                        f"conditional at offset {candidate.offset}: branch "
                                        "target not validated against CFG successors")
                fallthrough = next(succ for succ in b.successors if succ != target)
                if op == "if-eqz":       # jump when result == 0 == PERMISSION_GRANTED
                    granted = target
                elif op == "if-nez":     # jump when result != 0 == denied
                    granted = fallthrough
                elif op in ("if-eq", "if-ne"):
                    other = next(r for r in candidate.registers if r != result_reg)
                    if const_registers(b, candidate.offset).get(other) != 0:
                        return GuardFinding(api, "unknown-polarity",
                                            f"conditional at offset {candidate.offset} compares "
                                            "against a non-zero or unknown constant")
                    granted = target if op == "if-eq" else fallthrough
                else:
                    return GuardFinding(api, "unknown-polarity",
                                        f"conditional {op} at offset {candidate.offset} has no "
                                        "PERMISSION_GRANTED == 0 polarity reading")
                denied = fallthrough if granted == target else target
                granted_reaches = bool(_reachable_from(granted, by_start) & sink_block_starts)
                denied_reaches = bool(_reachable_from(denied, by_start) & sink_block_starts)
                dominating = all(b.start in dom.get(sb, set()) for sb in sink_block_starts)
                if granted_reaches and not denied_reaches:
                    if dominating:
                        return GuardFinding(api, "enforcing",
                                            f"result gates {op} at offset {candidate.offset}; "
                                            "granted branch is the only path to the sink "
                                            "blocks and the check dominates them")
                    return GuardFinding(api, "checked-not-dominating",
                                        f"result gates {op} at offset {candidate.offset} but "
                                        "the check does not dominate all sink blocks")
                if denied_reaches and not granted_reaches:
                    return GuardFinding(api, "polarity-inverted",
                                        f"sinks are reachable via the DENIED branch of the "
                                        f"conditional at offset {candidate.offset}; the "
                                        "guard does not protect them")
                return GuardFinding(api, "checked-not-dominating",
                                    f"both conditional outcomes reach sink blocks "
                                    f"(if at offset {candidate.offset})")
        if cross_block_consumption:
            return GuardFinding(api, "unknown-polarity",
                                f"result of guard at offset {ins.offset} is consumed by a "
                                "conditional in another block; without def-use ordering the "
                                "association is unverified")
        return GuardFinding(api, "ignored",
                            f"return value of guard at offset {ins.offset} never consumed "
                            "by a conditional")

    for b in blocks:
        for ins in b.instructions:
            if not ins.invoke_class:
                continue
            key = (ins.invoke_class, ins.invoke_method)
            if key in _UNMODELLED_CHECKS:
                findings.append(GuardFinding(
                    f"{ins.invoke_class}->{ins.invoke_method}", "unmodelled-check",
                    f"identity/signature check at offset {ins.offset}; this engine does "
                    "not model its enforcement contract, so enforcement stays unknown"))
            elif key in GUARDS:
                dominates = bool(sink_block_starts) and all(
                    b.start in dom.get(sb, set()) for sb in sink_block_starts)
                findings.append(classify(ins, b.start, dominates))
    for b in extra_blocks:
        for ins in b.instructions:
            if not ins.invoke_class:
                continue
            key = (ins.invoke_class, ins.invoke_method)
            if key in _UNMODELLED_CHECKS or key in GUARDS:
                # guards in helper bodies count as evidence, but neither
                # enforcement nor absence is provable across the call boundary
                findings.append(GuardFinding(
                    f"{ins.invoke_class}->{ins.invoke_method}", "helper-unresolved",
                    "guard in helper method; cross-method dominance not established"))
    return tuple(findings)


def _coverage_complete(
    blocks: Sequence[FlowBlock],
    methods: Mapping[MethodRef, Sequence[FlowBlock]],
    class_name: str,
    superclasses: Mapping[str, str] | None = None,
) -> tuple[bool, tuple[FlowBlock, ...], tuple[str, ...]]:
    """Every invoke must be framework or resolvable through the class hierarchy
    to an adapted app method or a framework ancestor.

    Returns (complete, helper_blocks, helper_classes): resolved app helpers
    are returned so their guard calls can count, with the class names whose
    adapted bytecode those blocks came from (runtime-loading provenance is
    checked against them API-side). Anything unresolved marks coverage
    incomplete, so guard-absence stays unknown - inherited guards and
    unadapted code are never assumed away.
    """
    complete = True
    helpers: list[FlowBlock] = []
    helper_classes: list[str] = []
    for b in blocks:
        for ins in b.instructions:
            if not ins.opcode.startswith("invoke-") or ins.invoke_class is None:
                continue
            cls = ins.invoke_class
            dotted = cls[1:-1].replace("/", ".") if cls.startswith("L") else cls
            # walk the superclass chain: an ancestor defining the method makes
            # it an adapted helper; a framework ancestor makes it inherited
            # platform behavior; anything else is unknown coverage
            # Adapted map FIRST, at every level of the superclass chain: an
            # adapted method is analyzed, whatever its package looks like.
            # Only then does a platform prefix settle coverage (inherited OS
            # behavior); bundled-library or app code we did not adapt stays
            # UNKNOWN, never assumed harmless.
            seen: set[str] = set()
            current: str | None = dotted
            resolved = False
            while current and current not in seen:
                seen.add(current)
                helper = next(
                    (m for ref, m in methods.items()
                     if ref.class_name == current
                     and ref.name == ins.invoke_method
                     and (ins.invoke_descriptor is None
                          or ref.descriptor.replace(" ", "") == ins.invoke_descriptor)),
                    None,
                )
                if helper is not None:
                    helpers.extend(helper)
                    if current not in helper_classes:
                        helper_classes.append(current)
                    resolved = True
                    break
                if current.startswith(_FRAMEWORK_DOTTED):
                    resolved = True  # inherited platform behavior, not adapted
                    break
                current = (superclasses or {}).get(current)
            if not resolved:
                complete = False
    return complete, tuple(helpers), tuple(helper_classes)


def _methods_named(
    methods: Mapping[MethodRef, Sequence[FlowBlock]], class_name: str, name: str,
) -> list[MethodRef]:
    return [ref for ref in methods
            if ref.class_name == class_name and ref.name == name]


def _caller_entry_state(
    ref: MethodRef, registers_sizes: Mapping[MethodRef, int] | None,
) -> dict[int, frozenset]:
    if not registers_sizes or ref not in registers_sizes:
        return {}
    regs = parameter_registers(ref.descriptor, registers_sizes[ref], is_static=False)
    return {r: frozenset({("ext", "provider-caller-argument")}) for r in regs}


def _analyze_operation(
    surface: ManifestSurface,
    component,
    operation: str,
    op_methods: list[str],
    methods: Mapping[MethodRef, Sequence[FlowBlock]],
    registers_sizes: Mapping[MethodRef, int] | None,
    representatives: tuple[str, ...],
    superclasses: Mapping[str, str] | None = None,
    try_regions: Mapping[MethodRef, tuple[tuple[int, int], ...]] | None = None,
) -> OperationExposure:
    dotted = component.fully_qualified_name
    crud = {
        ref: blocks
        for name in op_methods
        for ref in _methods_named(methods, dotted, name)
        for blocks in [methods[ref]]
    }

    sink_flows: list[SinkFlowEvidence] = []
    guard_findings: list[GuardFinding] = []
    flow_complete = bool(crud)
    coverage_complete = True
    # Per-method evidence: an enforcing guard in one CRUD method says nothing
    # about another method's sinks, so enforcement and openness are decided
    # per method first and only then aggregated.
    method_states: list[dict[str, object]] = []
    # Only classes whose adapted bytecode actually backs a claim: with no
    # adapted CRUD method the provider class contributed nothing (and may not
    # exist in the adapted set at all).
    evidence_classes: list[str] = [dotted] if crud else []
    for ref, blocks in crud.items():
        scan = scan_method_flow(
            blocks,
            entry_state=_caller_entry_state(ref, registers_sizes),
            sink_args=_WHERECLAUSE_ARGS,
        )
        flow_complete = flow_complete and scan.complete
        if scan.field_dependent:
            # Field-carried provenance reaches this scan's sinks: cross-method
            # writes are unmodelled, so these flows cannot satisfy provider
            # proofs. They stay off the record and force flow-complete down.
            flow_complete = False
        method_sink_blocks: set[int] = set()
        method_sink_count = 0
        for flow in scan.sink_flows if not scan.field_dependent else ():
            sink_flows.append(SinkFlowEvidence(str(ref), flow.kind, flow.detail))
            method_sink_count += 1
            # offset is embedded by the engine's stable detail format
            m = _FLOW_OFFSET.search(flow.detail)
            if m:
                start = _block_of_offset(blocks, int(m.group(1)))
                if start is not None:
                    method_sink_blocks.add(start)
        ok, helpers, helper_cls = _coverage_complete(blocks, methods, dotted, superclasses)
        coverage_complete = coverage_complete and ok
        for cls_name in helper_cls:
            if cls_name not in evidence_classes:
                evidence_classes.append(cls_name)
        method_findings = _analyze_guards(
            blocks, method_sink_blocks, extra_blocks=helpers,
            try_ranges=(try_regions or {}).get(ref, ()),
        )
        guard_findings.extend(method_findings)
        method_states.append({
            "sinks": method_sink_count,
            "complete": ok and scan.complete and not scan.field_dependent,
            "enforcing": any(f.outcome == "enforcing" for f in method_findings),
            "unresolved": any(
                f.outcome in ("helper-unresolved", "catch-unknown", "unknown-polarity",
                              "unmodelled-check")
                for f in method_findings
            ),
        })

    with_sinks = [m for m in method_states if m["sinks"]]
    proven_open = [
        m for m in with_sinks
        if m["complete"] and not m["enforcing"] and not m["unresolved"]
    ]
    unresolved = any(m["unresolved"] for m in method_states)
    if proven_open and coverage_complete and flow_complete and not unresolved:
        # At least one reachable sink method is completely evidenced with no
        # enforcing or unresolved guard, AND nothing elsewhere in this
        # operation was left partial: an unguarded caller path exists. When
        # the operation-level flags are partial, absence stays UNKNOWN rather
        # than claiming a proof the payload contract would (rightly) reject.
        caller_check_absent: bool | None = True
    elif with_sinks and all(m["enforcing"] for m in with_sinks) \
            and coverage_complete and flow_complete and not unresolved:
        # Every method that reaches a sink enforces a check, and nothing was
        # left unseen or unresolved: enforcement covers all evidenced paths.
        caller_check_absent = False
    elif not with_sinks and method_states and all(
            m["complete"] for m in method_states) and not unresolved:
        # Completely evidenced methods with no sink flow: any check state is
        # accurately described (no sink to protect on seen paths).
        caller_check_absent = not any(m["enforcing"] for m in method_states)
    else:
        caller_check_absent = None  # unknown: coverage/scan incomplete or a
        # guard's enforcement cannot be resolved across every sink method

    # protection: consult every discovered path instance. Numeric '#' segments
    # arrive as a representative '0', glob '*' as 'x'; an UNPROTECTED instance
    # is evidence, all-protected instances still leave other paths unverified
    # (UNKNOWN), and with no path-permissions at all the provider chain decides
    # every path uniformly.
    # A representative that is UNPROTECTED is evidence only for paths routed
    # to the SAME sink flows. The detector does not map UriMatcher branches to
    # flows, so an unprotected instance class counts only when every discovered
    # pattern resolves open (whichever branch carries the flow is then open);
    # mixed verdicts across registered patterns stay UNKNOWN rather than
    # confirming an operation-level exposure from an unrelated open path.
    verdict = None
    has_path_perms = bool(component.path_permissions)
    if representatives and has_path_perms:
        per_pattern = [
            (path, effective_protection(surface, component, operation, path))
            for path in representatives
        ]
        statuses = {v.status for _, v in per_pattern}
        if statuses == {ProtectionStatus.UNPROTECTED}:
            verdict = per_pattern[0][1]
        else:
            detail = ", ".join(f"{p}: {v.status.value}" for p, v in per_pattern)
            verdict = ProtectionVerdict(
                ProtectionStatus.UNKNOWN, None,
                "per-path protection differs or is unresolvable across the "
                "registered patterns and the sink-flow branch mapping is "
                f"unresolved ({detail}); other instances are unverified",
            )
    elif representatives:
        # No path-permissions: the provider chain decides every path uniformly.
        verdict = effective_protection(surface, component, operation,
                                       representatives[0])
    else:
        verdict = effective_protection(surface, component, operation)

    return OperationExposure(
        operation=operation,
        protection_status=verdict.status.value,
        protection_permission=verdict.permission,
        protection_basis=verdict.basis,
        caller_check_absent=caller_check_absent,
        guard_findings=tuple(guard_findings),
        coverage_complete=coverage_complete,
        sink_flows=tuple(sink_flows),
        flow_complete=flow_complete,
        evidence_classes=tuple(evidence_classes),
    )


def _representative_paths(patterns: tuple[str, ...], numeric: tuple[str, ...]) -> tuple[str, ...]:
    """Representative URI paths for discovered UriMatcher patterns: literals
    as-is, '#' -> '0', '*' -> 'x'. An UNPROTECTED verdict on a representative
    is evidence for that instance class; PROTECTED covers only that instance."""
    reps = ["/" + p for p in patterns]
    reps += ["/" + p.replace("#", "0").replace("*", "x") for p in numeric]
    return tuple(reps)


def detect_provider_exposures(
    surface: ManifestSurface,
    methods: Mapping[MethodRef, Sequence[FlowBlock]],
    registers_sizes: Mapping[MethodRef, int] | None = None,
    superclasses: Mapping[str, str] | None = None,
    try_regions: Mapping[MethodRef, tuple[tuple[int, int], ...]] | None = None,
) -> list[ProviderExposure]:
    """Evidence records for every declared provider, exported or not.

    ``methods`` maps MethodRef -> CFG blocks (androguard-adapted). Providers
    whose methods are absent from the map get manifest-only evidence and
    ``flow_complete=False`` per operation: absence of guard/sink evidence is
    not claimed.
    """
    exposures: list[ProviderExposure] = []
    for component in surface.by_kind("provider"):
        dotted = component.fully_qualified_name
        clinit = next(
            (blocks for ref, blocks in methods.items()
             if ref.class_name == dotted and ref.name == "<clinit>"),
            None,
        )
        patterns, numeric = uri_matcher_patterns(clinit)
        representatives = _representative_paths(patterns, numeric)
        operations = (
            _analyze_operation(surface, component, "read", list(_READ_OPS),
                               methods, registers_sizes, representatives,
                               superclasses, try_regions),
            _analyze_operation(surface, component, "write", list(_WRITE_OPS),
                               methods, registers_sizes, representatives,
                               superclasses, try_regions),
        )
        exposures.append(ProviderExposure(
            provider=dotted,
            exported=component.exported and component.enabled,
            grant_uri_permissions=component.grant_uri_permissions,
            uri_patterns=patterns,
            numeric_uri_patterns=numeric,
            operations=operations,
        ))
    return exposures
