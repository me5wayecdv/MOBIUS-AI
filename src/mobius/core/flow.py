"""Reusable register-provenance flow engine over adapted bytecode CFGs.

Generic may-flow machinery shared by the secrets detector and the provider
exposure detector: minimal instruction model (SInstruction/FlowBlock), a
bounded block-aware scan (scan_method_flow) with union join at block entries,
cycle/incomplete honesty, caller-argument seeding, sink-argument flow events,
and the androguard adapter. Domain heuristics (what counts as a secret, what
counts as a guard) live with the detectors, not here.
"""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from .reachability import MethodRef

# -- flow model -----------------------------------------------------------------

# Key-material sinks with the EXACT secret argument position (register tuple is
# receiver-first for instance calls; SecretKeySpec has a single (byte[], String)
# form, PBEKeySpec's first argument is always the char[] password, KeyStore.load
# is (InputStream, char[])). Deliberately absent: IvParameterSpec/PBEParameterSpec
# (IV/salt are not secret), Cipher.init/Mac.init (take Key objects, caught at
# SecretKeySpec), MessageDigest.digest/update (payload is not key material),
# Base64, socket factories, request properties.
_KEY_MATERIAL_ARGS: Mapping[tuple[str, str], tuple[int, ...]] = {
    ("Ljavax/crypto/spec/SecretKeySpec;", "<init>"): (1,),
    ("Ljavax/crypto/spec/PBEKeySpec;", "<init>"): (1,),
    ("Ljava/security/KeyStore;", "load"): (2,),
}

_COMPARISONS: frozenset[tuple[str, str]] = frozenset({
    ("Ljava/lang/String;", "equals"),
    ("Ljava/lang/String;", "equalsIgnoreCase"),
    ("Ljava/lang/String;", "contentEquals"),
    ("Ljava/lang/String;", "compareTo"),
})

# Adapter reference patterns (module-level so tests can pin them against REAL
# androguard output strings, including spaced multiarg descriptors).
_INVOKE_RE = re.compile(r"(L[^;]+;)->([^\(\s]+)(\([^)]*\)\S*)")
_FIELD_RE = re.compile(r"(L[^;]+;)->([^\s:]+)\s+(\S+)\s*$")

# Reads whose result is external input. Intent.getAction is EXCLUDED: it yields
# public dispatch identifiers, and comparing against them is routing, not an
# access decision.
_EXTERNAL_INPUT_READS: frozenset[tuple[str, str]] = frozenset({
    ("Landroid/widget/EditText;", "getText"),
    ("Landroid/content/Intent;", "getStringExtra"),
    ("Landroid/content/Intent;", "getData"),
    ("Landroid/content/Intent;", "getDataString"),
    ("Landroid/net/Uri;", "getQueryParameter"),
    ("Landroid/net/Uri;", "getLastPathSegment"),
    ("Landroid/os/Bundle;", "getString"),
})

# Value-preserving operations provenance may cross (may-flow; offsets recorded).
_PROPAGATION_APIS: frozenset[tuple[str, str]] = frozenset({
    ("Ljava/lang/String;", "concat"),
    ("Ljava/lang/String;", "trim"),
    ("Ljava/lang/String;", "substring"),
    ("Ljava/lang/String;", "toString"),
    ("Ljava/lang/StringBuilder;", "append"),
    ("Ljava/lang/StringBuilder;", "toString"),
    ("Ljava/lang/CharSequence;", "toString"),
    ("Landroid/text/Editable;", "toString"),
    # invokes in compiled code often resolve toString at the static Object type
    ("Ljava/lang/Object;", "toString"),
})

# String -> byte[]/char[] conversion. After crossing one of these the origin becomes
# ("keybytes", value): the sinks above take key material as bytes/chars, and a string
# flowing in UNCONVERTED lands in a String-typed parameter (algorithm name, spec
# string), which is not key material.
_TO_KEYBYTES_APIS: frozenset[tuple[str, str]] = frozenset({
    ("Ljava/lang/String;", "getBytes"),
    ("Ljava/lang/String;", "toCharArray"),
})

# Opcodes whose first register operand is NOT a write destination (uses only).
# Everything else with register operands kills provenance of its first register:
# binary/unary ops, cmp*, instanceof, array-get, new-instance... all write dest-first.
_NO_DEST_PREFIXES = (
    "if-", "goto", "return", "throw", "monitor-", "invoke-",
    "aput", "iput", "sput", "fill-array-data",
    "packed-switch", "sparse-switch",
)
# Value-preserving writes: provenance of the source is copied to the destination.
_COPY_OPS = ("move", "check-cast")


@dataclass(frozen=True, slots=True)
class SInstruction:
    """Minimal instruction the flow scan models (synthesised in tests, adapted
    from androguard in the APK runner)."""
    offset: int
    opcode: str
    registers: tuple[int, ...] = ()
    literal: str | None = None
    invoke_class: str | None = None
    invoke_method: str | None = None
    invoke_descriptor: str | None = None
    # (class, name, descriptor) for iput/iget/sput/sget field references
    field_ref: tuple[str, str, str] | None = None
    is_static: bool = False
    unsupported: bool = False
    # absolute branch target offset for if-*/goto* (byte offset, validated
    # against CFG successors); integer value for const* opcodes
    branch_target: int | None = None
    const_value: int | None = None


@dataclass(frozen=True, slots=True)
class FlowBlock:
    start: int
    instructions: tuple[SInstruction, ...]
    successors: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class FlowEvidence:
    kind: str  # "key-material-argument" | "access-comparison-suspect"
    detail: str


@dataclass(frozen=True, slots=True)
class CallRecord:
    """One resolved invoke with the argument-register provenance at its site."""
    offset: int
    invoke_class: str
    invoke_method: str
    invoke_descriptor: str | None
    is_static: bool
    arg_origins: tuple[frozenset, ...]
    opcode: str = ""


@dataclass(frozen=True, slots=True)
class MethodFlowScan:
    complete: bool
    # literal value -> evidence items for that value
    evidence: Mapping[str, tuple[FlowEvidence, ...]]
    # caller-input -> sink-argument flow events (external-input-argument kind)
    sink_flows: tuple[FlowEvidence, ...] = ()
    # may-flow union of field provenance observed across all scanned blocks
    # (field ref -> origins); seeds sibling-method scans of the same class
    field_summary: Mapping[tuple[str, str, str], frozenset] = field(default_factory=dict)
    # resolved invokes with their argument provenance (for one-hop callers)
    calls: tuple[CallRecord, ...] = ()
    # True when any field read contributed non-empty provenance to a register:
    # evidence may then rest on cross-method field values this scan cannot bound
    field_dependent: bool = False


def _scan_block(
    block: FlowBlock,
    in_state: dict[int, frozenset],
    invokes: dict[int, tuple[str, str, tuple[frozenset, ...]]],
    evidence: dict[str, list[FlowEvidence]],
    key_seed: list[int],
    sink_args: Mapping[tuple[str, str, str | None], tuple[int, ...]] | None = None,
    sink_flows: list[FlowEvidence] | None = None,
    field_state: dict[tuple[str, str, str], frozenset] | None = None,
    calls: list[CallRecord] | None = None,
    field_flags: list[bool] | None = None,
) -> tuple[dict[int, frozenset], bool]:
    """One linear pass over a block. Returns (out_state, complete).

    ``field_state`` carries method-local field provenance and is mutated in
    place (it is the block's OUT field state on return): iput/sput union the
    value register's provenance into the referenced field, iget/sget read it
    back. A field never stored within this scan yields an opaque
    ("field", "Class->name") origin marker, the same honesty contract as
    unmodelled invoke returns (unknown value, scan still structurally
    complete); it never masquerades as a literal or external input.
    """
    state = dict(in_state)
    fields = field_state if field_state is not None else {}
    pending: int | None = None
    complete = True

    def kill(register: int) -> None:
        state.pop(register, None)

    for ins in block.instructions:
        op = ins.opcode
        regs = ins.registers
        if ins.unsupported:
            complete = False
        if op.startswith("const-string"):
            if regs and ins.literal is not None:
                state[regs[0]] = frozenset({("lit", ins.literal)})
            elif regs:
                kill(regs[0])
            pending = None
        elif op.startswith("const"):
            if regs:
                state[regs[0]] = frozenset({("const",)})
            pending = None
        elif op.startswith("move-result"):
            if regs and pending is not None:
                cls, name, arg_origins = invokes[pending]
                if (cls, name) in _EXTERNAL_INPUT_READS:
                    state[regs[0]] = frozenset({("ext", f"{cls}->{name}")})
                elif (cls, name) in _TO_KEYBYTES_APIS:
                    # Only the RECEIVER's value becomes key bytes: String.getBytes(
                    # "UTF-8") converts the string, not the charset-name argument.
                    merged: set = set()
                    for origins in arg_origins[:1]:
                        merged |= {("keybytes", o[1]) for o in origins if o and o[0] == "lit"}
                        merged |= {o for o in origins if o and o[0] in ("ext", "keybytes")}
                    state[regs[0]] = frozenset(merged)
                elif (cls, name) in _PROPAGATION_APIS:
                    merged = set()
                    for origins in arg_origins:
                        merged |= {o for o in origins if o and o[0] in ("lit", "keybytes", "ext")}
                    state[regs[0]] = frozenset(merged)
                elif (cls, name) in _COMPARISONS:
                    state[regs[0]] = frozenset({("cmp", pending)})
                else:
                    state[regs[0]] = frozenset({("res", pending)})
            elif regs:
                complete = False  # move-result without a modelled preceding invoke
                kill(regs[0])
            pending = None
        elif op.startswith("check-cast"):
            # in-place cast: value-preserving, provenance untouched
            pending = None
        elif op.startswith("move"):
            if len(regs) >= 2:
                state[regs[0]] = state.get(regs[1], frozenset())
            elif regs:
                kill(regs[0])  # move-exception and friends: unknown value
            pending = None
        elif op.startswith("invoke-"):
            cls, name = ins.invoke_class, ins.invoke_method
            if cls is None:
                complete = False  # never guess argument positions
                pending = None
                continue
            arg_origins = tuple(state.get(r, frozenset()) for r in regs)
            key_seed[0] += 1
            invokes[key_seed[0]] = (cls, name, arg_origins)
            pending = key_seed[0]
            if calls is not None:
                calls.append(CallRecord(ins.offset, cls, name, ins.invoke_descriptor,
                                        ins.is_static, arg_origins, ins.opcode))
            if sink_args is not None and sink_flows is not None:
                positions = sink_args.get((cls, name, ins.invoke_descriptor))
                if positions is None:
                    positions = sink_args.get((cls, name, None), ())
                for position in positions:
                    if position >= len(arg_origins):
                        complete = False
                        continue
                    sources = sorted({o[1] for o in arg_origins[position] if o and o[0] == "ext"})
                    if sources:
                        sink_flows.append(FlowEvidence(
                            "external-input-argument",
                            f"caller-controlled value ({', '.join(sources)}) flows to "
                            f"argument {position} of {cls}->{name}{ins.invoke_descriptor or ''} "
                            f"at offset {ins.offset}",
                        ))
            for position in _KEY_MATERIAL_ARGS.get((cls, name), ()):
                if position >= len(arg_origins):
                    complete = False
                    continue
                for origin in sorted(arg_origins[position]):
                    if origin and origin[0] == "keybytes":
                        evidence.setdefault(origin[1], []).append(FlowEvidence(
                            "key-material-argument",
                            f"const-string literal flows via byte/char conversion into the "
                            f"key/password argument (register position {position}) of "
                            f"{cls}->{name} at offset {ins.offset}",
                        ))
        elif op.startswith("iput") or op.startswith("sput"):
            # iput vValue, vObj, ref / sput vValue, ref: union value provenance
            # into the referenced field (may-flow).
            if ins.field_ref is None:
                complete = False  # field op without a resolved reference: never guess
            elif regs:
                fields[ins.field_ref] = fields.get(ins.field_ref, frozenset()) | state.get(regs[0], frozenset())
            pending = None
        elif op.startswith("iget") or op.startswith("sget"):
            if ins.field_ref is None:
                complete = False
                if regs:
                    kill(regs[0])
            elif regs:
                if ins.field_ref in fields:
                    if fields[ins.field_ref] and field_flags is not None:
                        field_flags[0] = True
                    state[regs[0]] = fields[ins.field_ref]
                else:
                    cls, name, _ = ins.field_ref
                    state[regs[0]] = frozenset({("field", f"{cls}->{name}")})
            pending = None
        elif op.startswith("if-"):
            for r in regs:
                for origin in state.get(r, frozenset()):
                    if origin and origin[0] == "cmp":
                        cls, name, arg_origins = invokes[origin[1]]
                        lit_side: list[str] = []
                        ext_side: list[str] = []
                        for origins in arg_origins:
                            lit_side += sorted({o[1] for o in origins if o and o[0] == "lit"})
                            ext_side += sorted({o[1] for o in origins if o and o[0] == "ext"})
                        for value in set(lit_side):
                            if ext_side:
                                evidence.setdefault(value, []).append(FlowEvidence(
                                    "access-comparison-suspect",
                                    f"const-string literal compared by {cls}->{name} against "
                                    f"external input ({', '.join(ext_side)}); result consumed "
                                    f"by {op} at offset {ins.offset}. Comparison+branch shape "
                                    f"is shared with UI routing/dispatch; review-only.",
                                ))
            pending = None
        elif op.startswith(_NO_DEST_PREFIXES):
            pending = None
        else:
            # Unmodelled opcode: kill the first register (dest-first convention).
            if regs:
                kill(regs[0])
            pending = None
    return state, complete


def scan_method_flow(
    blocks: Sequence[FlowBlock] | Iterable[SInstruction],
    entry_state: Mapping[int, frozenset] | None = None,
    sink_args: Mapping[tuple[str, str, str | None], tuple[int, ...]] | None = None,
    entry_fields: Mapping[tuple[str, str, str], frozenset] | None = None,
) -> MethodFlowScan:
    """Bounded block-aware register-provenance scan of one method.

    One pass per block with union join at block entries. Cycles and unresolved
    edges mark the scan incomplete; absence of evidence is claimed only for
    complete scans. ``entry_state`` seeds register provenance (e.g. caller
    arguments of an IPC entry point); ``sink_args`` maps
    (class, method, descriptor-or-None) to argument positions whose external
    provenance is reported as external-input-argument sink flow.
    """
    items = list(blocks)
    if items and not isinstance(items[0], FlowBlock):
        material = [FlowBlock(0, tuple(items), ())]  # type: ignore[list-item]
    else:
        material = items  # type: ignore[assignment]
    if not material:
        return MethodFlowScan(complete=True, evidence={})
    by_start = {b.start: b for b in material}
    if len(by_start) != len(material):
        return MethodFlowScan(complete=False, evidence={})
    invokes: dict[int, tuple[str, str, tuple[frozenset, ...]]] = {}
    evidence: dict[str, list[FlowEvidence]] = {}
    sink_flows: list[FlowEvidence] = []
    call_records: list[CallRecord] = []
    field_flags = [False]
    key_seed = [0]
    complete = True

    preds: dict[int, set[int]] = {s: set() for s in by_start}
    for block in material:
        for succ in block.successors:
            if succ in preds:
                preds[succ].add(block.start)
            else:
                complete = False  # unresolved successor edge
    entry = min(by_start)
    in_states: dict[int, dict[int, frozenset]] = {entry: dict(entry_state or {})}
    field_states: dict[int, dict[tuple[str, str, str], frozenset]] = {
        entry: dict(entry_fields or {})}
    out_field_states: list[dict] = []
    processed: set[int] = set()
    ready = deque(sorted(s for s in by_start if not (preds[s] - {s}) or s == entry))
    while True:
        while ready:
            start = ready.popleft()
            if start in processed:
                continue
            processed.add(start)
            block = by_start[start]
            out_fields = dict(field_states.get(start, {}))
            out, ok = _scan_block(block, in_states.get(start, {}), invokes, evidence,
                                   key_seed, sink_args, sink_flows,
                                   field_state=out_fields, calls=call_records,
                                   field_flags=field_flags)
            complete = complete and ok
            out_field_states.append(out_fields)
            for succ in block.successors:
                if succ not in by_start:
                    continue
                if succ in processed:
                    # Back edge: provenance merged after the successor was scanned
                    # cannot propagate with one pass per block, so this scan
                    # cannot support absence claims.
                    complete = False
                merged: dict[int, set] = {}
                for reg, origins in in_states.get(succ, {}).items():
                    merged.setdefault(reg, set()).update(origins)
                for reg, origins in out.items():
                    merged.setdefault(reg, set()).update(origins)
                in_states[succ] = {reg: frozenset(o) for reg, o in merged.items()}
                merged_fields: dict[tuple[str, str, str], set] = {}
                for ref, origins in field_states.get(succ, {}).items():
                    merged_fields.setdefault(ref, set()).update(origins)
                for ref, origins in out_fields.items():
                    merged_fields.setdefault(ref, set()).update(origins)
                field_states[succ] = {ref: frozenset(o) for ref, o in merged_fields.items()}
                if succ not in processed and succ not in ready and preds[succ] <= processed:
                    ready.append(succ)
        leftover = [s for s in by_start if s not in processed]
        if not leftover:
            break
        # Cycles: blocks whose predecessors never all processed. Scan them once
        # with the partial in-state; one-pass results over a cycle cannot
        # support absence claims, so the scan is incomplete by construction.
        complete = False
        ready.append(min(leftover))
    summary: dict[tuple[str, str, str], set] = {}
    for states in out_field_states:
        for ref, origins in states.items():
            summary.setdefault(ref, set()).update(origins)
    return MethodFlowScan(complete=complete,
                          evidence={k: tuple(v) for k, v in evidence.items()},
                          sink_flows=tuple(sink_flows),
                          field_summary={ref: frozenset(o) for ref, o in summary.items()},
                          calls=tuple(call_records),
                          field_dependent=field_flags[0])


def flow_scan_from_androguard(vm, encoded_method) -> tuple[FlowBlock, ...] | None:
    """Adapt an androguard EncodedMethod into CFG blocks (APK runner only)."""
    code = encoded_method.get_code()
    if code is None:
        return None
    from androguard.core.analysis.analysis import MethodAnalysis
    from androguard.core.dex.dex_types import Operand
    # androguard 4.x encodes the const-string operand as (257, string-table index);
    # resolve it through the DEX string table, cached per vm.
    string_table = getattr(vm, "_secrets_string_table", None)
    if string_table is None:
        string_table = vm.get_strings()
        vm._secrets_string_table = string_table
    analysis = MethodAnalysis(vm, encoded_method)
    raw_blocks = list(analysis.get_basic_blocks().get())
    if not raw_blocks:
        return None
    blocks: list[FlowBlock] = []
    for raw_block in raw_blocks:
        raw_instructions = list(raw_block.get_instructions())
        # Switch/array payload pseudo-blocks hold data, not executable code, and
        # carry no CFG edges; including them would falsely mark scans incomplete.
        if raw_instructions and all(
            i.get_name().endswith("-payload") for i in raw_instructions
        ):
            continue
        instructions: list[SInstruction] = []
        offset = raw_block.get_start()
        for ins in raw_block.get_instructions():
            opcode = ins.get_name()
            literal = None
            branch_target = None
            const_value = None
            try:
                operands = ins.get_operands()
                registers = tuple(int(item[1]) for item in operands if item and item[0] == Operand.REGISTER)
                if opcode.startswith(("if-", "goto")):
                    # androguard encodes branch targets in 16-bit code units
                    # relative to the instruction; our offsets are bytes.
                    rel = next((int(item[1]) for item in operands
                                if item and item[0] == Operand.OFFSET), None)
                    if rel is not None:
                        branch_target = offset + 2 * rel
                elif opcode.startswith("const") and not opcode.startswith("const-string"):
                    const_value = next((int(item[1]) for item in operands
                                        if item and item[0] == Operand.LITERAL), None)
                if opcode.startswith("const-string"):
                    index = next((int(item[1]) for item in operands
                                  if item and item[0] != Operand.REGISTER), None)
                    if index is not None and 0 <= index < len(string_table):
                        literal = string_table[index]
            except Exception:
                registers = ()
                opcode = opcode + "|unparsed"
            target = None
            descriptor = None
            field_ref = None
            if opcode.startswith("invoke-"):
                match = _INVOKE_RE.search(ins.get_output())
                if match:
                    target = match.group(1), match.group(2)
                    # androguard renders descriptors with spaces after ';' and ',';
                    # normalise to the compact JVM form used by sink catalogues.
                    descriptor = re.sub(r"\s+", "", match.group(3))
            elif opcode.startswith(("iput", "iget", "sput", "sget")):
                # e.g. 'iput v0, v1, Lcom/x;->key [B' → (Lcom/x;, key, [B)
                match = _FIELD_RE.search(ins.get_output())
                if match:
                    field_ref = (match.group(1), match.group(2),
                                 re.sub(r"\s+", "", match.group(3)))
            instructions.append(SInstruction(
                offset=offset,
                opcode=opcode,
                registers=registers,
                literal=literal,
                invoke_class=target[0] if target else None,
                invoke_method=target[1] if target else None,
                invoke_descriptor=descriptor,
                field_ref=field_ref,
                is_static=opcode.startswith("invoke-static"),
                unsupported=opcode.endswith("|unparsed") or (
                    opcode.startswith("invoke-") and target is None) or (
                    opcode.startswith(("iput", "iget", "sput", "sget")) and field_ref is None),
                branch_target=branch_target,
                const_value=const_value,
            ))
            offset += ins.get_length()
        successors = tuple(sorted(
            edge[2].get_start() for edge in raw_block.get_next()
            if len(edge) >= 3 and edge[2] is not None
        ))
        blocks.append(FlowBlock(raw_block.get_start(), tuple(instructions), successors))
    return tuple(blocks)
