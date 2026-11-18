"""Bounded, conservative intra-procedural DEX taint analysis.

Results are candidate evidence only. They never confirm a finding or prove exploitability.
The engine deliberately models a small set of value-preserving operations and reports
unsupported tainted operations instead of guessing.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Literal

from .reachability import MethodRef
from .sinks import GUARDS, SINKS

@dataclass(frozen=True, slots=True)
class SourceSpec:
    id: str
    class_descriptor: str
    method: str
    description: str

@dataclass(frozen=True, slots=True)
class FlowInstruction:
    offset: int
    opcode: str
    registers: tuple[int, ...] = ()
    dest: int | None = None
    uses: tuple[int, ...] = ()
    invoke_class: str | None = None
    invoke_method: str | None = None
    is_static: bool = False
    unsupported: bool = False

@dataclass(frozen=True, slots=True)
class FlowBlock:
    start: int
    instructions: tuple[FlowInstruction, ...]
    successors: tuple[int, ...] = ()

@dataclass(frozen=True, slots=True)
class MethodFlow:
    method: MethodRef
    blocks: tuple[FlowBlock, ...]
    entry: int
    complete: bool = True

@dataclass(frozen=True, slots=True)
class DataFlowFinding:
    method: MethodRef
    source_id: str
    sink_id: str
    source_offset: int
    sink_offset: int
    sink_register: int
    guard_ids_before: tuple[str, ...] = ()
    guard_ids_after: tuple[str, ...] = ()
    guard_dominates_sink: bool = False
    guard_outcome_verified: bool = False
    assertion: Literal["may-flow"] = "may-flow"

    def describe(self) -> dict[str, object]:
        return {
            "method": {
                "class_name": self.method.class_name,
                "name": self.method.name,
                "descriptor": self.method.descriptor,
            },
            "source_id": self.source_id,
            "sink_id": self.sink_id,
            "source_offset": self.source_offset,
            "sink_offset": self.sink_offset,
            "sink_register": self.sink_register,
            "guard_ids_before": list(self.guard_ids_before),
            "guard_ids_after": list(self.guard_ids_after),
            "guard_dominates_sink": self.guard_dominates_sink,
            "guard_outcome_verified": self.guard_outcome_verified,
            "assertion": self.assertion,
        }

@dataclass(frozen=True, slots=True)
class DataFlowResult:
    status: Literal["flow-found", "no-flow", "incomplete", "truncated"]
    findings: tuple[DataFlowFinding, ...] = ()
    complete: bool = False
    blocks_visited: int = 0
    instructions_visited: int = 0
    limitations: tuple[str, ...] = ()

_SOURCES = (
    SourceSpec("intent-string-extra", "Landroid/content/Intent;", "getStringExtra",
               "Intent extra value; external caller control is not established"),
    SourceSpec("intent-charsequence-extra", "Landroid/content/Intent;", "getCharSequenceExtra",
               "Intent character data; external caller control is not established"),
    SourceSpec("intent-data", "Landroid/content/Intent;", "getData",
               "URI value obtained from an Intent; caller provenance is not established"),
    SourceSpec("intent-data-string", "Landroid/content/Intent;", "getDataString",
               "URI string obtained from an Intent; caller provenance is not established"),
    SourceSpec("uri-query-parameter", "Landroid/net/Uri;", "getQueryParameter",
               "URI query parameter; external provenance is not established"),
    SourceSpec("uri-last-path-segment", "Landroid/net/Uri;", "getLastPathSegment",
               "URI path segment; external provenance is not established"),
)
SOURCE_CATALOGUE = {(item.class_descriptor, item.method): item for item in _SOURCES}

# Parameter positions are zero-based and exclude the receiver for instance methods.
# Keep this intentionally small: only direct argument sinks are modelled in this slice.
_SINK_ARGUMENTS = {
    ("Landroid/webkit/WebView;", "loadUrl"): (0, "webview-load"),
    ("Landroid/database/sqlite/SQLiteDatabase;", "rawQuery"): (0, "raw-sql"),
    ("Ljava/lang/Runtime;", "exec"): (0, "process-exec"),
    ("Ljava/io/FileOutputStream;", "<init>"): (0, "file-write"),
    ("Ljava/io/FileWriter;", "<init>"): (0, "file-append"),
}
_GUARD_IDS = {key: guard.id for key, guard in GUARDS.items()}

def source_for(class_descriptor: str, method: str) -> SourceSpec | None:
    return SOURCE_CATALOGUE.get((class_descriptor, method))

def is_source_api(class_descriptor: str, method: str) -> bool:
    return (class_descriptor, method) in SOURCE_CATALOGUE

def is_sink_api(class_descriptor: str, method: str) -> bool:
    return (class_descriptor, method) in _SINK_ARGUMENTS

def is_flow_api(class_descriptor: str, method: str) -> bool:
    return (is_source_api(class_descriptor, method)
            or is_sink_api(class_descriptor, method)
            or (class_descriptor, method) in _GUARD_IDS)

def _sink_argument(class_descriptor: str, method: str) -> tuple[int, str] | None:
    spec = _SINK_ARGUMENTS.get((class_descriptor, method))
    if spec is None:
        return None
    argument_index, sink_id = spec
    # The catalogue remains the authority for sink identity.
    if not any(sink.id == sink_id for sink in SINKS.values()):
        return None
    return argument_index, sink_id

def _join(states: list[dict[int, frozenset[tuple[str, int]]]]) -> dict[int, frozenset[tuple[str, int]]]:
    merged: dict[int, set[tuple[str, int]]] = defaultdict(set)
    for state in states:
        for register, origins in state.items():
            merged[register].update(origins)
    return {register: frozenset(origins) for register, origins in merged.items()}

def _dominators(blocks: dict[int, FlowBlock], entry: int) -> dict[int, set[int]]:
    nodes = set(blocks)
    predecessors: dict[int, set[int]] = {node: set() for node in nodes}
    for block in blocks.values():
        for successor in block.successors:
            if successor in predecessors:
                predecessors[successor].add(block.start)
    dominators = {node: ({node} if node == entry else set(nodes)) for node in nodes}
    changed = True
    while changed:
        changed = False
        for node in sorted(nodes - {entry}):
            preds = predecessors[node]
            common = set.intersection(*(dominators[p] for p in preds)) if preds else set()
            updated = {node} | common
            if updated != dominators[node]:
                dominators[node] = updated
                changed = True
    return dominators

def analyse_method(
    flow: MethodFlow,
    *,
    max_blocks: int = 256,
    max_instructions: int = 2048,
    max_iterations: int = 4096,
    max_findings: int = 100,
) -> DataFlowResult:
    """Run a bounded forward may-taint analysis over one method's CFG."""
    blocks = {block.start: block for block in flow.blocks}
    instruction_count = sum(len(block.instructions) for block in flow.blocks)
    if (not blocks or flow.entry not in blocks
            or len(blocks) > max_blocks or instruction_count > max_instructions):
        return DataFlowResult(
            "truncated", complete=False,
            limitations=("method CFG exceeded the configured block/instruction budget or had no entry block",),
        )
    if len(blocks) != len(flow.blocks):
        return DataFlowResult("incomplete", complete=False,
                              limitations=("duplicate basic-block offsets",))
    if any(successor not in blocks for block in flow.blocks for successor in block.successors):
        return DataFlowResult("incomplete", complete=False,
                              limitations=("CFG contains an unresolved successor",))

    predecessors: dict[int, set[int]] = {node: set() for node in blocks}
    for block in blocks.values():
        for successor in block.successors:
            predecessors[successor].add(block.start)

    dominators = _dominators(blocks, flow.entry)
    in_states: dict[int, dict[int, frozenset[tuple[str, int]]]] = {flow.entry: {}}
    out_states: dict[int, dict[int, frozenset[tuple[str, int]]]] = {}
    queue = deque([flow.entry])
    queued = {flow.entry}
    guard_sites: list[tuple[str, int, int]] = [
        (_GUARD_IDS[(instruction.invoke_class, instruction.invoke_method)], instruction.offset, block.start)
        for block in flow.blocks
        for instruction in block.instructions
        if instruction.invoke_class is not None
        and instruction.invoke_method is not None
        and (instruction.invoke_class, instruction.invoke_method) in _GUARD_IDS
    ]
    findings: dict[tuple[object, ...], DataFlowFinding] = {}
    finding_budget_exhausted = False
    limitations = set()
    if not flow.complete:
        limitations.add("DEX method/CFG extraction was incomplete (including exception edges or operand decoding)")
    iterations = 0
    instructions_seen = 0

    while queue:
        iterations += 1
        if iterations > max_iterations:
            return DataFlowResult(
                "truncated", tuple(findings.values()), False, len(out_states),
                instructions_seen, tuple(sorted(limitations | {"data-flow fixed-point iteration budget exhausted"})),
            )
        block_id = queue.popleft()
        queued.discard(block_id)
        block = blocks[block_id]
        incoming = _join([out_states[p] for p in sorted(predecessors[block_id]) if p in out_states])
        if block_id == flow.entry:
            incoming = _join([incoming, in_states.get(flow.entry, {})])
        state = dict(incoming)
        pending_result: frozenset[tuple[str, int]] = frozenset()

        for instruction in block.instructions:
            instructions_seen += 1
            opcode = instruction.opcode
            invoke_key = (instruction.invoke_class, instruction.invoke_method)
            source = source_for(*invoke_key) if all(invoke_key) else None

            if instruction.invoke_class and instruction.invoke_method:
                sink_spec = _sink_argument(instruction.invoke_class, instruction.invoke_method)
                if sink_spec:
                    parameter_index, sink_id = sink_spec
                    argument_register_index = parameter_index + (0 if instruction.is_static else 1)
                    if argument_register_index < len(instruction.registers):
                        sink_register = instruction.registers[argument_register_index]
                        for source_id, source_offset in sorted(state.get(sink_register, frozenset())):
                            before = tuple(sorted({
                                gid for gid, offset, _ in guard_sites if offset < instruction.offset
                            }))
                            after = tuple(sorted({
                                gid for gid, offset, _ in guard_sites if offset > instruction.offset
                            }))
                            dominating = any(
                                offset < instruction.offset and guard_block in dominators.get(block_id, set())
                                for gid, offset, guard_block in guard_sites if gid in before
                            )
                            finding = DataFlowFinding(
                                method=flow.method,
                                source_id=source_id,
                                sink_id=sink_id,
                                source_offset=source_offset,
                                sink_offset=instruction.offset,
                                sink_register=sink_register,
                                guard_ids_before=before,
                                guard_ids_after=after,
                                guard_dominates_sink=dominating,
                            )
                            key = (source_id, source_offset, sink_id, instruction.offset, sink_register)
                            findings[key] = finding
                            if len(findings) >= max_findings:
                                finding_budget_exhausted = True
                                limitations.add("data-flow finding budget exhausted")
                                break
                    else:
                        limitations.add("sink call register operands were incomplete")
                if source:
                    pending_result = frozenset({(source.id, instruction.offset)})
                elif (instruction.invoke_class, instruction.invoke_method) == ("Ljava/lang/StringBuilder;", "append"):
                    receiver = instruction.registers[0] if instruction.registers and not instruction.is_static else None
                    tainted = frozenset().union(*(state.get(r, frozenset()) for r in instruction.registers[1:]))
                    if receiver is not None and tainted:
                        state[receiver] = state.get(receiver, frozenset()) | tainted
                    pending_result = tainted
                elif (instruction.invoke_class, instruction.invoke_method) == ("Ljava/lang/StringBuilder;", "toString"):
                    receiver = instruction.registers[0] if instruction.registers and not instruction.is_static else None
                    pending_result = state.get(receiver, frozenset()) if receiver is not None else frozenset()
                elif (instruction.invoke_class, instruction.invoke_method) == ("Landroid/net/Uri;", "toString"):
                    receiver = instruction.registers[0] if instruction.registers and not instruction.is_static else None
                    pending_result = state.get(receiver, frozenset()) if receiver is not None else frozenset()
                elif instruction.invoke_class == "Ljava/lang/String;" and instruction.invoke_method in {
                    "concat", "substring", "trim", "replace", "replaceAll", "toLowerCase", "toUpperCase"
                }:
                    pending_result = frozenset().union(*(state.get(r, frozenset()) for r in instruction.registers))
                elif instruction.invoke_class == "Ljava/lang/String;" and instruction.invoke_method == "valueOf":
                    pending_result = frozenset().union(*(state.get(r, frozenset()) for r in instruction.registers))
                else:
                    tainted_args = set().union(*(state.get(r, frozenset()) for r in instruction.registers))
                    if tainted_args and not sink_spec:
                        limitations.add("tainted value passed to an unsupported call; interprocedural summaries are not implemented")
                    pending_result = frozenset()
                continue

            if opcode.startswith("move-result"):
                if instruction.dest is not None:
                    if pending_result:
                        state[instruction.dest] = pending_result
                    else:
                        state.pop(instruction.dest, None)
                pending_result = frozenset()
                continue

            pending_result = frozenset()
            if instruction.unsupported:
                touched = set(instruction.registers) | set(instruction.uses)
                if any(state.get(register) for register in touched):
                    limitations.add(f"tainted value used by unsupported opcode {opcode}")
                # Unknown write semantics must not leave stale taint in a register.
                for register in touched:
                    state.pop(register, None)
                if instruction.dest is not None:
                    state.pop(instruction.dest, None)
                continue

            if instruction.dest is not None:
                if opcode.startswith("move") or opcode == "check-cast":
                    origins = frozenset().union(*(state.get(register, frozenset()) for register in instruction.uses))
                elif instruction.uses:
                    origins = frozenset().union(*(state.get(register, frozenset()) for register in instruction.uses))
                else:
                    origins = frozenset()
                if origins:
                    state[instruction.dest] = origins
                else:
                    state.pop(instruction.dest, None)
            elif opcode.startswith(("iput", "sput", "aput", "return", "throw", "fill-array-data")) and any(
                state.get(register) for register in instruction.uses
            ):
                limitations.add("tainted value escaped through a field, array, or method return; memory/interprocedural flow is not modelled")

        previous = out_states.get(block_id)
        out_states[block_id] = state
        if previous != state:
            for successor in block.successors:
                if successor not in queued:
                    queue.append(successor)
                    queued.add(successor)

    complete = flow.complete and not limitations and not finding_budget_exhausted
    ordered = tuple(sorted(findings.values(), key=lambda item: (
        item.method, item.source_offset, item.sink_offset, item.source_id, item.sink_id
    )))
    status: Literal["flow-found", "no-flow", "incomplete", "truncated"] = (
        "truncated" if finding_budget_exhausted else
        "flow-found" if ordered else "no-flow" if complete else "incomplete"
    )
    return DataFlowResult(status, ordered, complete, len(out_states), instructions_seen,
                          tuple(sorted(limitations)))
