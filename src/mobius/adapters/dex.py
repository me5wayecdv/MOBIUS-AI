"""Build a bounded, provenance-aware call graph from every APK DEX entry."""
from __future__ import annotations
import re
import zipfile
from dataclasses import asdict, dataclass, field
from io import BytesIO
from ..core.reachability import Boundary, CallGraph, CallTarget, MethodRef
from ..core.dataflow import (DataFlowFinding, FlowBlock, FlowInstruction, MethodFlow, analyse_method, is_source_api, is_sink_api)

MAX_METHODS = 50_000
MAX_STRING_CONSTANTS = 25
MAX_FLOW_METHOD_BYTES = 4 * 1024
MAX_DEX_BYTES = 64 * 1024 * 1024
MAX_TOTAL_DEX_BYTES = 256 * 1024 * 1024
_DEX_ENTRY = re.compile(r"^classes\d*\.dex$")
_REFERENCE = re.compile(r"(L[^;]+;)->([^\(\s]+)(\([^)]*\).*)?$")

class DexIndexError(Exception):
    """The APK or all available DEX entries could not be indexed."""

@dataclass(frozen=True, slots=True)
class DexCoverage:
    entry: str
    status: str  # indexed | failed | skipped | truncated
    size_bytes: int
    classes: int = 0
    methods: int = 0
    error: str | None = None
    def describe(self) -> dict[str, object]:
        return asdict(self)

@dataclass(frozen=True, slots=True)
class CodeIndex:
    graph: CallGraph
    boundary: Boundary
    classes: tuple[str, ...] = ()
    methods: int = 0
    truncated: bool = False
    strings: dict[MethodRef, tuple[str, ...]] = field(default_factory=dict)
    dex_coverage: tuple[DexCoverage, ...] = ()
    class_sources: dict[str, tuple[str, ...]] = field(default_factory=dict)
    method_sources: dict[MethodRef, tuple[str, ...]] = field(default_factory=dict)
    data_flows: tuple[DataFlowFinding, ...] = ()
    data_flow_methods: int = 0
    data_flow_truncated_methods: int = 0
    data_flow_complete: bool = True
    data_flow_limitations: tuple[str, ...] = ()
    @property
    def complete(self) -> bool:
        return bool(self.dex_coverage) and all(x.status == "indexed" for x in self.dex_coverage) and not self.truncated
    def describe(self) -> dict[str, object]:
        return {
            "classes": len(self.classes), "methods": self.methods,
            "graph_nodes": len(self.graph),
            "internal_calls": sum(len(v) for v in self.graph.edges.values()),
            "truncated": self.truncated, "complete": self.complete,
            "dex_files": len(self.dex_coverage),
            "dex_indexed": sum(x.status == "indexed" for x in self.dex_coverage),
            "dex_failed": sum(x.status == "failed" for x in self.dex_coverage),
            "dex_skipped": sum(x.status == "skipped" for x in self.dex_coverage),
            "dex_truncated": sum(x.status == "truncated" for x in self.dex_coverage),
            "data_flow_findings": len(self.data_flows),
            "data_flow_methods": self.data_flow_methods,
            "data_flow_truncated_methods": self.data_flow_truncated_methods,
            "data_flow_complete": self.data_flow_complete,
            "data_flow_limitations": list(self.data_flow_limitations),
        }

def _dotted(descriptor: str) -> str:
    return descriptor[1:-1].replace("/", ".") if descriptor.startswith("L") and descriptor.endswith(";") else descriptor

def _parse_reference(output: str) -> tuple[str, str, str] | None:
    match = _REFERENCE.search(output.strip())
    return (match.group(1), match.group(2), match.group(3) or "") if match else None


def _instruction_effect(opcode: str, registers: tuple[int, ...]) -> tuple[int | None, tuple[int, ...], bool]:
    """Return (destination, value operands, unsupported semantics) for a small DEX subset."""
    if opcode.startswith("invoke-"):
        return None, (), False
    if opcode.startswith("move-result") or opcode == "move-exception":
        return (registers[0], (), False) if registers else (None, (), True)
    if opcode.startswith("move") and len(registers) >= 2:
        return registers[0], (registers[1],), False
    if opcode == "check-cast" and registers:
        return registers[0], (registers[0],), False
    if opcode.startswith(("const", "new-instance", "new-array", "sget")):
        return (registers[0], registers[1:] if opcode.startswith("new-array") else (), False) if registers else (None, (), True)
    if opcode.startswith(("iget", "aget", "array-length", "instance-of")):
        return (registers[0], registers[1:], False) if registers else (None, (), True)
    if opcode.startswith(("iput", "sput", "aput", "return", "if-", "packed-switch", "sparse-switch",
                          "throw", "monitor-", "fill-array-data")):
        return None, registers, False
    if opcode.startswith(("add-", "sub-", "mul-", "div-", "rem-", "and-", "or-", "xor-",
                          "shl-", "shr-", "ushr-", "neg-", "not-", "int-to-", "long-to-",
                          "float-to-", "double-to-", "cmp", "cmpl", "cmpg")):
        return (registers[0], registers[1:], False) if registers else (None, (), True)
    if opcode in {"nop", "goto", "goto/16", "goto/32"}:
        return None, (), False
    if not registers:
        return None, (), False
    return None, registers, True


def _build_method_flow(vm, encoded_method: object) -> MethodFlow | None:
    """Translate Androguard's bounded basic-block CFG into the pure core IR."""
    from androguard.core.analysis.analysis import MethodAnalysis
    from androguard.core.dex.dex_types import Operand

    code = encoded_method.get_code()
    if code is None or code.get_length() * 2 > MAX_FLOW_METHOD_BYTES:
        return None
    analysis = MethodAnalysis(vm, encoded_method)
    raw_blocks = analysis.get_basic_blocks().get()
    if not raw_blocks:
        return None
    blocks = []
    extraction_complete = True
    for raw_block in raw_blocks:
        offset = raw_block.get_start()
        instructions = []
        for instruction in raw_block.get_instructions():
            opcode = instruction.get_name()
            try:
                operands = instruction.get_operands(offset)
                registers = tuple(
                    int(item[1]) for item in operands
                    if item and item[0] == Operand.REGISTER
                )
            except Exception:
                registers = ()
                extraction_complete = False
            dest, uses, unsupported = _instruction_effect(opcode, registers)
            target = _parse_reference(instruction.get_output(offset)) if opcode.startswith("invoke-") else None
            if opcode.startswith("invoke-") and target is None:
                unsupported = True
                extraction_complete = False
            instructions.append(FlowInstruction(
                offset=offset,
                opcode=opcode,
                registers=registers,
                dest=dest,
                uses=uses,
                invoke_class=target[0] if target else None,
                invoke_method=target[1] if target else None,
                is_static=opcode.startswith("invoke-static"),
                unsupported=unsupported,
            ))
            offset += instruction.get_length()
        successors = tuple(sorted(item.get_start() for item in raw_block.get_next()))
        blocks.append(FlowBlock(raw_block.get_start(), tuple(instructions), successors))
    method_ref = MethodRef(
        _dotted(encoded_method.get_class_name()),
        encoded_method.get_name(),
        encoded_method.get_descriptor(),
    )
    return MethodFlow(method_ref, tuple(blocks), min(item.start for item in blocks), extraction_complete)

def index_apk(apk_bytes: bytes, *, max_methods: int = MAX_METHODS) -> CodeIndex:
    """Index root-level classes*.dex entries and account for every discovered entry."""
    try:
        with zipfile.ZipFile(BytesIO(apk_bytes)) as archive:
            names = [n for n in archive.namelist() if _DEX_ENTRY.fullmatch(n)]
            if not names:
                raise DexIndexError("APK contains no classes*.dex")
            if len(names) != len(set(names)):
                raise DexIndexError("APK contains duplicate classes*.dex ZIP entry names")
            sources = []
            total = 0
            for name in sorted(names):
                info = archive.getinfo(name)
                total += info.file_size
                if info.file_size > MAX_DEX_BYTES:
                    raise DexIndexError(f"{name} is larger than {MAX_DEX_BYTES} bytes")
                if total > MAX_TOTAL_DEX_BYTES:
                    raise DexIndexError(f"total DEX expansion exceeds {MAX_TOTAL_DEX_BYTES} bytes")
                sources.append((name, archive.read(name)))
    except DexIndexError:
        raise
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise DexIndexError(f"cannot read APK: {exc}") from exc
    return _index(sources, max_methods)

def index_dex(*blobs: bytes, max_methods: int = MAX_METHODS) -> CodeIndex:
    """Index one or more bare DEX blobs."""
    if not blobs:
        raise DexIndexError("no dex supplied")
    return _index([(f"classes{i + 1}.dex", blob) for i, blob in enumerate(blobs)], max_methods)

def _index(sources: list[tuple[str, bytes]], max_methods: int) -> CodeIndex:
    from androguard.core.dex import DEX
    if max_methods < 1:
        raise ValueError("max_methods must be at least 1")
    defined, all_methods = set(), set()
    calls, strings = {}, {}
    class_sources, method_sources = {}, {}
    coverage = []
    flow_candidates = []
    source_methods = set()
    sink_methods = set()
    method_count = 0
    budget_exhausted = False
    for entry, raw in sources:
        if budget_exhausted:
            coverage.append(DexCoverage(entry, "skipped", len(raw), error="global method budget exhausted"))
            continue
        if len(raw) > MAX_DEX_BYTES:
            coverage.append(DexCoverage(entry, "failed", len(raw), error=f"exceeds {MAX_DEX_BYTES} byte limit"))
            continue
        try:
            dex = DEX(raw)
            entry_classes, entry_methods = set(), 0
            for cls in dex.get_classes():
                name = _dotted(cls.get_name())
                defined.add(name)
                entry_classes.add(name)
                class_sources.setdefault(name, set()).add(entry)
                for method in cls.get_methods():
                    if method_count >= max_methods:
                        budget_exhausted = True
                        break
                    method_count += 1
                    entry_methods += 1
                    ref = MethodRef(name, method.get_name(), method.get_descriptor())
                    all_methods.add(ref)
                    method_sources.setdefault(ref, set()).add(entry)
                    code = method.get_code()
                    if code is None:
                        continue
                    literals = []
                    has_source = False
                    has_sink = False
                    for instruction in code.get_bc().get_instructions():
                        opcode = instruction.get_name()
                        if opcode.startswith("invoke"):
                            parsed = _parse_reference(instruction.get_output())
                            if parsed:
                                calls.setdefault(ref, set()).add((parsed[0], parsed[1]))
                                has_source = has_source or is_source_api(parsed[0], parsed[1])
                                has_sink = has_sink or is_sink_api(parsed[0], parsed[1])
                        elif opcode.startswith("const-string") and len(literals) < MAX_STRING_CONSTANTS:
                            literal = instruction.get_output().split(",", 1)[-1].strip().strip('"')
                            if literal:
                                literals.append(literal)
                    if literals:
                        strings[ref] = tuple(dict.fromkeys((*strings.get(ref, ()), *literals)))
                    if has_source:
                        source_methods.add(ref)
                    if has_sink:
                        sink_methods.add(ref)
                    if has_source and has_sink:
                        flow_candidates.append((dex, method))
                if budget_exhausted:
                    break
            coverage.append(DexCoverage(
                entry, "truncated" if budget_exhausted else "indexed",
                len(raw), len(entry_classes), entry_methods,
                "global method budget exhausted" if budget_exhausted else None))
        except Exception as exc:
            coverage.append(DexCoverage(entry, "failed", len(raw), error=f"cannot parse: {type(exc).__name__}: {exc}"))
    # A DEX parsed up to the method budget is a valid partial index.
    if not any(x.status in {"indexed", "truncated"} for x in coverage):
        details = "; ".join(f"{x.entry}: {x.error or x.status}" for x in coverage)
        raise DexIndexError(f"no DEX entry could be indexed ({details})")
    edges = {m: () for m in all_methods}
    boundary = {}
    for caller, targets in calls.items():
        internal, external = set(), set()
        for class_descriptor, method_name in targets:
            target_class = _dotted(class_descriptor)
            if target_class in defined:
                internal.add(MethodRef(target_class, method_name))
            else:
                external.add(CallTarget(class_descriptor, method_name))
        if internal:
            edges[caller] = tuple(sorted(internal))
        if external:
            boundary[caller] = tuple(sorted(external, key=lambda c: (c.class_descriptor, c.method)))
    data_flows: list[DataFlowFinding] = []
    data_flow_limitations: set[str] = set()
    data_flow_truncated_methods = 0
    data_flow_methods = 0
    if source_methods and sink_methods and not (source_methods & sink_methods):
        data_flow_limitations.add("source and sink occur in different methods; interprocedural propagation is not implemented")
    if len(flow_candidates) > 2000:
        data_flow_limitations.add("candidate method budget exceeded (2000)")
        flow_candidates = flow_candidates[:2000]
    for vm, encoded_method in flow_candidates:
        if len(data_flows) >= 1000:
            data_flow_limitations.add("global data-flow evidence budget exceeded (1000)")
            break
        flow = _build_method_flow(vm, encoded_method)
        if flow is None:
            data_flow_limitations.add("one or more candidate methods had no usable CFG")
            continue
        data_flow_methods += 1
        result = analyse_method(flow)
        data_flows.extend(result.findings)
        data_flow_limitations.update(result.limitations)
        if result.status == "truncated":
            data_flow_truncated_methods += 1
    if budget_exhausted:
        data_flow_limitations.add("DEX method index was truncated")
    data_flows = sorted(
        set(data_flows),
        key=lambda item: (item.method, item.source_offset, item.sink_offset, item.source_id, item.sink_id),
    )[:1000]
    return CodeIndex(
        graph=CallGraph(edges=edges, strings=strings), boundary=boundary,
        classes=tuple(sorted(defined)), methods=method_count,
        truncated=budget_exhausted, strings=strings,
        dex_coverage=tuple(coverage),
        class_sources={k: tuple(sorted(v)) for k, v in sorted(class_sources.items())},
        method_sources={k: tuple(sorted(v)) for k, v in sorted(method_sources.items())},
        data_flows=tuple(data_flows),
        data_flow_methods=data_flow_methods,
        data_flow_truncated_methods=data_flow_truncated_methods,
        data_flow_complete=not data_flow_limitations,
        data_flow_limitations=tuple(sorted(data_flow_limitations)),
    )
