"""Build a call graph from an APK's dex code.

The translation layer between androguard's dex model and the Layer-1 `CallGraph`. Kept
narrow on purpose: everything that decides whether a path *means* something lives in
`core.reachability`, and everything that decides whether it *is evidence* lives in the gate.
This module only answers "which application method calls which".

Deliberate limits, all of them reported rather than hidden:

* Only classes defined in the APK are graph nodes. A call into the framework is recorded as
  a boundary target (a candidate sink or guard), never as a traversable node, so the search
  cannot walk into platform code and invent a path.
* `MAX_METHODS` and `MAX_STRING_CONSTANTS` bound memory on large or hostile input. Hitting
  them sets `truncated`, which downstream turns into "not established" rather than "safe".
* No deobfuscation, no reflection resolution, no control-flow analysis. A call made through
  reflection is invisible here, and that is a known false-negative source (R-21).
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from io import BytesIO

from ..core.reachability import Boundary, CallGraph, CallTarget, MethodRef

MAX_METHODS = 50_000
MAX_STRING_CONSTANTS = 25
MAX_DEX_BYTES = 64 * 1024 * 1024

_DEX_ENTRY = re.compile(r"^classes\d*\.dex$")
# `invoke-*` output looks like `v0, v1, Lcom/foo/Bar;->baz(I)V`; the reference is the tail.
_REFERENCE = re.compile(r"(L[^;]+;)->([^(\s]+)(\([^)]*\).*)?$")


class DexIndexError(Exception):
    """The dex could not be read."""


@dataclass(frozen=True, slots=True)
class CodeIndex:
    graph: CallGraph
    boundary: Boundary
    classes: tuple[str, ...] = ()
    methods: int = 0
    truncated: bool = False
    strings: dict[MethodRef, tuple[str, ...]] = field(default_factory=dict)

    def describe(self) -> dict[str, object]:
        return {
            "classes": len(self.classes),
            "methods": self.methods,
            "graph_nodes": len(self.graph),
            "internal_calls": sum(len(v) for v in self.graph.edges.values()),
            "truncated": self.truncated,
        }


def _dotted(descriptor: str) -> str:
    return descriptor[1:-1].replace("/", ".") if descriptor.startswith("L") and descriptor.endswith(";") else descriptor


def _descriptor(dotted: str) -> str:
    return "L" + dotted.replace(".", "/") + ";"


def _parse_reference(output: str) -> tuple[str, str, str] | None:
    """Extract (class descriptor, method name, descriptor) from an invoke operand string."""
    match = _REFERENCE.search(output.strip())
    if not match:
        return None
    return match.group(1), match.group(2), match.group(3) or ""


def index_apk(apk_bytes: bytes, *, max_methods: int = MAX_METHODS) -> CodeIndex:
    """Parse every `classes*.dex` in the APK into a call graph."""
    try:
        archive = zipfile.ZipFile(BytesIO(apk_bytes))
    except (zipfile.BadZipFile, OSError) as exc:
        raise DexIndexError(f"cannot read APK: {exc}") from exc

    names = sorted(n for n in archive.namelist() if _DEX_ENTRY.match(n))
    if not names:
        raise DexIndexError("APK contains no classes*.dex")
    return _index([(name, archive.read(name)) for name in names], max_methods)


def index_dex(*blobs: bytes, max_methods: int = MAX_METHODS) -> CodeIndex:
    """Index one or more bare `.dex` blobs. Used by tests and by tooling that has already
    extracted the code."""
    if not blobs:
        raise DexIndexError("no dex supplied")
    return _index([(f"classes{i}.dex", blob) for i, blob in enumerate(blobs)], max_methods)


def _index(sources: list[tuple[str, bytes]], max_methods: int) -> CodeIndex:
    from androguard.core.dex import DEX

    defined: set[str] = set()
    all_methods: set[MethodRef] = set()
    calls: dict[MethodRef, set[tuple[str, str]]] = {}
    strings: dict[MethodRef, tuple[str, ...]] = {}
    method_count = 0
    truncated = False

    for entry, raw in sources:
        if len(raw) > MAX_DEX_BYTES:
            raise DexIndexError(f"{entry} is larger than {MAX_DEX_BYTES} bytes")
        try:
            dex = DEX(raw)
        except Exception as exc:  # androguard raises a variety of internal errors
            raise DexIndexError(f"cannot parse {entry}: {exc}") from exc

        for cls in dex.get_classes():
            class_dotted = _dotted(cls.get_name())
            defined.add(class_dotted)
            for method in cls.get_methods():
                if method_count >= max_methods:
                    truncated = True
                    break
                method_count += 1
                ref = MethodRef(class_dotted, method.get_name(), method.get_descriptor())
                all_methods.add(ref)
                code = method.get_code()
                if code is None:
                    continue
                literals: list[str] = []
                for instruction in code.get_bc().get_instructions():
                    opcode = instruction.get_name()
                    if opcode.startswith("invoke"):
                        parsed = _parse_reference(instruction.get_output())
                        if parsed:
                            calls.setdefault(ref, set()).add((parsed[0], parsed[1]))
                    elif opcode.startswith("const-string") and len(literals) < MAX_STRING_CONSTANTS:
                        literal = instruction.get_output().split(",", 1)[-1].strip().strip('"')
                        if literal:
                            literals.append(literal)
                if literals:
                    strings[ref] = tuple(literals)
            if truncated:
                break
        if truncated:
            break

    # Split internal edges from boundary calls once `defined` is complete: a call to a class
    # that appears later in the dex must not be mistaken for a framework call.
    # Seed a node for every application method. A lifecycle method that only calls framework
    # APIs makes no internal call, and if it were absent from the graph it would look like a
    # method that does not exist - which is how a real exported receiver was reported as
    # "no entry point" during validation against a real APK (RL-006).
    edges: dict[MethodRef, tuple[MethodRef, ...]] = {m: () for m in all_methods}
    boundary: dict[MethodRef, tuple[CallTarget, ...]] = {}
    for caller, targets in calls.items():
        internal: set[MethodRef] = set()
        external: set[CallTarget] = set()
        for class_descriptor, method_name in targets:
            callee_class = _dotted(class_descriptor)
            if callee_class in defined:
                internal.add(MethodRef(callee_class, method_name))
            else:
                external.add(CallTarget(class_descriptor, method_name))
        if internal:
            edges[caller] = tuple(sorted(internal))
        if external:
            boundary[caller] = tuple(sorted(external, key=lambda c: (c.class_descriptor, c.method)))

    return CodeIndex(
        graph=CallGraph(edges=edges, strings=strings),
        boundary=boundary,
        classes=tuple(sorted(defined)),
        methods=method_count,
        truncated=truncated,
        strings=strings,
    )
