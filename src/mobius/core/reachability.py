"""Bounded reachability over an application's own call graph.

Layer 1: no dex, no I/O. The adapter produces a `CallGraph`; everything here is a total
function over it, so the reasoning can be tested exhaustively without an APK.

Three ways this refuses to overclaim:

1. **Truncation is not refutation.** If the search hits its depth or node budget without
   finding a sink, the answer is `truncated` - which yields `sink_reachable: None`, never
   `False`. A limited search that found nothing has found nothing; it has not shown absence.
   Only a *complete* traversal with no sink produces `not-reached`, which is what lets a gate
   reject a candidate with `not-reachable`.
2. **Guards refute the clause, they do not prove safety.** A `checkCallingPermission` call on
   the path means we cannot claim the check is absent. It does not mean the check is correct,
   bypassable-free, or applied to the right permission - that would be a different claim
   requiring different evidence.
3. **The graph holds application code only.** Framework classes appear as sink or guard
   targets, never as traversable nodes, so the search cannot wander through the platform and
   manufacture a path.

Determinism: neighbours are iterated in sorted order and the queue is FIFO, so the same graph
always yields the same path. A finding whose path changes between runs is not evidence.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable, Literal, Mapping, Sequence

from .sinks import Guard, Sink, guard_for, sink_for


@dataclass(frozen=True, slots=True, order=True)
class MethodRef:
    """A method in the target application, in a form that sorts stably."""

    class_name: str  # dotted, e.g. com.example.MainActivity
    name: str
    descriptor: str = ""

    @property
    def class_descriptor(self) -> str:
        return "L" + self.class_name.replace(".", "/") + ";"

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.class_name}->{self.name}{self.descriptor}"


@dataclass(frozen=True, slots=True)
class CallGraph:
    """Outgoing edges between application methods.

    `edges` deliberately contains only application methods as *keys*. A call to a framework
    class is not an edge - it is either a sink, a guard, or irrelevant.
    """

    edges: Mapping[MethodRef, tuple[MethodRef, ...]] = field(default_factory=dict)
    #: method -> string literals it loads, used to explain why a sink matters
    strings: Mapping[MethodRef, tuple[str, ...]] = field(default_factory=dict)

    def callees(self, method: MethodRef) -> tuple[MethodRef, ...]:
        return self.edges.get(method, ())

    def methods_named(self, class_name: str, name: str) -> tuple[MethodRef, ...]:
        """Find methods by class and name, ignoring the parameter descriptor.

        Necessary because a lifecycle entry point is identified by name, while the graph
        holds the full signature: `onReceive` in a real APK is
        `onReceive(Landroid/content/Context;Landroid/content/Intent;)V`, and an equality check
        against `MethodRef(cls, "onReceive")` never matches it. Overloads are returned
        together - all of them are candidates for being called, which is the question here.
        """
        return tuple(
            sorted(
                m for m in self.edges
                if m.class_name == class_name and m.name == name
            )
        )

    def methods(self) -> tuple[MethodRef, ...]:
        return tuple(self.edges)

    def callers_of(self, target: MethodRef) -> tuple[MethodRef, ...]:
        """Return application methods with a direct edge to target, in stable order."""
        return tuple(sorted(
            caller for caller, callees in self.edges.items()
            if target in callees
        ))

    def __len__(self) -> int:
        return len(self.edges)


SearchStatus = Literal["reached", "not-reached", "truncated", "no-entry-point"]


@dataclass(frozen=True, slots=True)
class ReachabilityResult:
    status: SearchStatus
    sink: Sink | None = None
    path: tuple[MethodRef, ...] = ()
    guards: tuple[Guard, ...] = ()
    visited: int = 0
    #: True when the traversal finished without exhausting its budget
    exhaustive: bool = False

    @property
    def reached(self) -> bool:
        return self.status == "reached"

    @property
    def truncated(self) -> bool:
        return self.status == "truncated"

    @property
    def guarded(self) -> bool:
        return bool(self.guards)

    def attributes(self) -> dict[str, bool | None]:
        """Gate attributes this result can support, and `None` where it supports none.

        `None` is not a third truth value for convenience: it is the statement "this search
        did not establish either answer", which the gate reports as missing evidence.
        """
        # Never False. A complete search that finds no catalogued sink is a fact about the
        # search (see `exhaustive` and `visited`), not evidence that no sink is reachable: the
        # catalogue is not known to be complete and callbacks, inter-component flows,
        # reflection and data flow are not modelled. Only independent refuting evidence could
        # justify False, and none exists in this engine.
        sink_reachable: bool | None = True if self.status == "reached" else None

        # "No caller check on the path" is only meaningful if there *is* a path. On a search
        # that found no sink this was reporting `True` - a claim about a call chain that does
        # not exist. Absence of a path cannot establish absence of a check.
        if self.status == "reached" and not self.truncated:
            caller_check_absent: bool | None = not self.guarded
        else:
            caller_check_absent = None
        return {
            "sink_reachable": sink_reachable,
            "caller_check_absent": caller_check_absent,
        }

    def explain(self) -> str:
        if self.status == "no-entry-point":
            return "no lifecycle entry point found for this component in the application code"
        if self.status == "reached":
            hops = " -> ".join(f"{m.class_name.rsplit('.', 1)[-1]}.{m.name}" for m in self.path)
            return (
                f"reaches {self.sink.id} ({self.sink.class_descriptor}) in {len(self.path) - 1} "
                f"call hop(s): {hops}"
            )
        if self.status == "truncated":
            return (
                f"search truncated after {self.visited} method(s) without finding a sink; "
                "absence not established"
            )
        return (
            f"complete traversal of {self.visited} method(s) found no catalogued sink on direct "
            "calls from the lifecycle entry points; not determined: the sink catalogue is not "
            "known to be complete, and callbacks, inter-component flows, reflection and data flow "
            "are not modelled, so this is not a finding that the component is secure"
        )


@dataclass(frozen=True, slots=True)
class CallTarget:
    """An external call the application makes: a framework method, not an app method."""

    class_descriptor: str
    method: str


Boundary = Mapping[MethodRef, tuple[CallTarget, ...]]
"""method -> external calls it makes. The adapter fills this from invoke instructions."""


def analyse(
    graph: CallGraph,
    *,
    entry_points: Sequence[MethodRef],
    boundary: Boundary | None = None,
    max_depth: int = 8,
    max_nodes: int = 5000,
) -> ReachabilityResult:
    """Search from every entry point; return the first (shortest) sink path found.

    A path is rejected as evidence if it passes a guard: the candidate is then reported as
    reached-but-guarded, which refutes `caller_check_absent` rather than confirming a
    finding.
    """
    boundary = boundary or {}
    roots = [m for m in entry_points if m in graph.edges]
    if not roots:
        # The component's class is not in the application's dex at all: usually a manifest
        # entry pointing at a library class, or obfuscation. Not evidence of safety.
        return ReachabilityResult(status="no-entry-point")

    visited: set[MethodRef] = set()
    truncated = False
    best_guarded: ReachabilityResult | None = None

    for root in sorted(roots):
        queue: deque[tuple[MethodRef, tuple[MethodRef, ...]]] = deque([(root, (root,))])
        seen: set[MethodRef] = set()
        while queue:
            method, path = queue.popleft()
            if method in seen:
                continue
            seen.add(method)
            visited.add(method)

            if len(visited) > max_nodes:
                truncated = True
                break

            guards = tuple(
                g
                for call in boundary.get(method, ())
                if (g := guard_for(call.class_descriptor, call.method)) is not None
            )
            sink = next(
                (s for call in boundary.get(method, ()) if (s := sink_for(call.class_descriptor, call.method))),
                None,
            )

            if sink is not None:
                collected = _collect_guards(boundary, path)
                result = ReachabilityResult(
                    status="reached",
                    sink=sink,
                    path=path,
                    guards=collected,
                    visited=len(visited),
                    exhaustive=False,
                )
                if not collected:
                    return result
                # Remember the guarded hit and keep looking for an unguarded one.
                if best_guarded is None or len(path) < len(best_guarded.path):
                    best_guarded = result

            if len(path) > max_depth:
                truncated = True
                continue
            for callee in graph.callees(method):
                if callee not in seen:
                    queue.append((callee, path + (callee,)))
        if truncated:
            break

    if best_guarded is not None:
        return best_guarded
    if truncated:
        return ReachabilityResult(status="truncated", visited=len(visited), exhaustive=False)
    return ReachabilityResult(
        status="not-reached",
        visited=len(visited),
        exhaustive=True,
        guards=_collect_guards(boundary, _all_reachable(graph, roots)),
    )


def _collect_guards(boundary: Boundary, methods: Iterable[MethodRef]) -> tuple[Guard, ...]:
    found: list[Guard] = []
    for method in methods:
        for call in boundary.get(method, ()):
            guard = guard_for(call.class_descriptor, call.method)
            if guard is not None and guard not in found:
                found.append(guard)
    return tuple(sorted(found, key=lambda g: g.id))


def _all_reachable(graph: CallGraph, roots: Iterable[MethodRef]) -> tuple[MethodRef, ...]:
    seen: set[MethodRef] = set()
    queue = deque(roots)
    while queue:
        method = queue.popleft()
        if method in seen:
            continue
        seen.add(method)
        queue.extend(graph.callees(method))
    return tuple(sorted(seen))
