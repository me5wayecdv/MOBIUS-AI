"""The reachability engine, tested without a single APK.

These tests are the reason the engine is in Layer 1: given a hand-built graph, every branch
of the reasoning is exercisable directly, including the ones that only occur on hostile or
pathological input.

The invariant worth reading first is `test_truncation_never_reports_absence`: a bounded
search that gives up must not be able to say "no sink". That single property is what keeps
the tool from turning its own budget into a clean bill of health.
"""

from __future__ import annotations

import pytest

from mobius.core.reachability import CallGraph, CallTarget, MethodRef, analyse

FO = ("Ljava/io/FileOutputStream;", "<init>")
CHECK = ("Landroid/content/Context;", "checkCallingPermission")


def M(cls: str, name: str) -> MethodRef:
    return MethodRef(cls, name)


def build(edges: dict[MethodRef, list[MethodRef]] | None = None,
          boundary: dict[MethodRef, list[tuple[str, str]]] | None = None) -> tuple[CallGraph, dict]:
    graph = CallGraph(edges={k: tuple(v) for k, v in (edges or {}).items()})
    b = {k: tuple(CallTarget(c, m) for c, m in v) for k, v in (boundary or {}).items()}
    return graph, b


def test_direct_call_to_a_sink_is_reached():
    root = M("com.x.A", "onCreate")
    graph, boundary = build(
        edges={root: []},
        boundary={root: [FO]},
    )
    result = analyse(graph, entry_points=[root], boundary=boundary)
    assert result.reached and result.status == "reached"
    assert result.sink is not None and result.sink.id == "file-write"
    assert result.path == (root,)
    assert result.attributes() == {"sink_reachable": True, "caller_check_absent": True}


def test_sink_reached_through_one_internal_hop():
    root, helper = M("com.x.A", "onCreate"), M("com.x.A", "writeFile")
    graph, boundary = build(
        edges={root: [helper], helper: []},
        boundary={helper: [FO]},
    )
    result = analyse(graph, entry_points=[root], boundary=boundary)
    assert result.reached
    assert result.path == (root, helper)
    assert result.explain().startswith("reaches file-write")


def test_guard_on_the_path_refutes_caller_check_absent():
    root, helper = M("com.x.A", "onCreate"), M("com.x.A", "writeFile")
    graph, boundary = build(
        edges={root: [helper], helper: []},
        boundary={root: [CHECK], helper: [FO]},
    )
    result = analyse(graph, entry_points=[root], boundary=boundary)
    assert result.reached
    assert result.guarded
    assert [g.id for g in result.guards] == ["check-calling-permission"]
    attrs = result.attributes()
    assert attrs["sink_reachable"] is True
    assert attrs["caller_check_absent"] is False


def test_guard_off_the_path_is_not_counted():
    """A permission check in a sibling method that the sink path never executes must not be
    used to explain away a finding."""
    root, path_method, other = M("com.x.A", "onCreate"), M("com.x.A", "go"), M("com.x.A", "unrelated")
    graph, boundary = build(
        edges={root: [path_method, other], path_method: [], other: []},
        boundary={path_method: [FO], other: [CHECK]},
    )
    result = analyse(graph, entry_points=[root], boundary=boundary)
    assert result.reached
    assert result.guards == ()
    assert result.attributes()["caller_check_absent"] is True


def test_complete_search_without_a_sink_is_a_real_refutation():
    root, helper = M("com.x.A", "onCreate"), M("com.x.A", "go")
    graph, boundary = build(edges={root: [helper], helper: []})
    result = analyse(graph, entry_points=[root], boundary=boundary)
    assert result.status == "not-reached"
    assert result.exhaustive is True
    assert result.attributes()["sink_reachable"] is False


def test_depth_cap_truncates_instead_of_refuting():
    edges = {}
    prev = M("com.x.A", "onCreate")
    for i in range(20):
        nxt = M("com.x.A", f"step{i}")
        edges[prev] = [nxt]
        prev = nxt
    edges[prev] = []
    graph, boundary = build(edges=edges, boundary={prev: [FO]})
    result = analyse(graph, entry_points=[M("com.x.A", "onCreate")], boundary=boundary, max_depth=3)
    assert result.status == "truncated"
    assert result.attributes()["sink_reachable"] is None


def test_truncation_never_reports_absence():
    """The invariant: inconclusive may never be spelled False.

    If this test ever fails, MOBIUS can report "no sink reachable" on the strength of a
    search it abandoned - which is precisely the failure mode the project exists to avoid.
    """
    edges = {}
    prev = M("com.x.A", "onCreate")
    for i in range(30):
        nxt = M("com.x.A", f"s{i}")
        edges[prev] = [nxt]
        prev = nxt
    graph, boundary = build(edges=edges)
    result = analyse(graph, entry_points=[M("com.x.A", "onCreate")], boundary=boundary, max_depth=2)
    assert result.truncated
    assert result.attributes()["sink_reachable"] is not False
    assert result.explain().endswith("absence not established")


def test_node_budget_truncates():
    edges = {M("com.x.A", "onCreate"): [M("com.x.A", "m0")]}
    for i in range(50):
        edges[M("com.x.A", f"m{i}")] = [M("com.x.A", f"m{i+1}")]
    graph, boundary = build(edges=edges)
    result = analyse(graph, entry_points=[M("com.x.A", "onCreate")], boundary=boundary, max_nodes=5)
    assert result.status == "truncated"


def test_no_entry_point_in_graph_is_not_evidence_of_safety():
    graph, boundary = build(edges={M("com.x.Other", "go"): []})
    result = analyse(graph, entry_points=[M("com.x.A", "onCreate")], boundary=boundary)
    assert result.status == "no-entry-point"
    assert result.attributes() == {"sink_reachable": None, "caller_check_absent": None}


def test_cycles_terminate():
    a, b = M("com.x.A", "onCreate"), M("com.x.A", "loop")
    graph, boundary = build(edges={a: [b], b: [a]})
    result = analyse(graph, entry_points=[a], boundary=boundary)
    assert result.status == "not-reached"


def test_shortest_path_wins_among_entry_points():
    short, long_ = M("com.x.A", "onCreate"), M("com.x.A", "onResume")
    mid = M("com.x.A", "mid")
    graph, boundary = build(
        edges={short: [], long_: [mid], mid: []},
        boundary={short: [FO], mid: [FO]},
    )
    result = analyse(graph, entry_points=[long_, short], boundary=boundary)
    assert result.reached
    assert len(result.path) == 1


def test_analysis_is_deterministic():
    root, x, y = M("com.x.A", "onCreate"), M("com.x.A", "x"), M("com.x.A", "y")
    graph, boundary = build(
        edges={root: [y, x], x: [], y: []},
        boundary={x: [FO], y: [FO]},
    )
    first = [analyse(graph, entry_points=[root], boundary=boundary).path for _ in range(3)]
    assert first[0] == first[1] == first[2]


def test_an_unguarded_branch_beats_a_guarded_one():
    root, guarded, open_ = M("com.x.A", "onCreate"), M("com.x.A", "g"), M("com.x.A", "o")
    graph, boundary = build(
        edges={root: [guarded, open_], guarded: [], open_: []},
        boundary={guarded: [CHECK, FO], open_: [FO]},
    )
    result = analyse(graph, entry_points=[root], boundary=boundary)
    assert result.reached and not result.guarded


def test_guard_before_the_split_guards_every_branch():
    """A check in the caller protects all of its callees, so neither branch is a finding."""
    root, a, b = M("com.x.A", "onCreate"), M("com.x.A", "a"), M("com.x.A", "b")
    graph, boundary = build(
        edges={root: [a, b], a: [], b: []},
        boundary={root: [CHECK], a: [FO], b: [FO]},
    )
    result = analyse(graph, entry_points=[root], boundary=boundary)
    assert result.reached and result.guarded


def test_guard_in_the_same_method_refutes_the_clause_regardless_of_order():
    """Documented conservative limitation.

    We see call references, not control flow, so a `checkCallingPermission` in the same
    method as the sink counts as protecting it even if it appears *after* the sink. That
    biases towards *not* confirming - the safe direction for a tool that must not overclaim,
    at the cost of missing some real findings. Fixing it properly needs a dominator analysis
    over the CFG, which is out of scope for v1 (recorded as R-21).
    """
    root = M("com.x.A", "onCreate")
    graph, boundary = build(edges={root: []}, boundary={root: [FO, CHECK]})
    result = analyse(graph, entry_points=[root], boundary=boundary)
    assert result.reached
    assert result.guarded, "same-method guard suppresses confirmation"


@pytest.mark.parametrize("status", ["reached", "not-reached", "truncated", "no-entry-point"])
def test_attributes_are_only_ever_true_false_or_none(status):
    root = M("com.x.A", "onCreate")
    graph, boundary = build(edges={root: []}, boundary={root: [FO]} if status == "reached" else {})
    result = analyse(graph, entry_points=[] if status == "no-entry-point" else [root],
                     boundary=boundary, max_depth=0 if status == "truncated" else 8)
    for key, value in result.attributes().items():
        assert value in (True, False, None), f"{key}={value!r}"


def test_methods_named_ignores_the_parameter_descriptor():
    """Regression: `onReceive` in a real APK is `onReceive(Context, Intent)V`.

    Matching entry points by equality against `MethodRef(cls, "onReceive")` found nothing,
    so a real exported receiver was reported as having no entry point at all.
    """
    ref = MethodRef("com.x.R", "onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V")
    graph = CallGraph(edges={ref: ()})
    assert graph.methods_named("com.x.R", "onReceive") == (ref,)
    assert MethodRef("com.x.R", "onReceive") not in graph.edges


def test_methods_named_returns_overloads():
    a = MethodRef("com.x.A", "onCreate", "()V")
    b = MethodRef("com.x.A", "onCreate", "(Landroid/os/Bundle;)V")
    graph = CallGraph(edges={a: (), b: ()})
    assert graph.methods_named("com.x.A", "onCreate") == (a, b)  # sorted by descriptor


def test_entry_point_with_parameters_is_found():
    on_receive = MethodRef("com.x.R", "onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V")
    graph, boundary = build(edges={on_receive: []}, boundary={on_receive: [FO]})
    result = analyse(graph, entry_points=graph.methods_named("com.x.R", "onReceive"), boundary=boundary)
    assert result.reached and result.path == (on_receive,)


def test_catalogue_excludes_operations_that_are_not_security_relevant_alone():
    """Regression from a real APK: `SharedPreferences.getString` produced a confirmed finding.

    An exported receiver that reads its own preference discloses nothing. Reachability
    without data flow cannot tell that apart from returning the value to the caller, so a
    sink must be an operation whose *execution* is security-relevant.
    """
    from mobius.core.sinks import SINKS

    ids = {s.id for s in SINKS.values()}
    assert "shared-prefs" not in ids
    assert "intent-redirect" not in ids
    # The ones that remain all name a privileged effect, not a value read.
    assert {"file-write", "webview-load", "process-exec", "dynamic-load"} <= ids


def test_sink_keys_are_unique():
    from mobius.core.sinks import SINKS

    assert len(SINKS) == len({s.id for s in SINKS.values()})


def test_absent_path_claims_nothing_about_a_caller_check():
    """Regression from a live HTTP run against a real APK.

    A complete search that found no sink reported `caller_check_absent: true`, which asserts
    something about a call chain that does not exist. `None` is the only honest value: with no
    path, no statement about checks on it has been established.
    """
    a = MethodRef("com.x.A", "onCreate")
    graph = CallGraph(edges={a: ()})
    result = analyse(graph, entry_points=(a,), boundary={})

    assert result.status == "not-reached"
    assert result.attributes()["sink_reachable"] is False  # exhaustive, so refuted
    assert result.attributes()["caller_check_absent"] is None


def test_truncated_search_establishes_neither_clause():
    a = MethodRef("com.x.A", "onCreate")
    b = MethodRef("com.x.B", "run")
    graph = CallGraph(edges={a: (b,), b: ()})
    result = analyse(graph, entry_points=(a,), boundary={}, max_nodes=1)

    assert result.status == "truncated"
    assert result.attributes() == {"sink_reachable": None, "caller_check_absent": None}
