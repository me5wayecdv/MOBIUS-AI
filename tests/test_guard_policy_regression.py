"""NEW regressions: seeing a guard-like CALL never refutes a reached sink.

The call graph records only that a call by class and method name occurs in a method. It has
no control-flow graph and no data flow, so it cannot show that the call's result is used, that
it runs before the sink, or that it constrains the caller. These tests pin the policy: a
guarded path is undetermined (manual review, guard kept as an observation), never confirmed
and never rejected. The graphs are synthetic fixtures; they prove policy, not real-APK recall.
"""

from __future__ import annotations

import pytest

from mobius.core.reachability import CallGraph, CallTarget, MethodRef, analyse

FO = ("Ljava/io/FileOutputStream;", "<init>")
GUARDS = {
    "permission check": ("Landroid/content/Context;", "checkCallingPermission"),
    "enforce": ("Landroid/content/Context;", "enforceCallingPermission"),
    "uid retrieval only": ("Landroid/os/Binder;", "getCallingUid"),
    "pid retrieval only": ("Landroid/os/Binder;", "getCallingPid"),
    "calling package": ("Landroid/app/ActivityManager;", "getCallingPackage"),
    "signature check": ("Landroid/content/pm/PackageManager;", "checkSignatures"),
}


def _run(calls_by_method, edges):
    graph = CallGraph(edges={k: tuple(v) for k, v in edges.items()})
    boundary = {k: tuple(CallTarget(c, m) for c, m in v) for k, v in calls_by_method.items()}
    root = MethodRef("com.x.A", "onCreate")
    return analyse(graph, entry_points=[root], boundary=boundary)


ROOT = MethodRef("com.x.A", "onCreate")
SINKM = MethodRef("com.x.A", "write")


@pytest.mark.parametrize("name", sorted(GUARDS))
def test_every_catalogued_guard_call_alone_is_undetermined(name):
    result = _run({ROOT: [GUARDS[name]], SINKM: [FO]}, {ROOT: [SINKM], SINKM: []})
    assert result.reached and result.guarded
    attrs = result.attributes()
    assert attrs["sink_reachable"] is True
    assert attrs["caller_check_absent"] is None  # not False (no refutation), not True (no confirm)


def test_guard_called_after_the_sink_in_the_same_method_does_not_refute():
    # The same method calls the sink first and the permission check afterwards.
    result = _run({ROOT: [FO, GUARDS["permission check"]]}, {ROOT: []})
    assert result.reached
    assert result.attributes()["caller_check_absent"] is None


def test_guard_whose_result_is_ignored_does_not_refute():
    # The graph cannot see result use at all: an ignored checkCallingPermission() looks the
    # same as an enforced one. That is exactly why presence cannot be proof.
    ignored = _run({ROOT: [GUARDS["permission check"], FO]}, {ROOT: []})
    assert ignored.attributes()["caller_check_absent"] is None


def test_uid_retrieval_alone_does_not_refute():
    result = _run({ROOT: [GUARDS["uid retrieval only"], FO]}, {ROOT: []})
    assert result.attributes()["caller_check_absent"] is None
    assert [g.id for g in result.guards] == ["calling-uid"]


def test_guard_is_retained_as_an_observation():
    result = _run({ROOT: [GUARDS["permission check"], FO]}, {ROOT: []})
    assert [g.id for g in result.guards] == ["check-calling-permission"]
    assert "check-calling-permission" in result.explain()


def test_unguarded_positive_path_still_establishes_the_clause():
    result = _run({SINKM: [FO]}, {ROOT: [SINKM], SINKM: []})
    attrs = result.attributes()
    assert result.reached and not result.guarded
    assert attrs == {"sink_reachable": True, "caller_check_absent": True}


def test_an_unguarded_alternative_path_still_wins_over_a_guarded_one():
    other = MethodRef("com.x.A", "other")
    result = _run(
        {SINKM: [GUARDS["permission check"], FO], other: [FO]},
        {ROOT: [SINKM, other], SINKM: [], other: []},
    )
    # The search keeps looking for an unguarded sink, so a real positive path is not masked.
    assert result.reached and not result.guarded
    assert result.attributes()["caller_check_absent"] is True
