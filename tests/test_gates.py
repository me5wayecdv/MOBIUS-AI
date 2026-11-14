"""Every gate gets a positive case and, more importantly, a negative control.

The negative controls are the reason this project exists. A gate that only ever sees
vulnerable input has not been tested; it has been demonstrated.
"""

from __future__ import annotations

import pytest

from mobius.core import gates


def _satisfying(category: str) -> dict[str, object]:
    """Attributes that satisfy every clause, derived from the gate's own key list."""
    gate = gates.get_gate(category)
    attrs: dict[str, object] = {}
    for clause in gate.clauses:
        source = str(clause.predicate.__name__)
        if source == "_is_empty":
            attrs[clause.key] = None
        elif source == "_is_true":
            attrs[clause.key] = True
        elif source == "_is_false":
            attrs[clause.key] = False
        else:  # pragma: no cover - guards against a predicate added later
            raise AssertionError(f"unknown predicate {source}")
    return attrs


@pytest.mark.parametrize("category", gates.all_categories())
def test_every_gate_passes_when_all_clauses_hold(category):
    result = gates.evaluate(category, _satisfying(category))
    assert result.passed, f"{category} failed on its own satisfying attributes: {result.failed}"
    assert result.failed == ()
    assert result.missing_attributes == ()


@pytest.mark.parametrize("category", gates.all_categories())
def test_every_gate_fails_when_any_clause_is_flipped(category):
    gate = gates.get_gate(category)
    for clause in gate.clauses:
        attrs = _satisfying(category)
        # flip the clause to its negated value
        attrs[clause.key] = (
            None if clause.predicate.__name__ == "_is_true" else True
        ) if clause.predicate.__name__ != "_is_false" else True
        result = gates.evaluate(category, attrs)
        assert not result.passed, f"{category} still passed with clause {clause.key} violated"
        assert clause.key in result.failed


def test_missing_attributes_are_reported_separately_from_failures():
    # An exported activity with no permission is not yet a finding: we have not shown that
    # a privileged sink is reachable. The distinction must survive into the result.
    #
    # Note the asymmetry, which is a real property of the model rather than an accident:
    # for a "must be empty" clause (no android:permission), an absent attribute IS the
    # evidence - absence of a declaration is what we are looking for. For a "must be true"
    # clause, an absent attribute means the claim was never established. Treating both as
    # "missing" would report the permission clause as unresolved when it is in fact
    # resolved in our favour.
    result = gates.evaluate("exported-component-no-permission", {"exported": True})
    assert not result.passed
    assert result.clauses["permission"] is True, "absent permission declaration satisfies the clause"
    assert set(result.missing_attributes) == {"permission", "caller_check_absent", "sink_reachable"}
    assert set(result.failed) == {"caller_check_absent", "sink_reachable"}


def test_negative_control_exported_launcher_is_not_a_finding():
    """The most common false positive in Android scanning: an exported launcher activity.

    It is exported, and it has no permission - but it exposes no privileged sink and it
    is reachable only by the user tapping it. A gate that flagged this would flag every
    app in existence.
    """
    attrs = {
        "exported": True,
        "permission": None,
        "caller_check_absent": True,
        "sink_reachable": False,
    }
    result = gates.evaluate("exported-component-no-permission", attrs)
    assert not result.passed
    assert result.failed == ("sink_reachable",)


def test_negative_control_md5_cache_key_is_not_a_finding():
    attrs = {
        "algorithm_identified": True,
        "algorithm_weak": True,
        "used_for_security_purpose": False,  # it is a cache key
        "key_provenance_known": True,
    }
    assert not gates.evaluate("weak-crypto", attrs).passed


def test_negative_control_secret_placeholder():
    attrs = {
        "located": True,
        "format_and_entropy_ok": True,
        "not_placeholder": False,  # e.g. "YOUR_API_KEY_HERE"
        "used_in_security_context": True,
    }
    assert not gates.evaluate("hardcoded-secret", attrs).passed


def test_negative_control_benign_plugin_loader():
    """Legitimate dynamic loading (themes, hot-patch SDK) must not be flagged.

    This is the control that keeps the dynamic-code-loading gate from firing on every app
    that uses a plugin architecture - see docs/ORACLE_THREAT_INTEL.md 7.
    """
    attrs = {
        "loader_used": True,
        "source_is_network_or_external": False,  # bundled, not fetched
        "no_integrity_check": True,
    }
    assert not gates.evaluate("dynamic-code-loading", attrs).passed


def test_unknown_gate_raises_rather_than_passing():
    with pytest.raises(gates.UnknownGate):
        gates.evaluate("not-a-real-category", {})


def test_required_evidence_is_declared_before_evaluation():
    required = gates.required_evidence("exported-component-no-permission")
    assert required == ("exported", "permission", "caller_check_absent", "sink_reachable")


def test_gate_catalogue_is_complete():
    assert len(gates.all_categories()) == 10
    for gate in gates.GATES.values():
        assert gate.clauses, f"{gate.category} has no clauses - it would pass vacuously"
        assert gate.maswe or gate.masvs, f"{gate.category} has no standards mapping"


def test_none_means_unestablished_not_false():
    """Regression: a `None` attribute once counted as a *failed* clause.

    That turned "we never established sink reachability" into "sink is not reachable", which
    would reject a candidate the tool had not actually refuted. A None on a must-be-true
    clause is missing evidence; on a must-be-empty clause it is the observation itself.
    """
    result = gates.evaluate(
        "exported-component-no-permission",
        {"exported": True, "permission": None, "caller_check_absent": None, "sink_reachable": None},
    )
    assert not result.passed
    assert set(result.missing_attributes) == {"caller_check_absent", "sink_reachable"}
    assert result.failed_decisively == ()
    assert "permission" not in result.missing_attributes, "absent permission is the evidence"


def test_decisive_failure_is_separated_from_missing_evidence():
    result = gates.evaluate(
        "exported-component-no-permission",
        {"exported": True, "permission": "com.example.BIND_SYNC", "caller_check_absent": None},
    )
    assert "permission" in result.failed_decisively
    assert "caller_check_absent" in result.missing_attributes
    assert "permission" not in result.missing_attributes


def test_gate_evidence_distinguishes_refuted_from_never_established():
    """Regression from a real scan's stored finding.

    A rejected finding recorded `caller_check_absent: false` for a clause nothing had been
    offered as evidence about. A reader cannot tell that from "a caller check was found", so
    the third state is carried through to storage as `null`.
    """
    from mobius.core.gates import evaluate

    result = evaluate(
        "exported-component-no-permission",
        {"exported": True, "permission": None, "sink_reachable": False},
    )

    evidence = result.as_gate_evidence()
    assert evidence["sink_reachable"] is False  # refuted by a complete search
    assert evidence["exported"] is True  # established
    assert evidence["caller_check_absent"] is None  # never established
    assert evidence["permission"] is True  # "no permission" is itself the evidence
