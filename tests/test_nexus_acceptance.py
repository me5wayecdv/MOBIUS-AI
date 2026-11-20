"""The NEXUS acceptance harness is test-pinned: the mock battery is green, and
the harness itself is not vacuous - a wrong expectation produces a FAIL."""
from __future__ import annotations

from dataclasses import replace

from mobius.tools.nexus_acceptance import _mock_report, build_fixture, cases, run_case


def test_mock_battery_every_case_meets_its_expectation():
    report = _mock_report()
    assert report.ok, report.render()
    assert len(report.results) == 11
    assert "VERDICT: every expected guard held" in report.render()


def test_case_names_and_criteria_are_stable_and_unique():
    report = _mock_report()
    names = [r.case.name for r in report.results]
    assert len(names) == len(set(names))
    criteria = {r.case.criterion for r in report.results}
    assert criteria == {
        "schema-validity",
        "evidence-confinement",
        "disposition-discipline",
        "repair-loop",
        "consent-gating",
        "budget-gating",
    }


def test_harness_flags_a_wrong_expectation(session, store):
    """If a guard silently changed behavior, the battery must go red, not green."""
    fx = build_fixture(session, store)
    malformed = next(c for c in cases(fx) if c.name == "malformed-json-refused")
    tampered = replace(malformed, expected="accepted:model_gateway")
    result = run_case(session, fx, tampered)
    assert not result.ok
    assert result.observed == "refused:ModelOutputInvalid"


def test_refused_generations_persist_diagnostics_not_hypotheses(session, store):
    fx = build_fixture(session, store)
    refused = [c for c in cases(fx) if c.expected.startswith("refused:")]
    assert len(refused) == 7
    for case in refused:
        result = run_case(session, fx, case)
        assert result.ok, f"{case.name}: {result.detail}"
