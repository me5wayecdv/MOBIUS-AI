"""New regression (not a rewrite of an old assertion): Allsafe-shaped, COMPLETE index, no
catalogued sink.

Found by validating against a real APK (Allsafe v1.6, 92,817 methods, complete index): every
exported component was "rejected / not-reachable" because lifecycle-root direct-call search
found no catalogued sink (DataProvider reaches SQLiteQueryBuilder.query, ProxyActivity does
startActivity on an extra Intent; neither is catalogued). A bounded search that finds nothing
is a fact about the search, never a refutation of the security hypothesis.

The graph here is synthetic (a fixture), so this proves the policy, not real-APK recall.
"""

from __future__ import annotations

from test_spectre import CLS, _spectre, surface_ready  # noqa: F401  (fixture re-export)

from mobius.adapters.dex import CodeIndex, DexCoverage
from mobius.adapters.models import EventRow, FindingRow, ObservationRow, VerdictRow
from mobius.core.enums import FindingStatus, Verdict
from mobius.core.reachability import CallGraph, MethodRef


def _complete_index_without_catalogued_sink() -> CodeIndex:
    root = MethodRef(CLS, "onCreate")
    helper = MethodRef(CLS, "handleExtra")
    leaf = MethodRef(CLS, "forward")
    # Only catalogued sink calls are recorded in the boundary; an uncatalogued call (a
    # SQLiteQueryBuilder.query, a startActivity of an attacker Intent) leaves no trace in it.
    return CodeIndex(
        graph=CallGraph(edges={root: (helper,), helper: (leaf,), leaf: ()}),
        boundary={},
        classes=(CLS,),
        methods=3,
        truncated=False,
        dex_coverage=(DexCoverage("classes.dex", "indexed", 3),),
    )


def test_complete_index_with_no_catalogued_sink_is_not_determined_not_rejected(
    session, store, surface_ready
):
    index = _complete_index_without_catalogued_sink()
    assert index.complete, "precondition: the index is complete, so truncation is not the reason"

    result = _spectre(session, store, index).analyse(surface_ready)

    assert result["rejected"] == 0
    entry = result["results"][0]
    assert entry["status"] == FindingStatus.MANUAL_REVIEW_REQUIRED.value
    assert entry["verdict"] == Verdict.INSUFFICIENT_EVIDENCE.value
    assert entry["attributes"]["sink_reachable"] is None

    verdict = session.query(VerdictRow).one()
    assert verdict.verdict != Verdict.REJECTED.value
    assert verdict.rejection_reason is None  # no "not-reachable" reason code is ever issued

    events = [e.type for e in session.query(EventRow).filter_by(investigation_id=surface_ready)]
    assert "finding_rejected" not in events


def test_the_bounded_search_fact_is_retained_but_scoped(session, store, surface_ready):
    _spectre(session, store, _complete_index_without_catalogued_sink()).analyse(surface_ready)

    obs = (
        session.query(ObservationRow)
        .filter_by(investigation_id=surface_ready, subject_ref=CLS)
        .all()
    )
    reach = [o for o in obs if (o.attributes or {}).get("reachability")]
    assert reach and all(o.attributes["reachability"] == "not-reached" for o in reach)
    statement = " ".join(o.statement for o in reach)
    assert "no catalogued sink" in statement and "not determined" in statement

    finding = session.query(FindingRow).one()
    assert "no sensitive sink reachable" not in finding.title
    assert "not determined" in finding.title
