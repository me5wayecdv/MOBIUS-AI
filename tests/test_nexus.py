"""NEXUS: the bounded dispatcher loop.

Two things are under test here and they are easy to confuse:

1. *That the loop works* - it pops the frontier, dispatches to the agent that can run the
   action, records the outcome, and closes the investigation even when it runs out of
   budget.
2. *That the loop stays honest* - work it cannot do is reported as dropped with a reason,
   a step budget is a real stop rather than a hint, and nothing in it upgrades a verdict.

The dispatch order is asserted explicitly because determinism is a requirement, not a
nicety: two identical runs must look at the same things in the same order.
"""

from __future__ import annotations

import pytest

from conftest import make_apk
from mobius.adapters.dex import CodeIndex, DexCoverage
from mobius.adapters.events import SqlEventStore
from mobius.adapters.models import FrontierEntryRow, InvestigationRow
from mobius.core.enums import InvestigationState
from mobius.core.ids import IdPrefix, new_id
from mobius.core.reachability import CallGraph, CallTarget, MethodRef
from mobius.services import errors
from mobius.services.intake import IntakeService
from mobius.services.nexus import NexusService
from mobius.services.recon import ReconService
from mobius.services.spectre import SpectreService

EXPORT = "com.example.demo.ExportActivity"
SECOND = "com.example.demo.SecondActivity"
FO = CallTarget("Ljava/io/FileOutputStream;", "<init>")

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.demo">
  <application>
    <activity android:name=".ExportActivity" android:exported="true"/>
    <activity android:name=".SecondActivity" android:exported="true"/>
  </application>
</manifest>
"""


def _index(*, sink_in: str | None = EXPORT, truncated: bool = False) -> CodeIndex:
    """Two exported activities; the sink, when present, sits behind one of them."""
    first = MethodRef(EXPORT, "onCreate")
    second = MethodRef(SECOND, "onCreate")
    boundary: dict[MethodRef, tuple[CallTarget, ...]] = {}
    if sink_in == EXPORT:
        boundary[first] = (FO,)
    if sink_in == SECOND:
        boundary[second] = (FO,)
    return CodeIndex(
        graph=CallGraph(edges={first: (), second: ()}),
        boundary=boundary,
        classes=(EXPORT, SECOND),
        methods=2,
        truncated=truncated,
        dex_coverage=(DexCoverage("fixture.dex", "truncated" if truncated else "indexed", 1),),
    )


def _scan(session, store, future_iso, *, apk: bytes | None = None) -> str:
    """Upload, authorise, start and run RECON: an investigation sitting at SURFACE_READY."""
    intake = IntakeService(session, store)
    app, _ = intake.create_application(
        apk or make_apk(manifest=MANIFEST), "demo.apk", uploaded_by="analyst-1"
    )
    auth = intake.create_authorization(
        apk_sha256=app.sha256,
        target_package="com.example.demo",
        scope_text="Static analysis of the supplied artefact only; no execution.",
        statement="s",
        max_intensity=2,
        granted_by="analyst-1",
        expires_at=future_iso,
    )
    inv = intake.create_investigation(
        application_id=app.id,
        authorization_id=auth.id,
        objective="Determine whether exported components reach a privileged sink.",
        intensity=0,
        created_by="analyst-1",
    )
    intake.start(inv.id)
    ReconService(session, store).run(inv.id)
    return inv.id


def _nexus(session, store, index, **kwargs) -> NexusService:
    spectre = SpectreService(session, store, indexer=lambda _apk: index)
    return NexusService(session, store, spectre=spectre, **kwargs)


def _row(session, investigation_id) -> InvestigationRow:
    return session.get(InvestigationRow, investigation_id)


# -- the loop works ------------------------------------------------------------------


def test_nexus_dispatches_every_candidate_and_closes(session, store, future_iso):
    scan = _scan(session, store, future_iso)

    result = _nexus(session, store, _index()).run(scan)

    assert result["candidates"] == 2
    assert result["dispatched"] == 3  # two component checks plus one adaptive callers_of action
    assert result["dropped"] == 0
    assert result["remaining"] == 0
    assert result["stop_reason"] == "completed"
    assert result["findings"] == {"confirmed": 1, "rejected": 0, "manual_review": 1}
    assert _row(session, scan).state == InvestigationState.CLOSED.value
    assert _row(session, scan).stop_reason == "completed"


def test_the_investigation_ends_closed_not_stuck_in_a_working_state(session, store, future_iso):
    scan = _scan(session, store, future_iso)
    _nexus(session, store, _index()).run(scan)

    assert _row(session, scan).state in {"CLOSED", "CANCELLED", "FAILED", "SCOPE_BLOCKED"}


def test_every_dispatched_entry_is_marked_done_with_one_attempt(session, store, future_iso):
    scan = _scan(session, store, future_iso)
    _nexus(session, store, _index()).run(scan)

    entries = (
        session.query(FrontierEntryRow).filter_by(investigation_id=scan).all()
    )
    assert len(entries) == 3
    assert {e.state for e in entries} == {"done"}
    assert sum(1 for e in entries if e.action == "callers_of") == 1
    assert {e.attempts for e in entries} == {1}


def test_nexus_can_close_an_investigation_spectre_already_finished(session, store, future_iso):
    """Arriving in CORRELATING is not an error: there is simply nothing left to dispatch."""
    scan = _scan(session, store, future_iso)
    SpectreService(session, store, indexer=lambda _apk: _index()).analyse(scan)
    assert _row(session, scan).state == InvestigationState.CORRELATING.value

    result = _nexus(session, store, _index()).run(scan)

    assert result["dispatched"] == 0
    assert result["stop_reason"] == "completed"
    assert _row(session, scan).state == InvestigationState.CLOSED.value


def test_a_second_run_is_refused(session, store, future_iso):
    scan = _scan(session, store, future_iso)
    _nexus(session, store, _index()).run(scan)

    with pytest.raises(errors.ScanStateConflict):
        _nexus(session, store, _index()).run(scan)


def test_a_zero_budget_is_rejected_rather_than_silently_ignored(session, store, future_iso):
    scan = _scan(session, store, future_iso)
    with pytest.raises(ValueError):
        _nexus(session, store, _index()).run(scan, max_steps=0)


# -- the budget is a real stop -------------------------------------------------------


def test_the_step_budget_stops_the_loop_and_reports_what_it_skipped(session, store, future_iso):
    scan = _scan(session, store, future_iso)

    result = _nexus(session, store, _index()).run(scan, max_steps=1)

    assert result["dispatched"] == 1
    # The first reachable sink creates one adaptive callers_of action. The untouched
    # original candidate and that follow-up both remain queued when the one-step
    # budget is exhausted.
    assert result["remaining"] == 2
    queued = session.query(FrontierEntryRow).filter_by(
        investigation_id=scan, state="queued"
    ).all()
    assert {entry.action for entry in queued} == {"find_api_refs", "callers_of"}
    assert result["stop_reason"] == "budget_exhausted"
    assert _row(session, scan).state == InvestigationState.CLOSED.value
    assert _row(session, scan).stop_reason == "budget_exhausted"
    # The budget stop is in the notes, not buried in a counter.
    assert any("left queued" in note for note in result["notes"])
    # The unrun entry keeps its state, so the report can name it.
    left = session.query(FrontierEntryRow).filter_by(investigation_id=scan, state="queued").all()
    assert len(left) == 2


def test_a_budget_that_covers_the_work_does_not_stop_early(session, store, future_iso):
    scan = _scan(session, store, future_iso)
    result = _nexus(session, store, _index()).run(scan, max_steps=5)

    assert result["stop_reason"] == "completed"
    # Two original component checks plus the evidence-triggered caller inspection.
    assert result["budget"]["steps_used"] == 3
    assert result["budget"]["steps_remaining"] == 2


# -- work without an executor is reported --------------------------------------------


def test_an_entry_for_an_unimplemented_agent_is_dropped_with_a_reason(session, store, future_iso):
    scan = _scan(session, store, future_iso)
    session.add(
        FrontierEntryRow(
            id=new_id(IdPrefix.FRONTIER),
            investigation_id=scan,
            # A static action, so the reason reported is the missing agent rather than the
            # intensity gate that would fire first for launch_component.
            action="find_string",
            action_args={"component": EXPORT},
            required_agent="PHANTOM",
            relates_to_maswe=["MASWE-0029"],
            score=0.0,
            depth=0,
            state="queued",
            attempts=0,
            inserted_at="2026-11-15T00:00:00Z",
        )
    )
    session.flush()

    result = _nexus(session, store, _index()).run(scan)

    dropped = [s for s in result["steps"] if s["disposition"] == "dropped"]
    assert len(dropped) == 1
    assert dropped[0]["agent"] == "PHANTOM"
    assert "PHANTOM is not implemented" in dropped[0]["reason"]
    assert any("dropped for want of an executor" in note for note in result["notes"])
    assert result["remaining"] == 0


def test_a_dynamic_action_at_passive_intensity_names_the_intensity_as_the_reason(
    session, store, future_iso
):
    """Both reasons are true; the decisive one is the one that stops it today.

    A PHANTOM entry is unexecutable because the agent does not exist *and* because intensity
    0 forbids executing anything. Reporting the intensity gate is right: it is the constraint
    the analyst could actually change (with a wider authorisation), whereas PHANTOM would
    still not exist.
    """
    scan = _scan(session, store, future_iso)
    session.add(
        FrontierEntryRow(
            id=new_id(IdPrefix.FRONTIER),
            investigation_id=scan,
            action="send_intent",
            action_args={"component": EXPORT},
            required_agent="PHANTOM",
            relates_to_maswe=["MASWE-0029"],
            score=0.0,
            depth=0,
            state="queued",
            attempts=1,  # tried once already, still not permitted
            inserted_at="2026-11-15T00:00:01Z",
        )
    )
    session.flush()

    result = _nexus(session, store, _index()).run(scan)

    dropped = [s for s in result["steps"] if s["disposition"] == "dropped"]
    assert dropped, "the forbidden entry must appear in the record"
    assert any("does not permit send_intent" in (d["reason"] or "") for d in dropped)


# -- the loop does not upgrade anything ----------------------------------------------


def test_nexus_never_confirms_a_negative_control(session, store, future_iso):
    scan = _scan(session, store, future_iso)
    result = _nexus(session, store, _index(sink_in=None)).run(scan)

    assert result["findings"]["confirmed"] == 0
    # No catalogued sink is a fact about the search, never a refutation.
    assert result["findings"]["rejected"] == 0
    assert result["findings"]["manual_review"] == 2
    assert all(o["verdict"] != "rejected" for o in result["results"])


def test_a_truncated_index_still_cannot_produce_a_confirmation(session, store, future_iso):
    scan = _scan(session, store, future_iso)
    result = _nexus(session, store, _index(truncated=True)).run(scan)

    assert result["findings"]["confirmed"] == 0
    assert result["findings"]["manual_review"] == 2


# -- determinism and the audit trail --------------------------------------------------


def test_the_dispatch_order_is_identical_across_runs(session, store, future_iso):
    first = _nexus(session, store, _index()).run(_scan(session, store, future_iso))
    second = _nexus(session, store, _index()).run(_scan(session, store, future_iso))

    def shape(result):
        return [
            (s["action"], s["agent"], s["disposition"], s["reason"]) for s in result["steps"]
        ]

    assert shape(first) == shape(second)
    def result_shape(result):
        # Component investigations and caller inspections have different payload
        # schemas. Compare their stable subject and status without assuming a
        # component key exists on callers_of outcomes.
        return [
            (item.get("component") or item.get("target_method"), item["status"])
            for item in result["results"]
        ]

    assert result_shape(first) == result_shape(second)
    assert first["findings"] == second["findings"]


def test_the_event_trail_can_be_read_as_a_sequence(session, store, future_iso):
    scan = _scan(session, store, future_iso)
    _nexus(session, store, _index()).run(scan)

    from mobius.adapters.models import EventRow

    events = (
        session.query(EventRow)
        .filter_by(investigation_id=scan)
        .order_by(EventRow.seq.asc())
        .all()
    )
    seqs = [e.seq for e in events]
    assert seqs == list(range(1, len(seqs) + 1)), "sequences must be contiguous"
    types = [e.type for e in events]
    assert "nexus_started" in types
    assert "frontier_dispatched" in types
    assert "nexus_complete" in types
    # nexus_started precedes the first dispatch, nexus_complete comes last.
    assert types.index("nexus_started") < types.index("frontier_dispatched")
    assert types[-1] == "nexus_complete"
    assert events[-1].payload["stop_reason"] == "completed"


def test_the_reason_a_loop_stopped_is_stored_not_just_emitted(session, store, future_iso):
    scan = _scan(session, store, future_iso)
    _nexus(session, store, _index()).run(scan, max_steps=1)

    row = _row(session, scan)
    assert row.stop_reason == "budget_exhausted"
    events = SqlEventStore(session)
    assert events is not None  # the store is shared with the API, not per-run


def test_nexus_emits_the_code_analysis_marker_the_stream_expects(session, store, future_iso):
    """A client waiting on `code_analysis_complete` must not hang because NEXUS drove the work."""
    from mobius.adapters.models import EventRow

    scan = _scan(session, store, future_iso)
    _nexus(session, store, _index()).run(scan)

    types = [
        e.type
        for e in session.query(EventRow)
        .filter_by(investigation_id=scan)
        .order_by(EventRow.seq.asc())
    ]
    assert "code_analysis_complete" in types
    assert types.index("code_analysis_complete") < types.index("nexus_complete")


def test_no_analysis_marker_is_emitted_when_nothing_was_dispatched(session, store, future_iso):
    """An event that says analysis completed, when none ran, is a false statement."""
    from mobius.adapters.models import EventRow

    scan = _scan(session, store, future_iso)
    SpectreService(session, store, indexer=lambda _apk: _index()).analyse(scan)
    _nexus(session, store, _index()).run(scan)

    nexus_scan_events = [
        e.type
        for e in session.query(EventRow)
        .filter_by(investigation_id=scan)
        .order_by(EventRow.seq.asc())
    ]
    # SPECTRE emitted one itself; NEXUS must not add a second.
    assert nexus_scan_events.count("code_analysis_complete") == 1



def test_nexus_drops_known_action_with_unregistered_arguments(
    session, store, future_iso
):
    scan = _scan(session, store, future_iso)
    session.add(
        FrontierEntryRow(
            id=new_id(IdPrefix.FRONTIER),
            investigation_id=scan,
            action="find_api_refs",
            action_args={"component": EXPORT, "command": "id"},
            required_agent="SPECTRE",
            relates_to_maswe=["MASWE-0001"],
            score=1.0,
            depth=0,
            state="queued",
            attempts=0,
            inserted_at="2026-11-15T00:00:02Z",
        )
    )
    session.flush()

    result = _nexus(session, store, _index()).run(scan)

    rejected = [
        step for step in result["steps"]
        if step["disposition"] == "dropped"
        and "action policy rejected dispatch" in (step["reason"] or "")
    ]
    assert len(rejected) == 1
    assert "Extra inputs are not permitted" in rejected[0]["reason"]
    # The malformed action is dropped, while the two component checks and the
    # sink-triggered callers_of follow-up are valid dispatches.
    assert result["dispatched"] == 3
    assert result["dropped"] == 1



def test_reachable_sink_result_changes_next_action_to_direct_caller_inspection(
    session, store, future_iso
):
    from mobius.adapters.models import DecisionRow, EventRow, ObservationRow

    scan = _scan(session, store, future_iso)
    result = _nexus(session, store, _index()).run(scan)

    assert result["dispatched"] == 3
    caller_steps = [step for step in result["steps"] if step["action"] == "callers_of"]
    assert len(caller_steps) == 1
    caller_rows = (
        session.query(FrontierEntryRow)
        .filter_by(investigation_id=scan, action="callers_of", state="done")
        .all()
    )
    assert len(caller_rows) == 1
    assert caller_rows[0].action_args["target_class"] == EXPORT
    assert caller_rows[0].action_args["target_method"] == "onCreate"

    decisions = (
        session.query(DecisionRow)
        .filter_by(investigation_id=scan, action="adaptive_replan")
        .all()
    )
    assert len(decisions) == 1
    assert decisions[0].prompt_version == "nexus-adaptive-replan-v1-deterministic"

    events = (
        session.query(EventRow)
        .filter_by(investigation_id=scan, type="nexus_replanned")
        .all()
    )
    assert len(events) == 1
    assert events[0].payload["next_action"] == "callers_of"

    observation = (
        session.query(ObservationRow)
        .filter_by(investigation_id=scan, subject_type="method")
        .one()
    )
    assert observation.attributes["target_present"] is True
    assert observation.attributes["exhaustive"] is True
