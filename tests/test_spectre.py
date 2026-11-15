"""SPECTRE: reachability evidence -> gate -> verdict.

This is the first place in the project where the pipeline can reach `confirmed`, so these
tests are also where overclaiming would be easiest to introduce. Each one checks the whole
chain: a synthetic code graph goes in, a verdict comes out, and the verdict is the one the
evidence supports.

Note what is synthetic and what is not. The *graph* is hand-built here so that each branch is
reachable deterministically; the manifest, database, FSM, gate, services and event log are
all real. `test_dex.py` covers the dex-to-graph translation, and RL-006 records the manual
run against a real APK.
"""

from __future__ import annotations

import pytest

from conftest import make_apk
from mobius.adapters.dex import CodeIndex, DexCoverage
from mobius.adapters.events import SqlEventStore
from mobius.adapters.models import FindingRow, FrontierEntryRow, ObservationRow, VerdictRow
from mobius.core.enums import FindingStatus, InvestigationState, RejectionReason, Verdict
from mobius.core.reachability import CallGraph, CallTarget, MethodRef
from mobius.services import errors
from mobius.services.intake import IntakeService
from mobius.services.recon import ReconService
from mobius.services.spectre import SpectreService

CLS = "com.example.demo.ExportActivity"
FO = CallTarget("Ljava/io/FileOutputStream;", "<init>")
CHECK = CallTarget("Landroid/content/Context;", "checkCallingPermission")

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.demo">
  <application>
    <activity android:name=".ExportActivity" android:exported="true"/>
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
  </application>
</manifest>
"""


def _index(*, guarded: bool = False, truncated: bool = False, has_entry: bool = True,
           has_sink: bool = True) -> CodeIndex:
    """A code graph for one exported activity."""
    root = MethodRef(CLS, "onCreate")
    writer = MethodRef(CLS, "writeSecret")
    if not has_entry:
        return CodeIndex(graph=CallGraph(edges={}), boundary={}, classes=(CLS,), methods=0,
                         dex_coverage=(DexCoverage("fixture.dex", "indexed", 1),))
    if not has_sink:
        boundary = {}
    else:
        boundary = {writer: (FO, CHECK) if guarded else (FO,)}
    return CodeIndex(
        graph=CallGraph(edges={root: (writer,)}),
        boundary=boundary,
        classes=(CLS,),
        methods=2,
        truncated=truncated,
        dex_coverage=(DexCoverage("fixture.dex", "truncated" if truncated else "indexed", 1),),
    )


@pytest.fixture()
def surface_ready(session, store, future_iso):
    """A scan that has completed RECON and is waiting for code analysis."""
    intake = IntakeService(session, store)
    app, _ = intake.create_application(
        make_apk(manifest=MANIFEST), "demo.apk", uploaded_by="analyst-1"
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


def _spectre(session, store, index) -> SpectreService:
    return SpectreService(session, store, indexer=lambda _apk: index)


def test_reachable_unguarded_sink_confirms(session, store, surface_ready):
    result = _spectre(session, store, _index()).analyse(surface_ready)
    assert result["candidates"] == 1
    assert result["confirmed"] == 1
    entry = result["results"][0]
    assert entry["status"] == FindingStatus.CONFIRMED.value
    assert entry["verdict"] == Verdict.CONFIRMED.value
    assert entry["sink"] == "file-write"
    assert entry["path_length"] == 2
    assert entry["attributes"]["sink_reachable"] is True
    assert entry["attributes"]["caller_check_absent"] is True


def test_confirmed_finding_is_persisted_with_its_gate_evidence(session, store, surface_ready):
    _spectre(session, store, _index()).analyse(surface_ready)
    findings = session.query(FindingRow).filter_by(investigation_id=surface_ready).all()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == "confirmed"
    # Capped, not 1.0: the gate passed, but reachability alone cannot prove exploitability.
    assert finding.confidence == 0.9
    assert finding.discovered_by == "SPECTRE"
    assert finding.validated_by == "VERITAS"
    assert all(finding.gate_evidence.values())
    # The finding carries the gate's weakness (exported component), not the sink's - the sink
    # family is recorded on the observation. Two different claims, two different columns.
    assert finding.maswe == ["MASWE-0029"]


def test_guard_on_the_path_rejects_and_names_the_reason(session, store, surface_ready):
    result = _spectre(session, store, _index(guarded=True)).analyse(surface_ready)
    assert result["rejected"] == 1
    entry = result["results"][0]
    assert entry["status"] == FindingStatus.REJECTED.value
    assert entry["verdict"] == Verdict.REJECTED.value
    assert entry["rejection_reason"] == RejectionReason.GUARDED_BY_CALLER_CHECK.value
    assert entry["guards"] == ["check-calling-permission"]
    # Reachability is still true: the path exists. What failed is the claim that there is no
    # caller check, which is a different clause and a different reason.
    assert entry["attributes"]["sink_reachable"] is True
    assert entry["attributes"]["caller_check_absent"] is False


def test_rejection_reason_is_not_mislabelled_as_unreachable(session, store, surface_ready):
    _spectre(session, store, _index(guarded=True)).analyse(surface_ready)
    verdict = session.query(VerdictRow).one()
    assert verdict.verdict == "rejected"
    assert verdict.rejection_reason == "guarded-by-caller-check"
    assert verdict.rejection_reason != "not-reachable"


def test_truncated_index_cannot_support_absence(session, store, surface_ready):
    # The search finds nothing, but the graph it searched was incomplete - so "nothing" is
    # not a finding either way.
    result = _spectre(session, store, _index(truncated=True, has_sink=False)).analyse(surface_ready)
    entry = result["results"][0]
    assert entry["reachability"] == "truncated"
    assert entry["attributes"]["sink_reachable"] is None
    assert entry["status"] == FindingStatus.MANUAL_REVIEW_REQUIRED.value
    assert result["manual_review"] == 1


def test_component_absent_from_the_graph_is_not_called_safe(session, store, surface_ready):
    result = _spectre(session, store, _index(has_entry=False)).analyse(surface_ready)
    entry = result["results"][0]
    assert entry["reachability"] == "no-entry-point"
    assert entry["attributes"] == {
        "exported": True,
        "permission": None,
        "sink_reachable": None,
        "caller_check_absent": None,
    }
    assert entry["status"] == FindingStatus.MANUAL_REVIEW_REQUIRED.value


def test_reachability_is_recorded_as_an_inference_not_a_fact(session, store, surface_ready):
    _spectre(session, store, _index()).analyse(surface_ready)
    observation = (
        session.query(ObservationRow)
        .filter_by(investigation_id=surface_ready, agent="SPECTRE")
        .one()
    )
    assert observation.kind == "inference", (
        "static reachability is a call path in bytecode, not a runtime observation"
    )
    assert observation.confidence < 1.0
    assert observation.attributes["sink"] == "file-write"
    assert observation.maswe == ["MASWE-0001"]
    assert observation.attributes["path"] == [f"{CLS}->onCreate", f"{CLS}->writeSecret"]


def test_walkthrough_of_the_state_machine(session, store, surface_ready):
    _spectre(session, store, _index()).analyse(surface_ready)
    from mobius.adapters.models import InvestigationRow

    row = session.get(InvestigationRow, surface_ready)
    assert row.state == InvestigationState.CORRELATING.value
    events = [e.type for e in SqlEventStore(session).read_after(surface_ready, 0)]
    assert events.count("investigation_updated") == 7  # 2 from intake + 5 from SPECTRE
    assert "evidence_collected" in events
    assert "code_analysis_complete" in events


def test_frontier_entries_are_consumed(session, store, surface_ready):
    _spectre(session, store, _index()).analyse(surface_ready)
    entries = session.query(FrontierEntryRow).filter_by(investigation_id=surface_ready).all()
    assert entries and all(e.state == "done" and e.attempts == 1 for e in entries)


def test_dex_index_is_recorded_as_evidence(session, store, surface_ready):
    _spectre(session, store, _index()).analyse(surface_ready)
    from mobius.adapters.models import EvidenceRow

    kinds = {e.kind for e in session.query(EvidenceRow).filter_by(investigation_id=surface_ready)}
    assert "dex-string" in kinds


def test_spectre_refuses_to_run_before_recon(session, store, future_iso):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(manifest=MANIFEST), "a.apk", uploaded_by="u")
    auth = intake.create_authorization(
        apk_sha256=app.sha256, target_package="com.example.demo",
        scope_text="Static analysis of the supplied artefact only.",
        statement="s", max_intensity=1, granted_by="u", expires_at=future_iso,
    )
    inv = intake.create_investigation(
        application_id=app.id, authorization_id=auth.id,
        objective="Run code analysis out of order to prove it is refused.",
        intensity=0, created_by="u",
    )
    intake.start(inv.id)  # RECON only
    with pytest.raises(errors.ScanStateConflict):
        _spectre(session, store, _index()).analyse(inv.id)


def test_spectre_refuses_to_run_twice(session, store, surface_ready):
    service = _spectre(session, store, _index())
    service.analyse(surface_ready)
    with pytest.raises(errors.ScanStateConflict):
        service.analyse(surface_ready)


def test_missing_artefact_is_a_typed_error(session, store, surface_ready):
    from mobius.services.artifacts import ArtifactStore

    empty = ArtifactStore(store.root / "elsewhere")
    with pytest.raises(errors.CodeIndexFailed):
        SpectreService(session, empty, indexer=lambda _apk: _index()).analyse(surface_ready)


def test_dex_failure_is_reported_not_swallowed(session, store, surface_ready):
    from mobius.adapters.dex import DexIndexError

    def boom(_apk):
        raise DexIndexError("no classes*.dex")

    with pytest.raises(errors.CodeIndexFailed, match="no classes"):
        SpectreService(session, store, indexer=boom).analyse(surface_ready)


def _scan(session, intake: IntakeService, store, apk: bytes, future_iso: str) -> str:
    """Upload, authorise, start and run RECON. Returns an investigation id."""
    app, _ = intake.create_application(apk, "demo.apk", uploaded_by="analyst-1")
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


def test_the_same_apk_yields_the_same_result_every_time(session, store, future_iso):
    """The determinism requirement, at the level an auditor would check it.

    Two independent investigations over identical bytes, each analysed by its own service
    instance, must produce byte-identical verdicts. No model, no clock, no randomness is in
    the path (ADR-022) - if any were, this test would be flaky, which is the point.
    """
    import json

    apk = make_apk(manifest=MANIFEST)
    intake = IntakeService(session, store)
    first = _spectre(session, store, _index())
    second = _spectre(session, store, _index())

    a = first.analyse(_scan(session, intake, store, apk, future_iso))
    b = second.analyse(_scan(session, intake, store, apk, future_iso))

    # Identifiers are generated per run (ULIDs) and are expected to differ. The *decision*
    # is what must not: same component, same path, same verdict, same reason.
    decision = ("component", "kind", "reachability", "sink", "guards", "path_length",
                "verdict", "status", "rejection_reason", "explanation", "attributes")

    def stable(result: dict) -> str:
        return json.dumps(
            [{k: r.get(k) for k in decision} for r in result["results"]], sort_keys=True
        )

    assert stable(a) == stable(b)
    assert a["confirmed"] == b["confirmed"] == 1


def test_a_repeat_run_is_refused_rather_than_duplicating_evidence(session, store, surface_ready):
    """SPECTRE moves the investigation past SURFACE_READY, so a second call is a state error.

    Determinism does not mean re-runnable in place: running twice would append a second
    observation and a second finding for the same component, and the evidence log would
    claim the analysis happened twice. Recovery is a new investigation, not a retry.
    """
    _spectre(session, store, _index()).analyse(surface_ready)
    with pytest.raises(errors.ScanStateConflict) as caught:
        _spectre(session, store, _index()).analyse(surface_ready)
    assert "SPECTRE" in str(caught.value)


def test_a_confirmed_finding_is_never_certain(session, store, surface_ready):
    """0.1 of doubt is permanent: no path proves the data on it is attacker-controlled."""
    result = _spectre(session, store, _index()).analyse(surface_ready)
    finding = session.query(FindingRow).filter_by(id=result["results"][0]["finding_id"]).one()
    assert finding.status == "confirmed"
    assert finding.confidence < 1.0
    assert finding.confidence == 0.9


def test_a_rejected_finding_reports_no_path_rather_than_a_zero_length_one(
    session, store, surface_ready
):
    """`path_length: 0` reads as "the entry point is the sink". There is no path, so: null."""
    result = _spectre(session, store, _index(has_sink=False)).analyse(surface_ready)
    entry = result["results"][0]
    assert entry["reachability"] == "not-reached"
    assert entry["path_length"] is None
    assert entry["attributes"] == {
        "exported": True,
        "permission": None,
        "sink_reachable": False,
        "caller_check_absent": None,
    }


def test_the_finding_title_matches_what_the_search_established(session, store, surface_ready):
    """A refuted search is not an unfinished one, and the title is what an analyst reads first."""
    rejected = _spectre(session, store, _index(has_sink=False)).analyse(surface_ready)
    title = session.query(FindingRow).filter_by(
        id=rejected["results"][0]["finding_id"]
    ).one().title
    assert "no sensitive sink reachable" in title
    assert "not established" not in title


def test_an_unfinished_search_says_so_in_its_title(session, store, surface_ready):
    # Truncated *and* nothing found: the search cannot be read as a refutation.
    result = _spectre(session, store, _index(truncated=True, has_sink=False)).analyse(surface_ready)
    title = session.query(FindingRow).filter_by(
        id=result["results"][0]["finding_id"]
    ).one().title
    assert "reachability not established" in title
    assert result["results"][0]["status"] == "manual_review_required"


def test_a_truncated_index_cannot_confirm_even_when_the_sink_is_reached(
    session, store, surface_ready
):
    """Regression, found by NEXUS: truncation only downgraded `not-reached`.

    A found path proves its own methods. It does not prove that no *unindexed* caller checks
    the permission before invoking it, so on an incomplete graph `caller_check_absent` is
    not established - and a candidate with an unestablished clause is not confirmed.
    """
    result = _spectre(session, store, _index(truncated=True)).analyse(surface_ready)
    entry = result["results"][0]

    assert entry["reachability"] == "reached"
    assert entry["status"] == "manual_review_required"
    assert entry["attributes"]["sink_reachable"] is True
    assert entry["attributes"]["caller_check_absent"] is None
    assert result["confirmed"] == 0
