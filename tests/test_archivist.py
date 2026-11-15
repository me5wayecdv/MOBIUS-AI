"""ARCHIVIST: the report must not be the place where the project starts lying.

Every test here checks a sentence the report is *allowed* to say, and one it is not. The
document is generated from rows, so most of these assertions are about the absence of
invented prose as much as the presence of real numbers.
"""

from __future__ import annotations

import pytest

from conftest import make_apk
from mobius.adapters.dex import CodeIndex
from mobius.adapters.models import EvidenceRow, FrontierEntryRow
from mobius.core.enums import EvidenceKind
from mobius.core.ids import IdPrefix, new_id
from mobius.core.reachability import CallGraph, CallTarget, MethodRef
from mobius.services import errors
from mobius.services.archivist import ArchivistService
from mobius.services.intake import IntakeService
from mobius.services.nexus import NexusService
from mobius.services.recon import ReconService
from mobius.services.spectre import SpectreService

CLS = "com.example.demo.ExportActivity"
FO = CallTarget("Ljava/io/FileOutputStream;", "<init>")

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.demo">
  <application>
    <activity android:name=".ExportActivity" android:exported="true"/>
  </application>
</manifest>
"""


def _index(*, sink: bool = True, truncated: bool = False) -> CodeIndex:
    root = MethodRef(CLS, "onCreate")
    return CodeIndex(
        graph=CallGraph(edges={root: ()}),
        boundary={root: (FO,)} if sink else {},
        classes=(CLS,),
        methods=1,
        truncated=truncated,
    )


def _scan(session, store, future_iso) -> str:
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


def _confirmed_scan(session, store, future_iso) -> str:
    scan = _scan(session, store, future_iso)
    SpectreService(session, store, indexer=lambda _apk: _index()).analyse(scan)
    return scan


def _rejected_scan(session, store, future_iso) -> str:
    scan = _scan(session, store, future_iso)
    SpectreService(session, store, indexer=lambda _apk: _index(sink=False)).analyse(scan)
    return scan


def _text(session, store, scan) -> str:
    return ArchivistService(session, store).build(scan, generated_at="2026-11-15T00:00:00Z").markdown


# -- it reports what happened ---------------------------------------------------------


def test_the_report_identifies_the_artefact_and_the_authority(session, store, future_iso):
    scan = _confirmed_scan(session, store, future_iso)
    text = _text(session, store, scan)

    assert scan in text
    assert "SHA-256" in text
    assert "Determine whether exported components reach a privileged sink." in text
    assert "Scope of the grant" in text
    assert "no execution" in text


def test_a_confirmed_finding_is_reported_with_its_gate_evidence(session, store, future_iso):
    scan = _confirmed_scan(session, store, future_iso)
    text = _text(session, store, scan)

    assert "## 3. Confirmed findings" in text
    assert "reaches a sensitive sink" in text
    assert "| `sink_reachable` | yes |" in text
    assert "| `caller_check_absent` | yes |" in text
    assert "**validated by** VERITAS" in text
    # The confidence cap must survive into the document.
    assert "0.9" in text


def test_a_rejection_is_reported_with_the_reason_it_was_rejected(session, store, future_iso):
    scan = _rejected_scan(session, store, future_iso)
    text = _text(session, store, scan)

    assert "## 4. Rejected hypotheses" in text
    assert "A rejection is a conclusion reached on evidence, not a silence." in text
    assert "`not-reachable`" in text
    assert "no sensitive sink reachable" in text


def test_the_outcome_sentence_matches_the_counts(session, store, future_iso):
    scan = _confirmed_scan(session, store, future_iso)
    text = _text(session, store, scan)

    assert "| Confirmed | 1 |" in text
    assert "1 finding was confirmed by the gate" in text


def test_an_investigation_with_no_hypotheses_says_so_instead_of_implying_safety(
    session, store, future_iso
):
    scan = _scan(session, store, future_iso)  # RECON only, no findings
    text = _text(session, store, scan)

    assert "No hypothesis was evaluated" in text
    assert "not about the application's security" in text
    assert "## 3. Confirmed findings\n\nNone." in text


# -- the "not determined" section ------------------------------------------------------


def test_findings_needing_a_human_are_listed_as_undetermined(session, store, future_iso):
    scan = _scan(session, store, future_iso)
    SpectreService(session, store, indexer=lambda _apk: _index(truncated=True)).analyse(scan)
    text = _text(session, store, scan)

    assert "## 5. Not determined" in text
    assert "Findings requiring a human decision" in text
    # The finding itself, by id, not a paraphrase of it.
    from mobius.adapters.models import FindingRow

    finding = session.query(FindingRow).filter_by(investigation_id=scan).one()
    assert finding.status == "manual_review_required"
    assert finding.id in text
    assert "Nothing in this investigation was left undetermined" not in text


def test_work_the_budget_skipped_appears_in_the_report(session, store, future_iso):
    """A closed scan with an unrun entry must not read as a finished one."""
    scan = _scan(session, store, future_iso)
    session.add(
        FrontierEntryRow(
            id=new_id(IdPrefix.FRONTIER),
            investigation_id=scan,
            action="find_string",
            action_args={"component": CLS},
            required_agent="PHANTOM",
            relates_to_maswe=[],
            score=0.0,
            depth=0,
            state="queued",
            attempts=0,
            inserted_at="2026-11-15T00:00:00Z",
        )
    )
    session.flush()
    NexusService(
        session, store, spectre=SpectreService(session, store, indexer=lambda _apk: _index())
    ).run(scan)

    text = _text(session, store, scan)

    assert "Work that was queued and not completed" in text
    assert "find_string" in text
    assert "PHANTOM" in text


def test_an_empty_undetermined_section_still_states_the_blind_spots(session, store, future_iso):
    scan = _confirmed_scan(session, store, future_iso)
    text = _text(session, store, scan)

    assert "Nothing in this investigation was left undetermined" in text
    # ...but never without the caveat that follows it.
    assert "no data-flow analysis" in text.lower()


# -- the part that must always be there ------------------------------------------------


def test_every_report_states_what_the_method_cannot_see(session, store, future_iso):
    for scan in (
        _scan(session, store, future_iso),
        _rejected_scan(session, store, future_iso),
    ):
        text = _text(session, store, scan)
        assert "No data-flow analysis" in text
        assert "Absence of a finding is not evidence of absence." in text
        assert "No language model was called" in text
        assert "No control-flow analysis" in text


# -- storage and reproducibility -------------------------------------------------------


def test_the_report_is_stored_as_evidence_and_emitted(session, store, future_iso):
    scan = _confirmed_scan(session, store, future_iso)
    written = ArchivistService(session, store).write(scan, generated_at="2026-11-15T00:00:00Z")

    row = session.get(EvidenceRow, written["evidence_id"])
    assert row is not None
    assert row.kind == EvidenceKind.REPORT.value
    assert row.sha256 == written["sha256"]
    assert row.produced_by == "ARCHIVIST"

    from mobius.adapters.models import EventRow

    types = [
        e.type
        for e in session.query(EventRow).filter_by(investigation_id=scan).order_by(EventRow.seq)
    ]
    assert "report_written" in types


def test_the_same_rows_produce_byte_identical_reports(session, store, future_iso):
    scan = _confirmed_scan(session, store, future_iso)
    service = ArchivistService(session, store)
    first = service.build(scan, generated_at="2026-11-15T00:00:00Z").markdown
    second = service.build(scan, generated_at="2026-11-15T00:00:00Z").markdown

    assert first == second


def test_writing_a_second_report_creates_a_second_document_and_says_why(
    session, store, future_iso
):
    """Writing a report is itself an event, so the second document is not the first.

    That is not a bug to design away: the second report is generated from a state that
    includes the first report's own `report_written` / `evidence_collected` events. Pretending
    the two are byte-identical would require the document to lie about its own history.
    """
    from mobius.adapters.models import EventRow

    scan = _confirmed_scan(session, store, future_iso)
    service = ArchivistService(session, store)
    one = service.write(scan, generated_at="2026-11-15T00:00:00Z")
    two = service.write(scan, generated_at="2026-11-15T00:00:00Z")

    assert one["evidence_id"] != two["evidence_id"]
    assert two["duplicate"] is False
    writes = [
        e
        for e in session.query(EventRow).filter_by(investigation_id=scan)
        if e.type == "report_written"
    ]
    assert len(writes) == 2, "each document is announced once"
    # The later document is what `latest` returns.
    assert service.latest(scan) == two["markdown"]


def test_the_report_reflects_the_investigation_at_the_moment_it_is_built(
    session, store, future_iso
):
    """An event added after the first build must appear in a later one.

    This is the property that made an idempotent rewrite impossible to claim honestly: the
    document is a function of the rows, and writing it adds rows.
    """
    from mobius.adapters.models import EventRow

    scan = _confirmed_scan(session, store, future_iso)
    service = ArchivistService(session, store)
    before = service.build(scan, generated_at="2026-11-15T00:00:00Z").markdown

    from mobius.adapters.events import SqlEventStore

    SqlEventStore(session).emit(scan, "manual_note", {"text": "analyst looked again"})
    session.flush()
    after = service.build(scan, generated_at="2026-11-15T00:00:00Z").markdown

    assert before != after
    assert "manual_note" in after
    events = session.query(EventRow).filter_by(investigation_id=scan).all()
    counted = [e for e in events if not e.type.startswith("report_")]
    assert f"{len(counted)} events" in after  # report_* events are excluded from the summary


def test_latest_reads_back_what_was_written(session, store, future_iso):
    scan = _confirmed_scan(session, store, future_iso)
    service = ArchivistService(session, store)
    written = service.write(scan, generated_at="2026-11-15T00:00:00Z")

    assert service.latest(scan) == written["markdown"]


def test_reading_a_report_that_does_not_exist_is_a_typed_error(session, store, future_iso):
    scan = _scan(session, store, future_iso)
    with pytest.raises(errors.NotFound):
        ArchivistService(session, store).latest(scan)


def test_the_report_quotes_no_finding_it_was_not_given(session, store, future_iso):
    """A negative control: nothing in this scan may appear in the confirmed section."""
    scan = _rejected_scan(session, store, future_iso)
    text = _text(session, store, scan)
    confirmed = text.split("## 3. Confirmed findings")[1].split("## 4.")[0]

    assert "None." in confirmed
    assert "reaches a sensitive sink" not in confirmed


def test_the_report_describes_a_closed_investigation_not_a_running_one(session, store, future_iso):
    """Regression: the report was written during REPORTING, so it said the scan was still
    reporting and its stop reason was "not recorded" — in the document a reader keeps."""
    scan = _scan(session, store, future_iso)
    result = NexusService(
        session, store, spectre=SpectreService(session, store, indexer=lambda _apk: _index())
    ).run(scan)
    assert result["state"] == "CLOSED"
    assert result["report_id"] is not None

    text = ArchivistService(session, store).latest(scan)
    assert "| Final state | `CLOSED` |" in text
    assert "| Stop reason | `completed` |" in text
    assert "`REPORTING`" not in text
