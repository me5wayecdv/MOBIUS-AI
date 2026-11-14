"""The event log is the audit trail; it must be append-only and gap-free."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError

from mobius.adapters.events import SqlEventStore
from mobius.adapters.models import EventRow
from mobius.core.enums import InvestigationState
from mobius.services.intake import IntakeService


@pytest.fixture()
def scan(session, store, future_iso):
    from conftest import make_apk

    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "a.apk", uploaded_by="analyst-1")
    auth = intake.create_authorization(
        apk_sha256=app.sha256,
        target_package="com.example",
        scope_text="Static analysis of the supplied artefact only.",
        statement="granted",
        max_intensity=2,
        granted_by="analyst-1",
        expires_at=future_iso,
    )
    inv = intake.create_investigation(
        application_id=app.id,
        authorization_id=auth.id,
        objective="Determine whether any exported component reaches a privileged sink.",
        intensity=0,
        created_by="analyst-1",
    )
    return inv.id


def test_sequence_starts_at_one_and_increments(session, scan):
    store = SqlEventStore(session)
    assert store.current_seq(scan) == 0
    first = store.emit(scan, "investigation_started", {"a": 1}, actor="NEXUS")
    second = store.emit(scan, "x", {}, actor="NEXUS")
    assert (first, second) == (1, 2)
    assert store.current_seq(scan) == 2
    assert store.count(scan) == 2


def test_read_after_is_exclusive(session, scan):
    store = SqlEventStore(session)
    for i in range(5):
        store.emit(scan, f"e{i}", {})
    assert [e.seq for e in store.read_after(scan, after_seq=2)] == [3, 4, 5]
    assert [e.seq for e in store.read_after(scan, after_seq=0, limit=2)] == [1, 2]


def test_payload_round_trips(session, scan):
    store = SqlEventStore(session)
    payload = {"nested": {"a": [1, 2, 3]}, "flag": True, "none": None}
    store.emit(scan, "x", payload, actor="SPECTRE", causation_id="dec_1")
    stored = store.read_after(scan, after_seq=0)[0]
    assert stored.payload == payload
    assert stored.actor == "SPECTRE"
    assert stored.causation_id == "dec_1"


def test_sequences_are_independent_per_investigation(session, scan, store, future_iso):
    from conftest import make_apk

    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(manifest="<manifest package='com.other'/>"), "b.apk", uploaded_by="u")
    auth = intake.create_authorization(
        apk_sha256=app.sha256, target_package="com.other",
        scope_text="Static analysis of the supplied artefact only.",
        statement="s", max_intensity=0, granted_by="u", expires_at=future_iso,
    )
    other = intake.create_investigation(
        application_id=app.id, authorization_id=auth.id,
        objective="A second case for a different application.", intensity=0, created_by="u",
    )
    events = SqlEventStore(session)
    events.emit(scan, "a", {})
    events.emit(other.id, "b", {})
    assert events.current_seq(scan) == 1
    assert events.current_seq(other.id) == 1


def test_duplicate_sequence_is_rejected_by_the_database(session, scan):
    """The unique constraint, not the application, is what guarantees no gaps remain."""
    store = SqlEventStore(session)
    store.emit(scan, "a", {})
    session.add(
        EventRow(
            id="evt_dupe", investigation_id=scan, seq=1, type="dupe", payload={},
            actor="x", created_at=store.read_after(scan, 0)[0].created_at,
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_start_emits_started_then_transition(session, store, future_iso):
    from conftest import make_apk

    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "a.apk", uploaded_by="u")
    auth = intake.create_authorization(
        apk_sha256=app.sha256, target_package="com.example",
        scope_text="Static analysis of the supplied artefact only.",
        statement="s", max_intensity=2, granted_by="u", expires_at=future_iso,
    )
    inv = intake.create_investigation(
        application_id=app.id, authorization_id=auth.id,
        objective="Check whether storage keys are attacker-reachable.", intensity=0, created_by="u",
    )
    intake.start(inv.id)
    types = [e.type for e in SqlEventStore(session).read_after(inv.id, 0)]
    assert types == ["investigation_started", "investigation_updated"]
    assert intake.get_investigation(inv.id).state is InvestigationState.RECON
