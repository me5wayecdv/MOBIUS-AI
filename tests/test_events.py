"""The event log is the audit trail; it must be append-only and gap-free."""

from __future__ import annotations

import os

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from mobius.adapters.events import SqlEventStore
from mobius.adapters.models import EventRow, InvestigationRow
from mobius.core.enums import InvestigationState
from mobius.services.intake import IntakeService

PG_URL = os.environ.get("MOBIUS_TEST_PG_URL")


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


def test_stale_identity_map_cannot_reuse_sequence(session, scan):
    """Another session's committed increment must not be re-allocated by this one.

    Regression test: the counter was read through this session's identity map, so after
    a second session emitted and committed, this session's next emit re-used the stale
    ``event_seq`` and collided on UNIQUE(investigation_id, seq). The allocation is now
    one atomic UPDATE...RETURNING in the database.
    """
    store = SqlEventStore(session)
    assert store.emit(scan, "before", {}) == 1
    # Prime the identity map with the counter value this session has seen.
    primed = session.get(InvestigationRow, scan)
    assert primed.event_seq == 1

    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)
    other = factory()
    try:
        assert SqlEventStore(other).emit(scan, "other_session", {}) == 2
        other.commit()
    finally:
        other.close()

    # Old behavior allocated 2 again here and raised IntegrityError on flush.
    assert store.emit(scan, "after", {}) == 3
    session.flush()
    assert store.current_seq(scan) == 3
    assert [e.seq for e in store.read_after(scan, after_seq=0)] == [1, 2, 3]


@pytest.mark.postgres
@pytest.mark.skipif(not PG_URL, reason="set MOBIUS_TEST_PG_URL to run PostgreSQL event concurrency tests")
def test_postgres_concurrent_emits_allocate_unique_monotonic_sequences(tmp_path, future_iso):
    """Two sessions racing on one investigation get a gap-free, unique sequence."""
    from concurrent.futures import ThreadPoolExecutor

    from conftest import make_apk
    from mobius.adapters.db import make_engine, make_session_factory
    from mobius.adapters.models import Base
    from mobius.services.artifacts import ArtifactStore

    engine = make_engine(PG_URL)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    artifact_store = ArtifactStore(tmp_path / "pg-event-artifacts")
    setup = factory()
    try:
        intake = IntakeService(setup, artifact_store)
        app, _ = intake.create_application(make_apk(), "pg-events.apk", uploaded_by="events-pg-test")
        auth = intake.create_authorization(
            apk_sha256=app.sha256,
            target_package="com.example",
            scope_text="PostgreSQL concurrency test for atomic event sequence allocation.",
            statement="I own this fixture APK",
            max_intensity=0,
            granted_by="events-pg-test",
            expires_at=future_iso,
        )
        inv = intake.create_investigation(
            application_id=app.id,
            authorization_id=auth.id,
            objective="Prove concurrent event emits allocate unique monotonic sequences",
            intensity=0,
            created_by="events-pg-test",
        )
        scan_id = inv.id
        setup.commit()
    finally:
        setup.close()

    def emit_batch(_index):
        racing = factory()
        try:
            racing_store = SqlEventStore(racing)
            seqs = [racing_store.emit(scan_id, "race", {}) for _ in range(10)]
            racing.commit()
            return seqs
        finally:
            racing.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(emit_batch, range(2)))

    allocated = sorted(seq for batch in results for seq in batch)
    assert allocated == list(range(1, 21))

    verify = factory()
    try:
        row = verify.get(InvestigationRow, scan_id)
        assert row.event_seq == 20
        verify_store = SqlEventStore(verify)
        assert verify_store.current_seq(scan_id) == 20
        assert verify_store.count(scan_id) == 20
    finally:
        verify.close()
        engine.dispose()
