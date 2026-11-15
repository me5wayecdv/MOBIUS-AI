"""The assertions are in the database, not only in Pydantic.

Pydantic guards the application path. A CHECK constraint guards every path - including a
psql session, a repair script, or a future service that forgets to construct a model. These
tests write raw SQL on purpose, deliberately going around the domain layer, to prove the
constraint is the thing that holds.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from mobius.adapters.events import utcnow
from mobius.services.intake import IntakeService

from conftest import make_apk


@pytest.fixture()
def seeded(session, store, future_iso):
    """Create the rows a raw insert needs to satisfy foreign keys."""
    from sqlalchemy import insert

    from mobius.adapters.models import ApplicationRow, AuthorizationRow, UserRow

    now = utcnow()
    session.add(UserRow(id="u1", email="u1@x.invalid", display_name="u1", role="analyst",
                        password_hash="x", created_at=now))
    session.flush()
    session.add(ApplicationRow(id="app_1", sha256="a" * 64, file_size=1, artifact_key="k",
                               uploaded_by="u1", created_at=now))
    session.flush()
    session.add(AuthorizationRow(id="ath_1", granted_by="u1", target_package="com.example",
                                 apk_sha256="a" * 64, scope_text="x" * 40, max_intensity=1,
                                 statement="s", expires_at="2999-01-01T00:00:00Z",
                                 created_at=now))
    session.execute(text(
        "INSERT INTO investigations (id, application_id, authorization_id, created_by, objective, "
        "intensity, state, budget_json, used_json, llm_data_sharing, event_seq, created_at) "
        "VALUES ('inv_obs', 'app_1', 'ath_1', 'u1', :obj, 0, 'INTAKE', '{}', '{}', '{}', 0, :now)"
    ), {"obj": "an objective of sufficient length", "now": now})
    # Commit so that a later rollback (from a deliberately failing insert) does not also
    # undo the fixtures. Without this the FK parents vanish and the test fails for the
    # wrong reason - which is exactly how this file first failed.
    session.commit()
    return session


def _insert_observation(session, **kw):
    cols = {
        "id": kw.pop("id", "obs_1"),
        "investigation_id": kw.pop("investigation_id", "inv_obs"),
        "agent": "RECON",
        "kind": kw.pop("kind", "fact"),
        "fidelity": "binary-xml",
        "statement": "the manifest declares android:exported",
        "attributes": "{}",
        "maswe": "[]",
        "confidence": kw.pop("confidence", 1.0),
        "evidence_refs": kw.pop("evidence_refs", '["ev_1"]'),
        "created_at": utcnow(),
    }
    cols.update(kw)
    names = ", ".join(cols)
    params = ", ".join(f":{k}" for k in cols)
    session.execute(text(f"INSERT INTO observations ({names}) VALUES ({params})"), cols)
    session.flush()


def test_fact_without_evidence_is_rejected_by_the_database(session, seeded):
    with pytest.raises(IntegrityError, match="facts_have_evidence"):
        _insert_observation(session, evidence_refs="[]")
    session.rollback()


def test_certainty_is_required_for_facts(session, seeded):
    with pytest.raises(IntegrityError, match="facts_are_certain"):
        _insert_observation(session, confidence=0.6)
    session.rollback()


def test_a_non_fact_may_be_uncertain_and_uncited(session, seeded):
    _insert_observation(session, kind="anomaly", confidence=0.2, evidence_refs="[]")
    assert session.execute(
        text("SELECT count(*) FROM observations WHERE id = 'obs_1'")
    ).scalar() == 1


def test_pause_flag_and_actor_must_be_set_together(session, seeded):
    base = ("INSERT INTO investigations (id, application_id, authorization_id, created_by, "
            "objective, intensity, state, budget_json, used_json, llm_data_sharing, event_seq, "
            "paused_at, paused_by, created_at) VALUES (:id, 'app_1', 'ath_1', 'u1', :obj, 0, "
            "'INTAKE', '{}', '{}', '{}', 0, :paused_at, :paused_by, :created_at)")
    common = {"obj": "an objective of sufficient length", "created_at": utcnow()}

    with pytest.raises(IntegrityError, match="pause_is_coherent"):
        session.execute(text(base), {**common, "id": "inv_p1", "paused_at": "2026-01-01T00:00:00Z",
                                     "paused_by": None})
    session.rollback()

    with pytest.raises(IntegrityError, match="pause_is_coherent"):
        session.execute(text(base), {**common, "id": "inv_p2", "paused_at": None,
                                     "paused_by": "u1"})
    session.rollback()

    session.execute(text(base), {**common, "id": "inv_p3", "paused_at": "2026-01-01T00:00:00Z",
                                 "paused_by": "u1"})
    assert session.execute(
        text("SELECT count(*) FROM investigations WHERE id = 'inv_p3'")
    ).scalar() == 1


def test_unknown_state_is_rejected(session, seeded):
    with pytest.raises(IntegrityError, match="state_known"):
        session.execute(text(
            "INSERT INTO investigations (id, application_id, authorization_id, created_by, "
            "objective, intensity, state, budget_json, used_json, llm_data_sharing, event_seq, "
            "created_at) VALUES ('inv_x', 'app_1', 'ath_1', 'u1', :obj, 0, 'PAUSED', '{}', '{}', "
            "'{}', 0, :now)"
        ), {"obj": "an objective of sufficient length", "now": utcnow()})
    session.rollback()


def test_intensity_outside_range_is_rejected(session, seeded):
    with pytest.raises(IntegrityError, match="intensity_range"):
        session.execute(text(
            "INSERT INTO investigations (id, application_id, authorization_id, created_by, "
            "objective, intensity, state, budget_json, used_json, llm_data_sharing, event_seq, "
            "created_at) VALUES ('inv_y', 'app_1', 'ath_1', 'u1', :obj, 5, 'INTAKE', '{}', '{}', "
            "'{}', 0, :now)"
        ), {"obj": "an objective of sufficient length", "now": utcnow()})
    session.rollback()


def test_an_approval_cannot_grant_more_than_was_requested(session, seeded):
    """Escalation by approval would defeat the point of having approvals at all."""
    stmt = text(
        "INSERT INTO approvals (id, investigation_id, requested_action, intensity_required, "
        "intensity_granted, justification, risk_summary, state, requested_by, expires_at, "
        "created_at) VALUES ('apr_1', :inv, 'frida_instrument', 1, :granted, :just, 'risk', "
        "'granted', 'u1', '2999-01-01T00:00:00Z', :now)"
    )
    with pytest.raises(IntegrityError, match="grant_within_request"):
        session.execute(stmt, {"inv": "inv_obs", "granted": 3, "just": "y" * 20, "now": utcnow()})
    session.rollback()


def test_duplicate_event_sequence_is_rejected(session, seeded):
    from mobius.adapters.models import EventRow

    session.add(EventRow(id="e1", investigation_id="inv_obs", seq=1, type="a", payload={},
                         actor="x", created_at=utcnow()))
    session.add(EventRow(id="e2", investigation_id="inv_obs", seq=1, type="b", payload={},
                         actor="x", created_at=utcnow()))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_foreign_keys_are_actually_enforced_by_sqlite(session):
    """SQLite ignores foreign keys unless the pragma is on per connection."""
    assert session.execute(text("PRAGMA foreign_keys")).scalar() == 1
