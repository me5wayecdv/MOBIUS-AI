"""DB-level proof that the authorisation guard cannot be bypassed.

The service layer refuses these transitions with a clean 409 (tests/test_intake.py). This
file tests the *backstop*: the ``enforce_authorization_scope`` trigger, which also catches
any writer that goes around the service - a migration, a repair script, a future worker.

It is skipped unless ``MOBIUS_TEST_PG_URL`` points at a live PostgreSQL, because the
trigger is PL/pgSQL and SQLite has no equivalent. The skip is reported as a skip, never as
a pass: the trigger has not been executed in an environment without Postgres.
"""

from __future__ import annotations

import os
import uuid
import hashlib

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from mobius.adapters.db import make_engine
from mobius.adapters.models import Base
from mobius.adapters.postgres import apply_scope_guard

PG_URL = os.environ.get("MOBIUS_TEST_PG_URL")

pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(not PG_URL, reason="set MOBIUS_TEST_PG_URL to run the trigger tests"),
]


@pytest.fixture(scope="module")
def engine():
    eng = make_engine(PG_URL)
    Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)
    apply_scope_guard(eng)
    yield eng
    Base.metadata.drop_all(eng)


def _seed(conn, *, max_intensity: int, expires: str, revoked: str | None = None) -> tuple[str, str]:
    """Insert a user, application and authorisation; return (app_id, auth_id)."""
    uid, app_id, auth_id = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    conn.execute(text(
        "INSERT INTO users (id, email, display_name, role, password_hash, created_at) "
        "VALUES (:id, :email, 'u', 'analyst', 'x', now())"
    ), {"id": uid, "email": f"{uid}@example.invalid"})
    conn.execute(text(
        "INSERT INTO applications (id, sha256, file_size, artifact_key, uploaded_by, created_at) "
        "VALUES (:id, :sha, 1, 'k', :uid, now())"
    ), {"id": app_id, "sha": hashlib.sha256(uid.encode()).hexdigest(), "uid": uid})
    conn.execute(text(
        "INSERT INTO authorizations (id, granted_by, target_package, apk_sha256, scope_text, "
        "max_intensity, statement, expires_at, revoked_at, created_at) VALUES "
        "(:id, :uid, 'com.example', :sha, :scope, :maxi, 's', :exp, :rev, now())"
    ), {"id": auth_id, "uid": uid, "sha": "0" * 64, "scope": "x" * 40,
        "maxi": max_intensity, "exp": expires, "rev": revoked})
    return app_id, auth_id


def _insert_investigation(conn, *, app_id: str, auth_id: str | None, state: str, intensity: int = 0):
    uid = conn.execute(
        text("SELECT uploaded_by FROM applications WHERE id = :app"), {"app": app_id}
    ).scalar_one()
    conn.execute(text(
        "INSERT INTO investigations (id, application_id, authorization_id, created_by, objective, "
        "intensity, state, budget_json, used_json, llm_data_sharing, event_seq, created_at) VALUES "
        "(:id, :app, :auth, :uid, :obj, :inten, :state, '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, 0, now())"
    ), {"id": str(uuid.uuid4()), "app": app_id, "auth": auth_id, "uid": uid,
        "obj": "a sufficiently long objective", "inten": intensity, "state": state})


def _branch_expects(engine, *, state, auth_id, intensity, message):
    with engine.begin() as conn:
        app_id, seeded_auth = _seed(conn, max_intensity=0, expires="2999-01-01T00:00:00Z")
    target = auth_id or seeded_auth
    with pytest.raises(IntegrityError) as exc:
        with engine.begin() as conn:
            _insert_investigation(conn, app_id=app_id, auth_id=target,
                                  state=state, intensity=intensity)
    assert message in str(exc.value).lower()


def test_branch_1_leaving_intake_without_authorization(engine):
    with engine.begin() as conn:
        app_id, _ = _seed(conn, max_intensity=0, expires="2999-01-01T00:00:00Z")
    with pytest.raises(IntegrityError) as exc:
        with engine.begin() as conn:
            _insert_investigation(conn, app_id=app_id, auth_id=None, state="RECON")
    assert "without an authorization" in str(exc.value).lower()


def test_branch_2_revoked_authorization(engine):
    with engine.begin() as conn:
        app_id, auth_id = _seed(conn, max_intensity=2,
                                expires="2999-01-01T00:00:00Z",
                                revoked="2026-01-01T00:00:00Z")
    with pytest.raises(IntegrityError) as exc:
        with engine.begin() as conn:
            _insert_investigation(conn, app_id=app_id, auth_id=auth_id, state="RECON")
    assert "revoked" in str(exc.value).lower()


def test_branch_3_expired_authorization(engine):
    with engine.begin() as conn:
        app_id, auth_id = _seed(conn, max_intensity=2, expires="2020-01-01T00:00:00Z")
    with pytest.raises(IntegrityError) as exc:
        with engine.begin() as conn:
            _insert_investigation(conn, app_id=app_id, auth_id=auth_id, state="RECON")
    assert "expired" in str(exc.value).lower()


def test_branch_4_intensity_above_grant(engine):
    with engine.begin() as conn:
        app_id, auth_id = _seed(conn, max_intensity=0, expires="2999-01-01T00:00:00Z")
    with pytest.raises(IntegrityError) as exc:
        with engine.begin() as conn:
            _insert_investigation(conn, app_id=app_id, auth_id=auth_id,
                                  state="RECON", intensity=2)
    assert "exceeds granted" in str(exc.value).lower()


def test_intake_is_exempt_so_a_refusal_is_auditable(engine):
    """INTAKE and SCOPE_BLOCKED must be writable with no authorisation at all.

    Otherwise a refused scan could not be recorded, and the audit trail would have a hole
    exactly where a refusal happened - which is the interesting case.
    """
    with engine.begin() as conn:
        app_id, _ = _seed(conn, max_intensity=0, expires="2020-01-01T00:00:00Z")
        _insert_investigation(conn, app_id=app_id, auth_id=None, state="INTAKE")
        _insert_investigation(conn, app_id=app_id, auth_id=None, state="SCOPE_BLOCKED")


def test_a_permitted_investigation_is_accepted(engine):
    with engine.begin() as conn:
        app_id, auth_id = _seed(conn, max_intensity=2, expires="2999-01-01T00:00:00Z")
        _insert_investigation(conn, app_id=app_id, auth_id=auth_id, state="RECON", intensity=1)
