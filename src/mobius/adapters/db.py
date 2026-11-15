"""Database engine and session plumbing.

Deviation from docs/ARCHITECTURE.md, recorded in ADR-018: ``create_all`` is used to
materialise the schema in development and tests. The deployment path is Alembic
migrations; ``create_all`` is deliberately *not* how production gets its schema, because
it cannot express an additive migration or a rollback.

SQLite support exists for development and CI only. The documented fallback
(docs/DATABASE_SCHEMA.md 7) notes the consequences: no ``FOR UPDATE SKIP LOCKED`` for
parallel workers, and ``LISTEN/NOTIFY`` unavailable, so the event bridge becomes
in-process. CI must also run Postgres before Phase 2 is called done.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .models import Base

DEFAULT_URL = "sqlite+pysqlite:///./data/mobius.db"


def make_engine(url: str = DEFAULT_URL, *, echo: bool = False) -> Engine:
    """Build an engine for ``url``.

    SQLite needs ``check_same_thread=False`` because the API hands sessions across the
    TestClient's thread; an in-memory database additionally needs ``StaticPool`` or each
    connection would get its own empty database - a classic source of tests that pass
    while proving nothing.
    """
    if url.startswith("sqlite"):
        kwargs: dict[str, object] = {"connect_args": {"check_same_thread": False}, "echo": echo}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
        engine = create_engine(url, **kwargs)

        @event.listens_for(engine, "connect")
        def _enable_foreign_keys(dbapi_conn, _record):  # pragma: no cover - driver hook
            # SQLite ignores foreign keys unless asked. Without this the tests would
            # happily insert rows pointing at investigations that do not exist.
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        return engine

    return create_engine(url, echo=echo, pool_pre_ping=True)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def init_schema(engine: Engine) -> None:
    """Create tables if absent. Development and test convenience only - see module docstring."""
    Base.metadata.create_all(engine)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on any exception."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
