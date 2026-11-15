"""Postgres-only DDL that SQLAlchemy models cannot express.

Kept in its own module and its own ``.sql`` file rather than buried in a migration so that
the trigger which enforces FR-AUTH-2 is reviewable as SQL, executable in a test, and
applicable by an operator without Python.
"""

from __future__ import annotations

from importlib import resources

from sqlalchemy import Engine, text

_SQL_DIR = "sql"


def scope_guard_sql() -> str:
    return resources.files(__package__).joinpath(_SQL_DIR, "scope_guard.sql").read_text(encoding="utf-8")


def apply_scope_guard(engine: Engine) -> None:
    """Install ``enforce_authorization_scope`` and its trigger. Idempotent."""
    statements = [s.strip() for s in scope_guard_sql().split("\n\n")]
    with engine.begin() as conn:
        for statement in statements:
            if statement and not all(line.startswith("--") or not line.strip() for line in statement.splitlines()):
                conn.execute(text(statement))
