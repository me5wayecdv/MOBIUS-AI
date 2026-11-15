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


def _split_sql_statements(sql: str) -> list[str]:
    """Split SQL on statement terminators, without splitting PL/pgSQL dollar bodies."""
    statements: list[str] = []
    current: list[str] = []
    in_dollar_quote = False
    i = 0
    while i < len(sql):
        if sql.startswith("$", i):
            in_dollar_quote = not in_dollar_quote
            current.append("$")
            i += 2
            continue
        char = sql[i]
        if char == ";" and not in_dollar_quote:
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current.clear()
        else:
            current.append(char)
        i += 1
    trailing = "".join(current).strip()
    if trailing:
        statements.append(trailing)
    if in_dollar_quote:
        raise ValueError("unterminated PostgreSQL dollar-quoted body in scope guard SQL")
    return statements


def apply_scope_guard(engine: Engine) -> None:
    """Install ``enforce_authorization_scope`` and its trigger. Idempotent."""
    with engine.begin() as conn:
        for statement in _split_sql_statements(scope_guard_sql()):
            if not all(line.startswith("--") or not line.strip() for line in statement.splitlines()):
                conn.execute(text(statement))
