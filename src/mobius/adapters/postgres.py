"""Postgres-only DDL that SQLAlchemy models cannot express.

Kept separate so the authorization trigger is reviewable as SQL and executable in tests.
"""

from __future__ import annotations

from importlib import resources

from sqlalchemy import Engine

_SQL_DIR = "sql"


def scope_guard_sql() -> str:
    return resources.files(__package__).joinpath(_SQL_DIR, "scope_guard.sql").read_text(encoding="utf-8")


def _split_sql_statements(sql: str) -> list[str]:
    """Split SQL at top-level semicolons while preserving dollar-quoted function bodies."""
    # The bundled DDL uses full-line SQL comments only.
    sql = "\n".join(
        line for line in sql.splitlines() if not line.lstrip().startswith("--")
    )
    statements: list[str] = []
    current: list[str] = []
    dollar_tag: str | None = None
    i = 0

    while i < len(sql):
        if sql[i] == "$":
            if dollar_tag is None:
                end = sql.find("$", i + 1)
                if end == -1:
                    raise ValueError("invalid PostgreSQL dollar-quote delimiter")
                dollar_tag = sql[i : end + 1]
                current.append(dollar_tag)
                i = end + 1
                continue
            if sql.startswith(dollar_tag, i):
                current.append(dollar_tag)
                i += len(dollar_tag)
                dollar_tag = None
                continue

        char = sql[i]
        if char == ";" and dollar_tag is None:
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current.clear()
        else:
            current.append(char)
        i += 1

    if dollar_tag is not None:
        raise ValueError("unterminated PostgreSQL dollar-quoted body in scope guard SQL")
    trailing = "".join(current).strip()
    if trailing:
        statements.append(trailing)
    return statements


def apply_scope_guard(engine: Engine) -> None:
    """Install the authorization trigger. Idempotent."""
    with engine.begin() as conn:
        for statement in _split_sql_statements(scope_guard_sql()):
            conn.exec_driver_sql(statement)
