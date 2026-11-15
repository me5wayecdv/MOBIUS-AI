"""The migration history must stay the truth about the schema.

`create_all()` is how the tests build their database, which means the tests would keep passing
even if the migrations stopped matching the models. These checks close that hole: a fresh
database is built **only** by `alembic upgrade head`, and the result is compared to the models.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

ROOT = Path(__file__).resolve().parent.parent
ALEMBIC = ROOT / ".venv" / "bin" / "alembic"


def _alembic(db_url: str, *args: str) -> subprocess.CompletedProcess:
    binary = str(ALEMBIC) if ALEMBIC.exists() else "alembic"
    env = {**os.environ, "MOBIUS_DB_URL": db_url}
    return subprocess.run(
        [binary, *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )


@pytest.fixture()
def migrated(tmp_path) -> str:
    url = f"sqlite+pysqlite:///{tmp_path / 'migrated.db'}"
    result = _alembic(url, "upgrade", "head")
    assert result.returncode == 0, f"alembic upgrade failed:\n{result.stderr}"
    return url


def test_migrations_build_the_whole_schema(migrated):
    from mobius.adapters.models import Base

    engine = create_engine(migrated)
    tables = set(inspect(engine).get_table_names())
    expected = set(Base.metadata.tables) | {"alembic_version"}
    assert expected <= tables, f"missing from migrations: {sorted(expected - tables)}"


def test_migrations_and_models_do_not_drift(migrated):
    """`alembic check` fails when a model change never made it into a migration."""
    result = _alembic(migrated, "check")
    assert result.returncode == 0, (
        "models and migrations disagree; run `alembic revision --autogenerate`:\n"
        f"{result.stdout}\n{result.stderr}"
    )


def test_the_migration_history_can_be_rolled_back(migrated):
    result = _alembic(migrated, "downgrade", "base")
    assert result.returncode == 0, result.stderr

    engine = create_engine(migrated)
    tables = set(inspect(engine).get_table_names()) - {"alembic_version"}
    assert tables == set(), f"downgrade left tables behind: {sorted(tables)}"


def test_the_migration_is_replayable_from_scratch(tmp_path):
    """Upgrade, roll back, upgrade again: the history must survive its own undo."""
    url = f"sqlite+pysqlite:///{tmp_path / 'replay.db'}"
    for args in (("upgrade", "head"), ("downgrade", "base"), ("upgrade", "head")):
        result = _alembic(url, *args)
        assert result.returncode == 0, f"{args} failed:\n{result.stderr}"

    from mobius.adapters.models import Base

    engine = create_engine(url)
    assert set(Base.metadata.tables) <= set(inspect(engine).get_table_names())


def test_migrating_without_a_database_url_is_refused(monkeypatch, tmp_path):
    """Guessing which database to migrate is worse than stopping."""
    binary = str(ALEMBIC) if ALEMBIC.exists() else "alembic"
    env = {k: v for k, v in os.environ.items() if k != "MOBIUS_DB_URL"}
    result = subprocess.run(
        [binary, "upgrade", "head"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode != 0
    assert "MOBIUS_DB_URL" in (result.stderr + result.stdout)


def test_the_postgres_trigger_is_referenced_by_the_migration():
    """SQLite skips it; a reader must still be able to see that it is not forgotten."""
    text = (ROOT / "migrations" / "versions" / "0001_initial_schema.py").read_text(encoding="utf-8")
    assert "scope_guard.sql" in text
    assert "postgresql" in text
    assert "not executed" in text or "NOT EXECUTED" in text
