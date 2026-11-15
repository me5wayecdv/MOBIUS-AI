"""Alembic environment for MOBIUS.

Two decisions worth stating:

* **The URL comes from `MOBIUS_DB_URL`.** The same variable the API reads, resolved the same
  way. A migration tool with its own connection string is how a deploy migrates one database
  and serves another.
* **`render_as_batch` is on for SQLite.** SQLite cannot `ALTER TABLE` most columns; batch mode
  rewrites the table so the migration history stays usable on the developer database, not only
  on Postgres.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from mobius.adapters.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _url() -> str:
    url = os.environ.get("MOBIUS_DB_URL") or config.get_main_option("sqlalchemy.url")
    if not url:
        raise RuntimeError(
            "MOBIUS_DB_URL is not set and alembic.ini has no sqlalchemy.url. Refusing to "
            "guess which database to migrate."
        )
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _url()
    connectable = engine_from_config(
        section, prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
