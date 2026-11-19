"""Postgres test-DSN selection, dependency-free on purpose.

Kept out of test_worker_queue_pg.py because that module runs
pytest.importorskip("psycopg") at import time: importing the selector from
there would turn a missing psycopg into a silent SKIP of the pure selection
tests instead of a failure. This module imports nothing beyond the standard
library, so the selection tests always execute.
"""
from __future__ import annotations


def resolve_pg_dsn(env):
    """Pick the Postgres test DSN: MOBIUS_TEST_PG_DSN wins; CI's
    MOBIUS_TEST_PG_URL is the fallback. Pure so the selection is testable
    without a database."""
    return env.get("MOBIUS_TEST_PG_DSN") or env.get("MOBIUS_TEST_PG_URL")
