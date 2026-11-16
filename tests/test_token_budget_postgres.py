from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import make_apk
from mobius.adapters.db import make_engine, make_session_factory
from mobius.adapters.models import Base, InvestigationRow
from mobius.core.schemas import Budget
from mobius.services.artifacts import ArtifactStore
from mobius.services.intake import IntakeService
from mobius.services.model_provider import ModelBudgetExceeded
from mobius.services.token_budget import InvestigationTokenBudget

PG_URL = os.environ.get("MOBIUS_TEST_PG_URL")
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(not PG_URL, reason="set MOBIUS_TEST_PG_URL to run PostgreSQL budget locking tests"),
]


def test_postgres_concurrent_investigation_reservations_are_serialized(tmp_path, future_iso):
    engine = make_engine(PG_URL)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    store = ArtifactStore(tmp_path / "pg-artifacts")
    setup = factory()
    try:
        intake = IntakeService(setup, store)
        app, _ = intake.create_application(make_apk(), "pg-budget.apk", uploaded_by="budget-pg-test")
        auth = intake.create_authorization(
            apk_sha256=app.sha256,
            target_package="com.example",
            scope_text="PostgreSQL row-locking test for cumulative model token budgets.",
            statement="I own this fixture APK",
            max_intensity=0,
            granted_by="budget-pg-test",
            expires_at=future_iso,
        )
        scan = intake.create_investigation(
            application_id=app.id,
            authorization_id=auth.id,
            objective="Prove concurrent model token reservations are serialized",
            intensity=0,
            created_by="budget-pg-test",
            budget=Budget(max_model_tokens=100),
        )
        scan_id = scan.id
        setup.commit()
    finally:
        setup.close()

    ledger = InvestigationTokenBudget(factory)

    def reserve():
        try:
            return ledger.reserve(scan_id, 80)
        except ModelBudgetExceeded:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        reservations = list(pool.map(lambda _index: reserve(), range(2)))

    accepted = [item for item in reservations if item is not None]
    rejected = [item for item in reservations if item is None]
    assert len(accepted) == 1
    assert len(rejected) == 1

    ledger.settle(
        accepted[0], actual_tokens=80, provider="ollama", model_id="postgres-concurrency-test"
    )
    verify = factory()
    try:
        row = verify.get(InvestigationRow, scan_id)
        assert row.used_json["model_tokens"] == 80
        assert row.used_json["model_tokens_reserved"] == 0
        assert (
            row.used_json["model_tokens"] + row.used_json["model_tokens_reserved"]
            <= row.budget_json["max_model_tokens"]
        )
    finally:
        verify.close()
        engine.dispose()
