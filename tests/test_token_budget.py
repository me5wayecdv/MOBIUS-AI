from __future__ import annotations

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


def _create_scan(session, store, future_iso, *, max_tokens=100):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "budget.apk", uploaded_by="analyst-1")
    auth = intake.create_authorization(
        apk_sha256=app.sha256,
        target_package="com.example",
        scope_text="Static analysis only for cumulative token budget tests.",
        statement="I own this fixture APK",
        max_intensity=0,
        granted_by="analyst-1",
        expires_at=future_iso,
    )
    scan = intake.create_investigation(
        application_id=app.id,
        authorization_id=auth.id,
        objective="Test cumulative model token budget accounting",
        intensity=0,
        created_by="analyst-1",
        budget=Budget(max_model_tokens=max_tokens),
    )
    return scan.id


def test_multiple_calls_share_one_cumulative_investigation_budget(
    session, store, future_iso
):
    scan_id = _create_scan(session, store, future_iso, max_tokens=100)
    ledger = InvestigationTokenBudget(session.bind and session.get_bind() and
                                      sessionmaker_for(session))

    first = ledger.reserve(scan_id, 60)
    ledger.settle(first, actual_tokens=50, provider="ollama", model_id="test-model")
    second = ledger.reserve(scan_id, 40)
    ledger.settle(second, actual_tokens=35, provider="ollama", model_id="test-model")

    with pytest.raises(ModelBudgetExceeded, match="would be exceeded"):
        ledger.reserve(scan_id, 16)

    row = session.get(InvestigationRow, scan_id)
    assert row.used_json["model_tokens"] == 85
    assert row.used_json["model_tokens_reserved"] == 0


def sessionmaker_for(session):
    from sqlalchemy.orm import sessionmaker
    return sessionmaker(bind=session.get_bind(), expire_on_commit=False, future=True)


def test_concurrent_calls_cannot_reserve_the_same_remaining_budget(tmp_path, future_iso):
    engine = make_engine(f"sqlite+pysqlite:///{tmp_path / 'concurrent-budget.db'}")
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    setup = factory()
    try:
        scan_id = _create_scan(setup, store, future_iso, max_tokens=100)
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
        results = list(pool.map(lambda _n: reserve(), range(2)))

    accepted = [item for item in results if item is not None]
    rejected = [item for item in results if item is None]
    assert len(accepted) == 1
    assert len(rejected) == 1

    ledger.settle(
        accepted[0], actual_tokens=80, provider="ollama", model_id="parallel-test"
    )
    check = factory()
    try:
        row = check.get(InvestigationRow, scan_id)
        used = row.used_json
        assert used["model_tokens"] + used["model_tokens_reserved"] <= 100
        assert used["model_tokens"] == 80
        assert used["model_tokens_reserved"] == 0
    finally:
        check.close()
        engine.dispose()
