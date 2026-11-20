"""PostgreSQL proof for the NEXUS bounded repair loop's independent transactions.

Rejection diagnostics commit on their own session while the request transaction
is still open. Under PostgreSQL that means lock interaction with the request
session and with concurrent writers on the same investigation row; SQLite-only
rollback proof cannot show either. These tests run only with MOBIUS_TEST_PG_URL.
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy.orm import sessionmaker

from conftest import make_apk
from mobius.adapters.db import make_engine, make_session_factory
from mobius.adapters.models import (
    Base,
    DecisionRow,
    EventRow,
    HypothesisRow,
    InvestigationRow,
)
from mobius.core.schemas import Budget
from mobius.services.artifacts import ArtifactStore
from mobius.services.intake import IntakeService
from mobius.services.model_provider import (
    ModelOutputInvalid,
    ProviderResult,
    StructuredModelGateway,
)
from mobius.services.nexus_hypotheses import NexusHypothesisService

PG_URL = os.environ.get("MOBIUS_TEST_PG_URL")
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(not PG_URL, reason="set MOBIUS_TEST_PG_URL to run PostgreSQL repair-loop locking tests"),
]


class ScriptedProvider:
    name = "ollama"

    def __init__(self, steps):
        self.steps = list(steps)
        self.calls = 0

    def complete_json(self, **kwargs):
        self.calls += 1
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        return ProviderResult(
            content=step,
            model_id="local-test-model",
            prompt_tokens=7,
            completion_tokens=5,
        )


def _make_scan(factory, store, future_iso, suffix):
    setup = factory()
    try:
        intake = IntakeService(setup, store)
        app, _ = intake.create_application(make_apk(), f"pg-repair-{suffix}.apk", uploaded_by="pg-repair-test")
        auth = intake.create_authorization(
            apk_sha256=app.sha256,
            target_package="com.example",
            scope_text="PostgreSQL repair-loop locking test.",
            statement="I own this fixture APK",
            max_intensity=0,
            granted_by="pg-repair-test",
            expires_at=future_iso,
        )
        scan = intake.create_investigation(
            application_id=app.id,
            authorization_id=auth.id,
            objective="Prove rejection diagnostics commit without lock hazards",
            intensity=0,
            created_by="pg-repair-test",
            budget=Budget(max_model_tokens=400_000),
        )
        row = setup.get(InvestigationRow, scan.id)
        row.llm_data_sharing = {"enabled": True, "provider": "ollama"}
        setup.commit()
        return scan.id
    finally:
        setup.close()


def _run_exhaustion(factory, scan_id):
    """One request: open read transaction, model fails 3x, rejection commits."""
    request_session = factory()
    provider = ScriptedProvider(["{bad json", "{worse json", "{worst json"])
    gateway = StructuredModelGateway(provider, model="local-test-model")
    try:
        with pytest.raises(ModelOutputInvalid):
            NexusHypothesisService(
                request_session, gateway=gateway, session_factory=factory
            ).generate(scan_id)
        # The request transaction is still open here: its reads cannot have
        # blocked the rejection writes, or the calls above would have hung.
        request_session.rollback()
        return provider.calls
    finally:
        request_session.close()


def test_postgres_rejection_commits_while_request_transaction_open(tmp_path, future_iso):
    engine = make_engine(PG_URL)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    store = ArtifactStore(tmp_path / "pg-artifacts")
    scan_id = _make_scan(factory, store, future_iso, "single")

    assert _run_exhaustion(factory, scan_id) == 3

    check = factory()
    try:
        events = (
            check.query(EventRow)
            .filter_by(investigation_id=scan_id, type="planner_rejected")
            .order_by(EventRow.seq)
            .all()
        )
        assert [e.payload["reason"] for e in events] == ["schema-invalid"] * 3
        assert [e.payload["final"] for e in events] == [False, False, True]
        decision = check.query(DecisionRow).filter_by(
            investigation_id=scan_id, action="generate_hypotheses_rejected"
        ).one()
        assert decision.output_json is None
        assert check.query(HypothesisRow).filter_by(investigation_id=scan_id).count() == 0
    finally:
        check.close()


def test_postgres_concurrent_exhaustions_do_not_deadlock(tmp_path, future_iso):
    engine = make_engine(PG_URL)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    store = ArtifactStore(tmp_path / "pg-artifacts")
    scan_id = _make_scan(factory, store, future_iso, "concurrent")

    with ThreadPoolExecutor(max_workers=2) as pool:
        calls = list(pool.map(lambda _: _run_exhaustion(factory, scan_id), range(2)))

    assert calls == [3, 3]
    check = factory()
    try:
        events = (
            check.query(EventRow)
            .filter_by(investigation_id=scan_id, type="planner_rejected")
            .order_by(EventRow.seq)
            .all()
        )
        # Two full rejections (3 attempts each) serialized on the investigation
        # row without a deadlock and without duplicate sequence numbers.
        assert len(events) == 6
        assert len({e.seq for e in events}) == 6
        assert sum(1 for e in events if e.payload["final"]) == 2
        decisions = check.query(DecisionRow).filter_by(
            investigation_id=scan_id, action="generate_hypotheses_rejected"
        ).all()
        assert len(decisions) == 2
        assert check.query(HypothesisRow).filter_by(investigation_id=scan_id).count() == 0
    finally:
        check.close()
