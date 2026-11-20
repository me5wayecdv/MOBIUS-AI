"""PostgreSQL proof for the VERITAS auto-review pass concurrency guard.

Two simultaneous passes over the same finding must not double-review it or
reserve budget twice. The guard is a per-(investigation, finding) advisory
transaction lock, which SQLite cannot exercise - so this proof only runs with
MOBIUS_TEST_PG_URL.
"""

from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import select

from conftest import make_apk
from mobius.adapters.db import make_engine, make_session_factory
from mobius.adapters.models import (
    Base,
    DecisionRow,
    EventRow,
    EvidenceRow,
    InvestigationRow,
)
from mobius.core.enums import Severity
from mobius.core.schemas import Budget
from mobius.services.artifacts import ArtifactStore
from mobius.services.intake import IntakeService
from mobius.services.model_provider import DeterministicMockProvider, StructuredModelGateway
from mobius.services.validation import ValidationService
from mobius.services.veritas_auto import run_auto_review_pass

PG_URL = os.environ.get("MOBIUS_TEST_PG_URL")
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(not PG_URL, reason="set MOBIUS_TEST_PG_URL to run PostgreSQL auto-review locking tests"),
]

REPLY = json.dumps({
    "disposition": "no_material_challenge",
    "summary": "The supplied evidence supports the draft; no material challenge.",
    "challenges": [],
})


class CountingProvider(DeterministicMockProvider):
    def __init__(self):
        super().__init__(REPLY, model_id="veritas-model", prompt_tokens=30, completion_tokens=20)
        self.calls = 0

    def complete_json(self, **kwargs):
        self.calls += 1
        return super().complete_json(**kwargs)


class SlowProvider(DeterministicMockProvider):
    """A provider that stays inside the call long enough for a second pass to
    genuinely overlap, proving the advisory lock is held across the provider
    call rather than released before it."""

    def __init__(self):
        super().__init__(REPLY, model_id="veritas-model", prompt_tokens=30, completion_tokens=20)
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def complete_json(self, **kwargs):
        self.calls += 1
        self.entered.set()
        assert self.release.wait(timeout=30)
        return super().complete_json(**kwargs)


def _make_scan_with_finding(factory, store, future_iso, suffix):
    setup = factory()
    try:
        intake = IntakeService(setup, store)
        app, _ = intake.create_application(make_apk(), f"pg-auto-review-{suffix}.apk", uploaded_by="pg-auto-test")
        auth = intake.create_authorization(
            apk_sha256=app.sha256,
            target_package="com.example",
            scope_text="PostgreSQL auto-review concurrency test.",
            statement="I own this fixture APK",
            max_intensity=2,
            granted_by="pg-auto-test",
            expires_at=future_iso,
        )
        scan = intake.create_investigation(
            application_id=app.id,
            authorization_id=auth.id,
            objective="Prove concurrent auto-review passes cannot double-review",
            intensity=0,
            created_by="pg-auto-test",
            budget=Budget(max_model_tokens=400_000),
        )
        row = setup.get(InvestigationRow, scan.id)
        row.llm_data_sharing = {"enabled": True, "provider": "mock", "auto_veritas": True}
        setup.add(EvidenceRow(
            id=f"ev_pg_auto_{suffix}",
            investigation_id=scan.id,
            kind="code_analysis",
            sha256="d" * 64,
            object_key="evidence/pg-auto",
            byte_size=128,
            truncated=False,
            redacted=True,
            summary="A persisted code observation showing a reachable file write.",
            produced_by="SPECTRE",
            created_at=future_iso,
        ))
        setup.flush()
        finding, _ = ValidationService(setup).validate(
            investigation_id=scan.id,
            category="exported-component-no-permission",
            attributes={
                "exported": True,
                "permission": None,
                "caller_check_absent": True,
                "sink_reachable": True,
            },
            title="Exported activity writes attacker-supplied path",
            description="The exported activity forwards an untrusted path to a privileged file sink.",
            evidence_refs=(f"ev_pg_auto_{suffix}",),
            discovered_by="SPECTRE",
            validated_by="DETERMINISTIC_GATE",
            severity=Severity.HIGH,
        )
        setup.commit()
        return scan.id, finding.id
    finally:
        setup.close()


def test_postgres_concurrent_passes_review_exactly_once(tmp_path, future_iso):
    engine = make_engine(PG_URL)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    store = ArtifactStore(tmp_path / "pg-artifacts")
    scan_id, finding_id = _make_scan_with_finding(factory, store, future_iso, "concurrent")
    provider = CountingProvider()
    gateway = StructuredModelGateway(provider, model="reviewer-v2")

    def _pass():
        return run_auto_review_pass(
            session_factory=factory, gateway=gateway, investigation_id=scan_id
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        summaries = list(pool.map(lambda _: _pass(), range(2)))

    completed = sum(s["completed"] for s in summaries)
    attempted = sum(s["attempted"] for s in summaries)
    skipped = sum(s["skipped"] for s in summaries)
    assert completed == 1, summaries
    assert attempted == 1, summaries
    assert skipped == 1, summaries
    skip_reasons = {skip["reason"] for s in summaries for skip in s["skips"]}
    assert skip_reasons <= {"review-in-progress", "already-reviewed"}, summaries
    assert provider.calls == 1

    check = factory()
    try:
        reviews = check.execute(select(DecisionRow).where(
            DecisionRow.investigation_id == scan_id,
            DecisionRow.agent == "VERITAS",
            DecisionRow.action == "review_finding",
        )).scalars().all()
        assert len(reviews) == 1
        events = check.execute(select(EventRow).where(
            EventRow.investigation_id == scan_id,
            EventRow.type == "veritas_review_completed",
        )).scalars().all()
        assert len(events) == 1
    finally:
        check.close()


def test_postgres_lock_is_held_across_the_provider_call(tmp_path, future_iso):
    """A second pass on its own connection while the first pass is INSIDE the
    provider call must observe review-in-progress - proof the advisory lock is
    not committed or rolled back before provider/persistence completes."""
    engine = make_engine(PG_URL)
    Base.metadata.create_all(engine)
    factory = make_session_factory(engine)
    store = ArtifactStore(tmp_path / "pg-artifacts-slow")
    scan_id, finding_id = _make_scan_with_finding(factory, store, future_iso, "slow")
    provider = SlowProvider()
    gateway = StructuredModelGateway(provider, model="reviewer-v2")

    def _pass():
        return run_auto_review_pass(
            session_factory=factory, gateway=gateway, investigation_id=scan_id
        )

    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(_pass)
        assert provider.entered.wait(timeout=30), "first pass never reached the provider"
        # Independently opened connections: the factory creates a fresh session
        # (and connection) per pass, on a separate thread from the first pass.
        overlapping = _pass()
        provider.release.set()
        first_summary = first.result(timeout=30)

    assert overlapping["attempted"] == 0, overlapping
    assert overlapping["skipped"] == 1
    assert overlapping["skips"] == [{"finding_id": finding_id, "reason": "review-in-progress"}]
    assert first_summary["completed"] == 1, first_summary
    assert provider.calls == 1

    check = factory()
    try:
        reviews = check.execute(select(DecisionRow).where(
            DecisionRow.investigation_id == scan_id,
            DecisionRow.agent == "VERITAS",
            DecisionRow.action == "review_finding",
        )).scalars().all()
        assert len(reviews) == 1
    finally:
        check.close()
