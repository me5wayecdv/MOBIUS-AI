"""Paired-session Postgres regressions for worker-job concurrency.

These need a real Postgres (sqlite cannot express row locks or partial unique
indexes across concurrent transactions). Set MOBIUS_TEST_PG_DSN, e.g.:

    postgresql+psycopg://postgres@/mobius_racetest?host=/tmp

Skipped otherwise. The database is migrated with alembic to head so the test
exercises the deployed schema, not just create_all.
"""
from __future__ import annotations

import os
import threading
import time

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

DSN = os.environ.get("MOBIUS_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="MOBIUS_TEST_PG_DSN not set")

pytest.importorskip("psycopg")


@pytest.fixture()
def pg_engine():
    import subprocess
    env = dict(os.environ, MOBIUS_DB_URL=DSN)
    subprocess.run(["alembic", "upgrade", "head"], check=True, env=env,
                   cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    engine = create_engine(DSN, isolation_level="READ COMMITTED")
    yield engine
    with engine.begin() as conn:
        conn.execute(text(
            "TRUNCATE worker_jobs, events, investigations, authorizations, "
            "applications CASCADE"
        ))
    engine.dispose()


def _seed_scan(engine, future_iso):
    """One application + authorization + investigation, via the real intake."""
    from mobius.services.artifacts import ArtifactStore
    from mobius.services.intake import IntakeService
    from conftest import make_apk
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        store = ArtifactStore(tmp)
        with Session(engine) as session:
            intake = IntakeService(session, store)
            app, _ = intake.create_application(make_apk(), "authorized.apk",
                                               uploaded_by="analyst-1")
            auth = intake.create_authorization(
                apk_sha256=app.sha256,
                target_package="com.example",
                scope_text="Static analysis of the supplied APK only.",
                statement="I am authorized to analyze this APK.",
                max_intensity=0, granted_by="analyst-1", expires_at=future_iso,
            )
            scan = intake.create_investigation(
                application_id=app.id, authorization_id=auth.id,
                objective="Inspect the Android manifest.", intensity=0, created_by="analyst-1",
            )
            intake.start(scan.id)
            session.commit()
            # enqueue_provider_analysis requires SURFACE_READY; the recon run
            # is not what this regression exercises, so move the state directly.
            session.execute(text(
                "UPDATE investigations SET state = 'SURFACE_READY' WHERE id = :i"
            ), {"i": scan.id})
            session.commit()
            return scan.id, app.artifact_key


def test_concurrent_enqueue_admits_exactly_one_job(pg_engine, future_iso):
    from mobius.services.worker_queue import WorkerQueue
    from mobius.services.errors import ScanStateConflict
    scan_id, artifact_key = _seed_scan(pg_engine, future_iso)

    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def enqueue(tag):
        with Session(pg_engine) as session:
            try:
                barrier.wait(timeout=10)
                WorkerQueue(session).enqueue_provider_analysis(scan_id, artifact_key)
                session.commit()
                outcomes.append(f"{tag}:ok")
            except ScanStateConflict:
                session.rollback()
                outcomes.append(f"{tag}:conflict")
            except Exception as exc:  # surfaced for diagnosis
                session.rollback()
                outcomes.append(f"{tag}:{type(exc).__name__}")

    threads = [threading.Thread(target=enqueue, args=(t,)) for t in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert sorted(outcomes) == ["a:ok", "b:conflict"] or sorted(outcomes) == [
        "a:conflict", "b:ok"], f"exactly one enqueue must win, got {outcomes}"
    with Session(pg_engine) as session:
        count = session.execute(text(
            "SELECT COUNT(*) FROM worker_jobs WHERE investigation_id = :i"
        ), {"i": scan_id}).scalar_one()
    assert count == 1


def test_concurrent_claim_apply_admits_exactly_one_applier(pg_engine, future_iso):
    """Two appliers race the conditional UPDATE: the loser blocks on the row
    lock, re-evaluates the WHERE after the winner commits, and matches 0 rows."""
    from mobius.services.worker_queue import WorkerQueue
    from mobius.services.errors import ScanStateConflict
    scan_id, artifact_key = _seed_scan(pg_engine, future_iso)

    with Session(pg_engine) as session:
        queue = WorkerQueue(session)
        job = queue.enqueue_provider_analysis(scan_id, artifact_key)
        session.commit()
        job_id = job.id
    with Session(pg_engine) as session:
        queue = WorkerQueue(session)
        claimed = queue.claim("worker-a")
        queue.succeed(claimed.id, "worker-a", {"schema_version": 1})
        session.commit()

    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def apply(tag):
        with Session(pg_engine) as session:
            try:
                barrier.wait(timeout=10)
                WorkerQueue(session).claim_apply(job_id)
                session.commit()
                outcomes.append(f"{tag}:ok")
            except ScanStateConflict:
                session.rollback()
                outcomes.append(f"{tag}:conflict")
            except Exception as exc:
                session.rollback()
                outcomes.append(f"{tag}:{type(exc).__name__}")

    threads = [threading.Thread(target=apply, args=(t,)) for t in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    oks = [o for o in outcomes if o.endswith(":ok")]
    conflicts = [o for o in outcomes if o.endswith(":conflict")]
    assert len(oks) == 1 and len(conflicts) == 1, (
        f"exactly one applier must win, got {outcomes}")
    with Session(pg_engine) as session:
        applied = session.execute(text(
            "SELECT applied_at IS NOT NULL FROM worker_jobs WHERE id = :i"
        ), {"i": job_id}).scalar_one()
    assert applied is True


def _pg_client(pg_engine, tmp_path):
    """Full API app wired to the migrated Postgres schema."""
    from mobius.api.app import create_app
    from mobius.api.config import Settings
    from mobius.api.deps import AppContext, set_context
    from fastapi.testclient import TestClient
    settings = Settings(db_url=DSN, artifact_root=tmp_path / "artifacts", env="test")
    context = AppContext(settings)
    set_context(context)
    return TestClient(create_app()), context


def test_full_route_concurrent_apply_admits_exactly_one(pg_engine, tmp_path, future_iso):
    """Paired HTTP applies of the SAME job against real Postgres: one 200, one
    409, one finding set. This exercises the whole route (validation, anchors,
    claim), not only the claim helper."""
    from conftest import make_apk
    from test_api import _upload, _authorize, _scan, _provider_worker_payload, _provider_manifest
    from mobius.services.worker_queue import WorkerQueue
    from sqlalchemy.orm import Session as _S

    client, context = _pg_client(pg_engine, tmp_path)
    try:
        app = _upload(client, data=make_apk(manifest=_provider_manifest())).json()
        auth = _authorize(client, app["sha256"]).json()
        scan = _scan(client, app["id"], auth["id"]).json()
        assert client.post(f"/api/v1/scans/{scan['id']}/recon").status_code == 200
        queued = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs")
        assert queued.status_code == 202
        job_id = queued.json()["job_id"]
        payload = _provider_worker_payload(app["sha256"])
        with context.session() as session:
            queue = WorkerQueue(session)
            claimed = queue.claim("pg-worker")
            queue.succeed(claimed.id, "pg-worker", payload,
                          staged_sha256=app["sha256"])
            session.commit()

        results: list[int] = []
        barrier = threading.Barrier(2)

        def apply(tag):
            from fastapi.testclient import TestClient
            c = TestClient(client.app)
            barrier.wait(timeout=10)
            r = c.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
            results.append(r.status_code)

        threads = [threading.Thread(target=apply, args=(t,)) for t in ("a", "b")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
            assert not t.is_alive(), "apply request deadlocked"

        assert sorted(results) == [200, 409], f"one apply must win, got {results}"
        findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"]
        provider_findings = [f for f in findings
                             if f["category"] == "exported-provider-unprotected-sink"]
        assert len(provider_findings) == 1
    finally:
        from mobius.api.deps import set_context
        set_context(None)


def test_full_route_reject_races_claim_without_deadlock(pg_engine, tmp_path, future_iso):
    """A legacy second job applied concurrently with the first job's apply:
    exactly one 200; the loser is either 409 (rolled back, retryable) or 422
    (truthful terminal rejection); a follow-up apply of the loser then
    terminalizes as rejected. No deadlock, no duplicate findings."""
    from conftest import make_apk
    from test_api import _upload, _authorize, _scan, _provider_worker_payload, _provider_manifest
    from mobius.services.worker_queue import WorkerQueue
    from mobius.adapters.models import WorkerJobRow
    from sqlalchemy.orm import Session as _S

    client, context = _pg_client(pg_engine, tmp_path)
    try:
        app = _upload(client, data=make_apk(manifest=_provider_manifest())).json()
        auth = _authorize(client, app["sha256"]).json()
        scan = _scan(client, app["id"], auth["id"]).json()
        assert client.post(f"/api/v1/scans/{scan['id']}/recon").status_code == 200
        job1 = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]
        payload = _provider_worker_payload(app["sha256"])
        with context.session() as session:
            queue = WorkerQueue(session)
            claimed = queue.claim("pg-worker")
            queue.succeed(claimed.id, "pg-worker", payload,
                          staged_sha256=app["sha256"])
            session.commit()
        assert client.post(
            f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job1}/apply"
        ).status_code == 200
        # legacy second job (predates the applied-gate at enqueue; insertable
        # because the applied job is no longer active under the partial index)
        with context.session() as session:
            session.add(WorkerJobRow(
                id="legacy-racer", investigation_id=scan["id"],
                kind="provider_analysis", artifact_key=app["artifact_key"],
                status="succeeded", attempts=1, result_json=payload,
                created_at="2026-11-19T00:00:00.000Z", staged_sha256=app["sha256"],
            ))
            session.commit()

        # two requests race to terminalize the same legacy job: one rejection
        # commits (422), the loser of the conditional UPDATE gets 409
        results: list[int] = []
        barrier = threading.Barrier(2)

        def apply(tag):
            from fastapi.testclient import TestClient
            c = TestClient(client.app)
            barrier.wait(timeout=10)
            r = c.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/legacy-racer/apply")
            results.append(r.status_code)

        threads = [threading.Thread(target=apply, args=(t,)) for t in ("a", "b")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
            assert not t.is_alive(), "apply request deadlocked"

        assert sorted(results) == [409, 422], f"reject race must settle, got {results}"
        again = client.post(
            f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/legacy-racer/apply")
        assert again.status_code == 409  # already terminal: not ready
        status = client.get(
            f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/legacy-racer").json()
        assert status["status"] == "rejected"
        findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"]
        provider_findings = [f for f in findings
                             if f["category"] == "exported-provider-unprotected-sink"]
        assert len(provider_findings) == 1
    finally:
        from mobius.api.deps import set_context
        set_context(None)


def test_full_route_apply_loses_to_committed_claim(pg_engine, tmp_path, future_iso):
    """Reject-vs-successful-claim on the SAME job: T1 holds the row lock after
    claim_apply; T2 runs the full apply route concurrently and blocks on the
    lock; once T1 commits, T2's conditional UPDATE matches 0 rows. T2 must get
    409, the job must stay applied (never rejected), exactly one finding set."""
    from conftest import make_apk
    from test_api import _upload, _authorize, _scan, _provider_worker_payload, _provider_manifest
    from mobius.services.worker_queue import WorkerQueue

    client, context = _pg_client(pg_engine, tmp_path)
    try:
        app = _upload(client, data=make_apk(manifest=_provider_manifest())).json()
        auth = _authorize(client, app["sha256"]).json()
        scan = _scan(client, app["id"], auth["id"]).json()
        assert client.post(f"/api/v1/scans/{scan['id']}/recon").status_code == 200
        job_id = client.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs").json()["job_id"]
        payload = _provider_worker_payload(app["sha256"])
        with context.session() as session:
            queue = WorkerQueue(session)
            claimed = queue.claim("pg-worker")
            queue.succeed(claimed.id, "pg-worker", payload,
                          staged_sha256=app["sha256"])
            session.commit()

        claimed_event = threading.Event()
        release = threading.Event()
        holder_error: list[str] = []

        def holder():
            try:
                with context.session() as session:
                    WorkerQueue(session).claim_apply(job_id)  # row lock held
                    claimed_event.set()
                    assert release.wait(timeout=30)
                    # finish the apply in the same transaction
                    from mobius.services.provider_analysis import ProviderAnalysisService
                    from mobius.adapters.provider_payload import (
                        validate_provider_analysis_payload)
                    import json as _json
                    result = validate_provider_analysis_payload(
                        _json.dumps(payload).encode(), app["sha256"])
                    ProviderAnalysisService(
                        session, context.store).run_from_payload(
                        scan["id"], result, validated_by="analyst-1",
                        applied_job_id=job_id)
                    session.commit()
            except Exception as exc:
                holder_error.append(f"{type(exc).__name__}: {exc}")

        t1 = threading.Thread(target=holder)
        t1.start()
        assert claimed_event.wait(timeout=30)

        route_result: list[int] = []

        def route_apply():
            from fastapi.testclient import TestClient
            c = TestClient(client.app)
            r = c.post(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}/apply")
            route_result.append(r.status_code)

        t2 = threading.Thread(target=route_apply)
        t2.start()
        import time
        time.sleep(2)  # let T2 reach the locked row before T1 commits
        release.set()
        t1.join(timeout=60)
        t2.join(timeout=60)
        assert not t1.is_alive() and not t2.is_alive(), "deadlock in apply race"
        assert not holder_error, holder_error
        assert route_result == [409], f"loser must get 409, got {route_result}"

        status = client.get(f"/api/v1/scans/{scan['id']}/provider-analysis/jobs/{job_id}").json()
        assert status["status"] == "succeeded"  # never marked rejected
        assert status["applied"] is True
        findings = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"]
        provider_findings = [f for f in findings
                             if f["category"] == "exported-provider-unprotected-sink"]
        assert len(provider_findings) == 1
    finally:
        from mobius.api.deps import set_context
        set_context(None)


def test_terminal_reject_loses_to_committed_claim(pg_engine, future_iso):
    """Paired-session race on the SAME job: T1 holds the row lock after
    claim_apply; T2's terminal_reject blocks on the lock; once T1 commits, the
    reject's conditional UPDATE (status succeeded AND applied_at IS NULL)
    matches 0 rows and must raise ScanStateConflict. The job stays applied,
    never rejected, and no deadlock occurs (bounded joins)."""
    from mobius.services.errors import ScanStateConflict
    from mobius.services.worker_queue import WorkerQueue
    scan_id, artifact_key = _seed_scan(pg_engine, future_iso)

    with Session(pg_engine) as session:
        queue = WorkerQueue(session)
        job = queue.enqueue_provider_analysis(scan_id, artifact_key)
        session.commit()
        job_id = job.id
    with Session(pg_engine) as session:
        queue = WorkerQueue(session)
        claimed_job = queue.claim("pg-worker")
        queue.succeed(claimed_job.id, "pg-worker", {"schema_version": 1},
                      staged_sha256=artifact_key.rsplit("/", 1)[-1][:-4])
        session.commit()

    claimed = threading.Event()
    release = threading.Event()
    holder_error: list[str] = []

    def holder():
        try:
            with Session(pg_engine) as session:
                WorkerQueue(session).claim_apply(job_id)  # row lock held
                claimed.set()
                assert release.wait(timeout=30)
                session.commit()
        except Exception as exc:
            holder_error.append(f"{type(exc).__name__}: {exc}")

    t1 = threading.Thread(target=holder)
    t1.start()
    assert claimed.wait(timeout=30)

    reject_error: list[str] = []

    def rejecter():
        try:
            with Session(pg_engine) as session:
                WorkerQueue(session).terminal_reject(job_id, "CONFLICT", "racing reject")
                session.commit()
        except ScanStateConflict as exc:
            reject_error.append(f"ScanStateConflict: {exc}")
        except Exception as exc:
            reject_error.append(f"{type(exc).__name__}: {exc}")

    t2 = threading.Thread(target=rejecter)
    t2.start()
    time.sleep(1.0)  # let T2 block on the held row lock
    assert t2.is_alive(), "terminal_reject should wait on the held claim"
    release.set()
    t1.join(timeout=30)
    t2.join(timeout=30)
    assert not t1.is_alive() and not t2.is_alive(), "deadlock: bounded join exceeded"
    assert holder_error == [], holder_error
    assert reject_error and reject_error[0].startswith("ScanStateConflict"), reject_error

    with Session(pg_engine) as session:
        row = WorkerQueue(session).get(job_id)
        assert row.status == "succeeded"
        assert row.applied_at is not None
        assert row.error_code is None  # never rejected
