"""Paired-session Postgres regressions for worker-job concurrency.

These need a real Postgres (sqlite cannot express row locks or partial unique
indexes across concurrent transactions). Set MOBIUS_TEST_PG_DSN, e.g.:

    postgresql+psycopg://postgres@/mobius_racetest?host=/tmp

Skipped otherwise. CI exports MOBIUS_TEST_PG_URL instead, so that name is
accepted as a fallback (DSN wins when both are set). The database is migrated
with alembic to head so the test exercises the deployed schema, not just
create_all.

Isolation model: the configured database may hold anything (other test files
in this suite build their schema in `public` via create_all, so alembic cannot
migrate `public` without colliding - and must never be allowed to wipe it).
Every test therefore runs inside its own generated schema (wqtest_<uuid>)
through a search_path-pinned DSN, migrates that schema with alembic, asserts
the migration landed there, and drops exactly that schema on teardown. A
module-level guard proves this run's own public sentinel row is untouched and
that no schema this run created is leaked.
"""
from __future__ import annotations

import os
import threading
import time
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine.url import make_url
from sqlalchemy.orm import Session

from pg_dsn import resolve_pg_dsn

DSN = resolve_pg_dsn(os.environ)
pytestmark = pytest.mark.skipif(
    not DSN, reason="neither MOBIUS_TEST_PG_DSN nor MOBIUS_TEST_PG_URL set")

pytest.importorskip("psycopg")


SCHEMA_PREFIX = "wqtest_"

# Names of every schema this run created, so the teardown guard validates
# exactly what this run owns and nothing else (another run sharing the
# database may legitimately own look-alike names).
_CREATED_SCHEMAS: list[str] = []


def _schema_url(dsn: str, schema: str) -> str:
    """DSN pinned to a single schema via the libpq options connection
    parameter, so every unqualified name (app tables, the alembic version
    table, the scope-guard trigger function) resolves inside that schema."""
    url = make_url(dsn)
    query = dict(url.query)
    setting = f"-csearch_path={schema}"
    existing = query.get("options", "")
    query["options"] = f"{existing} {setting}".strip()
    return url.set(query=query).render_as_string(hide_password=False)


@pytest.fixture(scope="module", autouse=True)
def _public_schema_guard():
    """Proof, not isolation: this module must never write to the public
    schema and must drop every schema it creates.

    Setup plants a sentinel row in a uniquely-named public table (uuid suffix:
    the name cannot belong to another run, so setup never skips and
    non-execution can never be masked); a setup failure removes the sentinel
    before re-raising. Teardown checks this run's own sentinel row, then -
    independently of the checks, on a fresh connection - drops any leaked
    schema this run created (tracked in _CREATED_SCHEMAS, never a prefix
    sweep) and the sentinel. Cleanup failures are recorded, never masked over
    an error already propagating. Only after cleanup does the guard fail the
    module if anything was amiss."""
    sentinel = f"{SCHEMA_PREFIX}sentinel_{uuid.uuid4().hex}"
    admin = create_engine(DSN, isolation_level="AUTOCOMMIT")
    created = False
    try:
        with admin.connect() as conn:
            conn.execute(text(f'CREATE TABLE public."{sentinel}" (id integer PRIMARY KEY)'))
            created = True
            conn.execute(text(f'INSERT INTO public."{sentinel}" (id) VALUES (1)'))
    except BaseException:
        if created:
            try:
                with admin.connect() as conn:
                    conn.execute(text(f'DROP TABLE IF EXISTS public."{sentinel}"'))
            except Exception:
                pass  # the original setup failure takes precedence
        admin.dispose()
        raise
    yield
    errors: list[str] = []
    try:
        with admin.connect() as conn:
            count = conn.execute(text(
                f'SELECT COUNT(*) FROM public."{sentinel}"')).scalar_one()
            if count != 1:
                errors.append(
                    f"public sentinel row changed (count={count}): "
                    "a test wrote to public")
    finally:
        # Cleanup is independent of the checks: fresh connection, each
        # statement guarded, failures recorded without masking a check
        # failure already propagating.
        leaked: list[str] = []
        try:
            with admin.connect() as conn:
                if _CREATED_SCHEMAS:
                    leaked = conn.execute(text(
                        "SELECT schema_name FROM information_schema.schemata "
                        "WHERE schema_name = ANY(:names)"
                    ), {"names": list(_CREATED_SCHEMAS)}).scalars().all()
                    for name in leaked:  # ours by construction
                        try:
                            conn.execute(text(f'DROP SCHEMA "{name}" CASCADE'))
                        except Exception as exc:
                            errors.append(f"failed to drop leaked schema {name}: {exc!r}")
                try:
                    conn.execute(text(f'DROP TABLE IF EXISTS public."{sentinel}"'))
                except Exception as exc:
                    errors.append(f"failed to drop sentinel: {exc!r}")
        except Exception as exc:
            errors.append(f"guard cleanup connection failed: {exc!r}")
        finally:
            admin.dispose()
        if leaked:
            errors.append(f"test schemas leaked (cleaned by guard): {leaked}")
    assert not errors, "; ".join(errors)


@pytest.fixture()
def pg_engine():
    """Migrate and run inside a per-test throwaway schema so the configured
    database is never wiped or migrated. The schema name is generated here
    (fixed prefix + uuid), never taken from configuration; teardown drops
    exactly that schema and nothing else, including when migration or test
    setup fails."""
    import subprocess
    schema = SCHEMA_PREFIX + uuid.uuid4().hex
    test_dsn = _schema_url(DSN, schema)
    admin = create_engine(DSN, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        _CREATED_SCHEMAS.append(schema)
        env = dict(os.environ, MOBIUS_DB_URL=test_dsn)
        subprocess.run(["alembic", "upgrade", "head"], check=True, env=env,
                       cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        # Deterministic tripwire: the migration must have landed in THIS
        # private schema (admin is unpinned, so qualify explicitly).
        with admin.connect() as conn:
            for rel in ("worker_jobs", "alembic_version"):
                landed = conn.execute(text(
                    "SELECT to_regclass(:name)"
                ), {"name": f"{schema}.{rel}"}).scalar_one()
                assert landed is not None, (
                    f"alembic did not land {rel} in private schema {schema}")
        engine = create_engine(test_dsn, isolation_level="READ COMMITTED")
        try:
            yield engine
        finally:
            engine.dispose()
    finally:
        try:
            with admin.connect() as conn:
                conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        finally:
            admin.dispose()


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


def test_concurrent_secrets_enqueue_admits_exactly_one_job(pg_engine, future_iso):
    """Same race as the provider enqueue test, for the secrets kind. The 0008
    active-job uniqueness index is per (investigation, kind) and kind-blind,
    so this must behave identically: exactly one winner.

    NOTE: this test requires MOBIUS_TEST_PG_DSN (real Postgres) and has never
    been executed in the authoring environment (no local PG server, no
    docker); it exists for the CI pg-integration job."""
    from mobius.services.worker_queue import WorkerQueue
    from mobius.services.errors import ScanStateConflict
    scan_id, artifact_key = _seed_scan(pg_engine, future_iso)

    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def enqueue(tag):
        with Session(pg_engine) as session:
            try:
                barrier.wait(timeout=10)
                WorkerQueue(session).enqueue_secrets_analysis(scan_id, artifact_key)
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
    settings = Settings(db_url=pg_engine.url.render_as_string(hide_password=False), artifact_root=tmp_path / "artifacts", env="test")
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
        context.engine.dispose()  # release private-schema connections before DROP SCHEMA


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
        context.engine.dispose()  # release private-schema connections before DROP SCHEMA


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
        context.engine.dispose()  # release private-schema connections before DROP SCHEMA


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
