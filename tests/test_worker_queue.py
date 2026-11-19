from __future__ import annotations

import pytest

from mobius.adapters.models import InvestigationRow
from mobius.services.artifacts import ArtifactStore
from mobius.services.intake import IntakeService
from mobius.services.worker_queue import WorkerQueue

from conftest import make_apk


def _recon_job(session, store, future_iso):
    intake = IntakeService(session, store)
    app, _ = intake.create_application(make_apk(), "authorized.apk", uploaded_by="analyst-1")
    auth = intake.create_authorization(
        apk_sha256=app.sha256,
        target_package="com.example",
        scope_text="Static analysis of the supplied APK only.",
        statement="I am authorized to analyze this APK.",
        max_intensity=0,
        granted_by="analyst-1",
        expires_at=future_iso,
    )
    scan = intake.create_investigation(
        application_id=app.id,
        authorization_id=auth.id,
        objective="Inspect the Android manifest.",
        intensity=0,
        created_by="analyst-1",
    )
    intake.start(scan.id)
    return scan, app


def test_worker_queue_claims_and_completes_a_recon_job(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    queue = WorkerQueue(session)
    job = queue.enqueue_recon(scan.id, app.artifact_key)
    assert job.status == "queued"

    claimed = queue.claim("worker-a")
    assert claimed is not None
    assert claimed.id == job.id
    assert claimed.status == "running"
    assert claimed.attempts == 1
    assert claimed.lease_until is not None

    queue.succeed(job.id, "worker-a", {"manifest_xml": "<manifest package='com.example'/>"})
    assert queue.get(job.id).status == "succeeded"
    assert queue.get(job.id).result_json["manifest_xml"].startswith("<manifest")


def test_worker_cannot_complete_another_workers_job(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    queue = WorkerQueue(session)
    job = queue.enqueue_recon(scan.id, app.artifact_key)
    queue.claim("worker-a")
    with pytest.raises(Exception, match="does not own"):
        queue.succeed(job.id, "worker-b", {"manifest_xml": "<manifest/>"})


def test_worker_queue_refuses_jobs_outside_recon_state(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    session.get(InvestigationRow, scan.id).state = "CLOSED"
    session.flush()
    with pytest.raises(Exception, match="requires RECON state"):
        WorkerQueue(session).enqueue_recon(scan.id, app.artifact_key)


def test_worker_queue_claim_returns_none_when_empty(session):
    assert WorkerQueue(session).claim("worker-empty") is None


def test_worker_job_lease_allows_reclaim_after_expiry(session, store, future_iso):
    from datetime import datetime, timedelta, timezone

    scan, app = _recon_job(session, store, future_iso)
    queue = WorkerQueue(session)
    job = queue.enqueue_recon(scan.id, app.artifact_key)
    first = queue.claim("worker-a")
    assert first is not None
    first.lease_until = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    session.flush()

    second = queue.claim("worker-b")
    assert second is not None
    assert second.id == job.id
    assert second.worker_id == "worker-b"
    assert second.attempts == 2


def test_worker_queue_prevents_duplicate_unapplied_recon_jobs(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    queue = WorkerQueue(session)
    queue.enqueue_recon(scan.id, app.artifact_key)
    with pytest.raises(Exception, match="already active"):
        queue.enqueue_recon(scan.id, app.artifact_key)



def test_worker_queue_enqueues_and_claims_authorized_jadx_job(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    session.get(InvestigationRow, scan.id).state = "SURFACE_READY"
    session.flush()
    queue = WorkerQueue(session)

    job = queue.enqueue_jadx_decompile(scan.id, app.artifact_key)
    assert job.kind == "jadx_decompile"
    assert job.status == "queued"

    claimed = queue.claim("jadx-worker")
    assert claimed is not None
    assert claimed.id == job.id
    assert claimed.kind == "jadx_decompile"
    assert claimed.status == "running"


def test_worker_queue_prevents_duplicate_unapplied_jadx_jobs(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    session.get(InvestigationRow, scan.id).state = "SURFACE_READY"
    session.flush()
    queue = WorkerQueue(session)
    queue.enqueue_jadx_decompile(scan.id, app.artifact_key)

    with pytest.raises(Exception, match="already active"):
        queue.enqueue_jadx_decompile(scan.id, app.artifact_key)


def test_worker_queue_refuses_jadx_job_without_surface_ready_state(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    with pytest.raises(Exception, match="requires SURFACE_READY state"):
        WorkerQueue(session).enqueue_jadx_decompile(scan.id, app.artifact_key)


def test_worker_queue_enqueues_and_claims_provider_analysis_job(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    session.get(InvestigationRow, scan.id).state = "SURFACE_READY"
    session.flush()
    queue = WorkerQueue(session)

    job = queue.enqueue_provider_analysis(scan.id, app.artifact_key)
    assert job.kind == "provider_analysis"
    assert job.status == "queued"

    claimed = queue.claim("provider-worker")
    assert claimed is not None
    assert claimed.id == job.id
    assert claimed.kind == "provider_analysis"
    assert claimed.status == "running"


def test_worker_queue_prevents_duplicate_unapplied_provider_jobs(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    session.get(InvestigationRow, scan.id).state = "SURFACE_READY"
    session.flush()
    queue = WorkerQueue(session)
    queue.enqueue_provider_analysis(scan.id, app.artifact_key)

    with pytest.raises(Exception, match="already active"):
        queue.enqueue_provider_analysis(scan.id, app.artifact_key)


def test_worker_queue_refuses_provider_job_without_surface_ready_state(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    with pytest.raises(Exception, match="requires SURFACE_READY state"):
        WorkerQueue(session).enqueue_provider_analysis(scan.id, app.artifact_key)


def test_worker_queue_refuses_provider_job_for_a_different_artifact(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    session.get(InvestigationRow, scan.id).state = "SURFACE_READY"
    session.flush()
    with pytest.raises(Exception, match="does not match the investigation APK"):
        WorkerQueue(session).enqueue_provider_analysis(scan.id, "sha256:other")


def test_worker_queue_enqueues_and_claims_secrets_analysis_job(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    session.get(InvestigationRow, scan.id).state = "SURFACE_READY"
    session.flush()
    queue = WorkerQueue(session)

    job = queue.enqueue_secrets_analysis(scan.id, app.artifact_key)
    assert job.kind == "secrets_analysis"
    assert job.status == "queued"

    claimed = queue.claim("secrets-worker")
    assert claimed is not None
    assert claimed.id == job.id
    assert claimed.kind == "secrets_analysis"
    assert claimed.status == "running"
    # The lease must outlive the 900s tool timeout (claim() comment): this
    # kind is mapped to 20 minutes, same as provider analysis.
    from datetime import datetime, timedelta, timezone
    lease = datetime.fromisoformat(claimed.lease_until.replace("Z", "+00:00"))
    assert lease >= datetime.now(timezone.utc) + timedelta(minutes=19)


def test_worker_queue_prevents_duplicate_unapplied_secrets_jobs(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    session.get(InvestigationRow, scan.id).state = "SURFACE_READY"
    session.flush()
    queue = WorkerQueue(session)
    queue.enqueue_secrets_analysis(scan.id, app.artifact_key)

    with pytest.raises(Exception, match="already active"):
        queue.enqueue_secrets_analysis(scan.id, app.artifact_key)


def test_worker_queue_refuses_secrets_job_without_surface_ready_state(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    with pytest.raises(Exception, match="requires SURFACE_READY state"):
        WorkerQueue(session).enqueue_secrets_analysis(scan.id, app.artifact_key)


def test_worker_queue_refuses_secrets_job_for_a_different_artifact(session, store, future_iso):
    scan, app = _recon_job(session, store, future_iso)
    session.get(InvestigationRow, scan.id).state = "SURFACE_READY"
    session.flush()
    with pytest.raises(Exception, match="does not match the investigation APK"):
        WorkerQueue(session).enqueue_secrets_analysis(scan.id, "sha256:other")


def test_worker_queue_refuses_secrets_job_for_a_revoked_authorization(session, store, future_iso):
    from mobius.adapters.models import AuthorizationRow
    scan, app = _recon_job(session, store, future_iso)
    row = session.get(InvestigationRow, scan.id)
    row.state = "SURFACE_READY"
    auth = session.get(AuthorizationRow, row.authorization_id)
    auth.revoked_at = future_iso
    session.flush()
    with pytest.raises(Exception, match="no longer valid"):
        WorkerQueue(session).enqueue_secrets_analysis(scan.id, app.artifact_key)


def test_worker_queue_refuses_secrets_job_for_an_expired_authorization(session, store, future_iso):
    from mobius.adapters.models import AuthorizationRow
    scan, app = _recon_job(session, store, future_iso)
    row = session.get(InvestigationRow, scan.id)
    row.state = "SURFACE_READY"
    auth = session.get(AuthorizationRow, row.authorization_id)
    auth.expires_at = "2000-01-01T00:00:00Z"
    session.flush()
    with pytest.raises(Exception, match="no longer valid"):
        WorkerQueue(session).enqueue_secrets_analysis(scan.id, app.artifact_key)


def test_worker_queue_claims_mixed_kinds_in_creation_order(session, store, future_iso):
    """Shared-kind claim regression: adding secrets_analysis to the claimable
    set must not starve or reorder the existing kinds."""
    scan, app = _recon_job(session, store, future_iso)
    queue = WorkerQueue(session)
    recon = queue.enqueue_recon(scan.id, app.artifact_key)
    session.get(InvestigationRow, scan.id).state = "SURFACE_READY"
    session.flush()
    secrets = queue.enqueue_secrets_analysis(scan.id, app.artifact_key)

    first = queue.claim("worker-a")
    second = queue.claim("worker-b")
    assert first is not None and first.id == recon.id
    assert second is not None and second.id == secrets.id
    assert queue.claim("worker-c") is None


# ---------------------------------------------------------------------------
# PG DSN selection (test_worker_queue_pg.resolve_pg_dsn): the CI-exported
# MOBIUS_TEST_PG_URL must actually reach the PG tests, without breaking the
# pre-existing MOBIUS_TEST_PG_DSN name.
# ---------------------------------------------------------------------------

def test_pg_dsn_prefers_explicit_dsn_over_ci_url():
    from pg_dsn import resolve_pg_dsn
    env = {"MOBIUS_TEST_PG_DSN": "postgresql+psycopg://a/x",
           "MOBIUS_TEST_PG_URL": "postgresql+psycopg://b/y"}
    assert resolve_pg_dsn(env) == "postgresql+psycopg://a/x"


def test_pg_dsn_falls_back_to_ci_url():
    from pg_dsn import resolve_pg_dsn
    assert resolve_pg_dsn({"MOBIUS_TEST_PG_URL": "postgresql+psycopg://b/y"}) == \
        "postgresql+psycopg://b/y"


def test_pg_dsn_empty_dsn_does_not_shadow_ci_url():
    from pg_dsn import resolve_pg_dsn
    assert resolve_pg_dsn({"MOBIUS_TEST_PG_DSN": "",
                           "MOBIUS_TEST_PG_URL": "postgresql+psycopg://b/y"}) == \
        "postgresql+psycopg://b/y"


def test_pg_dsn_missing_returns_none_so_tests_skip():
    from pg_dsn import resolve_pg_dsn
    assert resolve_pg_dsn({}) is None
