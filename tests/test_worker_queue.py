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
