"""Durable job lifecycle for isolated analysis workers.

The API owns job creation and result consumption. The worker needs access only to this
queue table plus read-only access to the content-addressed APK volume; it does not need
the application database tables or API credentials.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from ..adapters.events import utcnow
from ..adapters.models import ApplicationRow, AuthorizationRow, InvestigationRow, WorkerJobRow
from .intake import is_expired
from .errors import NotFound, ScanStateConflict


class WorkerQueue:
    def __init__(self, session: Session) -> None:
        self.session = session

    def enqueue_recon(self, investigation_id: str, artifact_key: str) -> WorkerJobRow:
        investigation = self.session.get(InvestigationRow, investigation_id)
        if investigation is None:
            raise NotFound(f"investigation {investigation_id} not found")
        if investigation.state != "RECON":
            raise ScanStateConflict(
                f"RECON job requires RECON state, got {investigation.state}"
            )
        application = self.session.get(ApplicationRow, investigation.application_id)
        authorization = self.session.get(AuthorizationRow, investigation.authorization_id)
        if application is None or authorization is None:
            raise ScanStateConflict("RECON requires an existing APK and authorization")
        if (
            authorization.revoked_at is not None
            or is_expired(authorization.expires_at)
            or authorization.apk_sha256 != application.sha256
        ):
            raise ScanStateConflict("APK authorization is no longer valid for this artifact")
        if artifact_key != application.artifact_key:
            raise ScanStateConflict("worker job artifact does not match the investigation APK")
        active = self.session.execute(
            select(WorkerJobRow).where(
                WorkerJobRow.investigation_id == investigation_id,
                WorkerJobRow.kind == "recon_manifest",
                WorkerJobRow.status.in_(("queued", "running", "succeeded")),
                WorkerJobRow.applied_at.is_(None),
            ).limit(1)
        ).scalar_one_or_none()
        if active is not None:
            raise ScanStateConflict(f"RECON worker job {active.id} is already active or awaiting application")
        job = WorkerJobRow(
            id=str(uuid4()),
            investigation_id=investigation_id,
            kind="recon_manifest",
            artifact_key=artifact_key,
            status="queued",
            attempts=0,
            created_at=utcnow(),
        )
        self.session.add(job)
        self.session.flush()
        return job

    def get(self, job_id: str) -> WorkerJobRow:
        row = self.session.get(WorkerJobRow, job_id)
        if row is None:
            raise NotFound(f"worker job {job_id} not found")
        return row

    def claim(self, worker_id: str) -> WorkerJobRow | None:
        now = utcnow()
        self.session.execute(
            update(WorkerJobRow)
            .where(
                WorkerJobRow.status == 'running',
                WorkerJobRow.attempts >= 3,
                WorkerJobRow.lease_until < now,
            )
            .values(
                status='failed', error_code='WorkerLeaseExhausted',
                error_detail='worker lease expired after three attempts',
                finished_at=now, lease_until=None,
            )
        )
        stmt = (
            select(WorkerJobRow)
            .where(
                WorkerJobRow.kind == "recon_manifest",
                WorkerJobRow.attempts < 3,
                or_(
                    WorkerJobRow.status == "queued",
                    (WorkerJobRow.status == "running") & (WorkerJobRow.lease_until < utcnow()),
                ),
            )
            .order_by(WorkerJobRow.created_at.asc(), WorkerJobRow.id.asc())
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        row = self.session.execute(stmt).scalar_one_or_none()
        if row is None:
            return None
        row.status = "running"
        row.worker_id = worker_id
        row.attempts += 1
        row.started_at = utcnow()
        row.lease_until = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        self.session.flush()
        return row

    def succeed(self, job_id: str, worker_id: str, result: dict) -> None:
        row = self.get(job_id)
        if row.status != "running" or row.worker_id != worker_id:
            raise ScanStateConflict("worker does not own this running job")
        row.status = "succeeded"
        row.result_json = result
        row.finished_at = utcnow()
        row.lease_until = None
        row.error_code = None
        row.error_detail = None
        self.session.flush()

    def fail(self, job_id: str, worker_id: str, code: str, detail: str) -> None:
        row = self.get(job_id)
        if row.status != "running" or row.worker_id != worker_id:
            raise ScanStateConflict("worker does not own this running job")
        row.status = "failed"
        row.error_code = code[:80]
        row.error_detail = detail[:4000]
        row.finished_at = utcnow()
        row.lease_until = None
        self.session.flush()
