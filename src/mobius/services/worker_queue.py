"""Durable job lifecycle for isolated analysis workers.

The API owns job creation and result consumption. The worker needs access only to this
queue table plus read-only access to the content-addressed APK volume; it does not need
the application database tables or API credentials.
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.events import utcnow
from ..adapters.models import InvestigationRow, WorkerJobRow
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
        stmt = (
            select(WorkerJobRow)
            .where(WorkerJobRow.status == "queued", WorkerJobRow.kind == "recon_manifest")
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
        self.session.flush()
        return row

    def succeed(self, job_id: str, worker_id: str, result: dict) -> None:
        row = self.get(job_id)
        if row.status != "running" or row.worker_id != worker_id:
            raise ScanStateConflict("worker does not own this running job")
        row.status = "succeeded"
        row.result_json = result
        row.finished_at = utcnow()
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
        self.session.flush()
