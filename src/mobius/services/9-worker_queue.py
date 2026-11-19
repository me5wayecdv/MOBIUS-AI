"""Durable job lifecycle for isolated analysis workers.

The API owns job creation and result consumption. The worker needs access only to this
queue table plus read-only access to the content-addressed APK volume; it does not need
the application database tables or API credentials.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..adapters.events import utcnow
from ..adapters.models import ApplicationRow, AuthorizationRow, InvestigationRow, WorkerJobRow
from .intake import is_expired
from .errors import NotFound, ScanStateConflict


class WorkerQueue:
    def __init__(self, session: Session) -> None:
        self.session = session

    def _flush_new(self, job: WorkerJobRow) -> WorkerJobRow:
        """Insert a job, converting the active-job unique index violation into
        the same conflict the pre-check raises. The index (not the pre-check)
        is what makes concurrent enqueues safe."""
        self.session.add(job)
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ScanStateConflict(
                f"a {job.kind} worker job is already active or awaiting application"
            ) from exc
        return job

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
        return self._flush_new(job)

    def enqueue_dex_index(self, investigation_id: str, artifact_key: str) -> WorkerJobRow:
        investigation = self.session.get(InvestigationRow, investigation_id)
        if investigation is None:
            raise NotFound(f"investigation {investigation_id} not found")
        if investigation.state != "SURFACE_READY":
            raise ScanStateConflict(
                f"DEX indexing requires SURFACE_READY state, got {investigation.state}"
            )
        application = self.session.get(ApplicationRow, investigation.application_id)
        authorization = self.session.get(AuthorizationRow, investigation.authorization_id)
        if application is None or authorization is None:
            raise ScanStateConflict("DEX indexing requires an existing APK and authorization")
        if (
            authorization.revoked_at is not None
            or is_expired(authorization.expires_at)
            or authorization.apk_sha256 != application.sha256
        ):
            raise ScanStateConflict("APK authorization is no longer valid for this artifact")
        if artifact_key != application.artifact_key:
            raise ScanStateConflict("DEX job artifact does not match the investigation APK")
        active = self.session.execute(
            select(WorkerJobRow).where(
                WorkerJobRow.investigation_id == investigation_id,
                WorkerJobRow.kind == "dex_index",
                WorkerJobRow.status.in_(("queued", "running", "succeeded")),
                WorkerJobRow.applied_at.is_(None),
            ).limit(1)
        ).scalar_one_or_none()
        if active is not None:
            raise ScanStateConflict(
                f"DEX worker job {active.id} is already active or awaiting application"
            )
        job = WorkerJobRow(
            id=str(uuid4()),
            investigation_id=investigation_id,
            kind="dex_index",
            artifact_key=artifact_key,
            status="queued",
            attempts=0,
            created_at=utcnow(),
        )
        return self._flush_new(job)

    def enqueue_provider_analysis(self, investigation_id: str, artifact_key: str) -> WorkerJobRow:
        """Queue isolated provider-exposure analysis for the authorized APK.

        Same state and authorization gates as DEX indexing: the worker parses
        attacker-supplied bytes, so it only runs on an authorized, surfaced
        investigation."""
        investigation = self.session.get(InvestigationRow, investigation_id)
        if investigation is None:
            raise NotFound(f"investigation {investigation_id} not found")
        if investigation.state != "SURFACE_READY":
            raise ScanStateConflict(
                f"provider analysis requires SURFACE_READY state, got {investigation.state}"
            )
        application = self.session.get(ApplicationRow, investigation.application_id)
        authorization = self.session.get(AuthorizationRow, investigation.authorization_id)
        if application is None or authorization is None:
            raise ScanStateConflict("provider analysis requires an existing APK and authorization")
        if (
            authorization.revoked_at is not None
            or is_expired(authorization.expires_at)
            or authorization.apk_sha256 != application.sha256
        ):
            raise ScanStateConflict("APK authorization is no longer valid for this artifact")
        if artifact_key != application.artifact_key:
            raise ScanStateConflict("provider job artifact does not match the investigation APK")
        already_applied = self.session.execute(
            select(WorkerJobRow).where(
                WorkerJobRow.investigation_id == investigation_id,
                WorkerJobRow.kind == "provider_analysis",
                WorkerJobRow.applied_at.is_not(None),
            ).limit(1)
        ).scalar_one_or_none()
        if already_applied is not None:
            # A second run would duplicate findings and evidence. Refuse BEFORE
            # any compute is queued; the applied result stands.
            raise ScanStateConflict(
                f"provider analysis was already applied for this investigation "
                f"(worker job {already_applied.id})"
            )
        active = self.session.execute(
            select(WorkerJobRow).where(
                WorkerJobRow.investigation_id == investigation_id,
                WorkerJobRow.kind == "provider_analysis",
                WorkerJobRow.status.in_(("queued", "running", "succeeded")),
                WorkerJobRow.applied_at.is_(None),
            ).limit(1)
        ).scalar_one_or_none()
        if active is not None:
            raise ScanStateConflict(
                f"provider-analysis worker job {active.id} is already active or awaiting application"
            )
        job = WorkerJobRow(
            id=str(uuid4()),
            investigation_id=investigation_id,
            kind="provider_analysis",
            artifact_key=artifact_key,
            status="queued",
            attempts=0,
            created_at=utcnow(),
        )
        return self._flush_new(job)

    def enqueue_jadx_decompile(self, investigation_id: str, artifact_key: str) -> WorkerJobRow:
        """Queue isolated JADX decompilation for the authorized APK of one investigation."""
        investigation = self.session.get(InvestigationRow, investigation_id)
        if investigation is None:
            raise NotFound(f"investigation {investigation_id} not found")
        if investigation.state != "SURFACE_READY":
            raise ScanStateConflict(
                f"JADX decompilation requires SURFACE_READY state, got {investigation.state}"
            )
        application = self.session.get(ApplicationRow, investigation.application_id)
        authorization = self.session.get(AuthorizationRow, investigation.authorization_id)
        if application is None or authorization is None:
            raise ScanStateConflict("JADX decompilation requires an existing APK and authorization")
        if (
            authorization.revoked_at is not None
            or is_expired(authorization.expires_at)
            or authorization.apk_sha256 != application.sha256
        ):
            raise ScanStateConflict("APK authorization is no longer valid for this artifact")
        if artifact_key != application.artifact_key:
            raise ScanStateConflict("JADX job artifact does not match the investigation APK")
        active = self.session.execute(
            select(WorkerJobRow).where(
                WorkerJobRow.investigation_id == investigation_id,
                WorkerJobRow.kind == "jadx_decompile",
                WorkerJobRow.status.in_(("queued", "running")),
            ).limit(1)
        ).scalar_one_or_none()
        if active is not None:
            raise ScanStateConflict(
                f"JADX worker job {active.id} is already active or awaiting application"
            )
        job = WorkerJobRow(
            id=str(uuid4()),
            investigation_id=investigation_id,
            kind="jadx_decompile",
            artifact_key=artifact_key,
            status="queued",
            attempts=0,
            created_at=utcnow(),
        )
        return self._flush_new(job)

    def enqueue_secrets_analysis(self, investigation_id: str, artifact_key: str) -> WorkerJobRow:
        """Queue isolated secrets candidate analysis for the authorized APK.

        Same state and authorization gates as provider analysis: the worker
        parses attacker-supplied bytes, so it only runs on an authorized,
        surfaced investigation. The result applies through the secrets
        apply route's anchor chain; this method only queues compute."""
        investigation = self.session.get(InvestigationRow, investigation_id)
        if investigation is None:
            raise NotFound(f"investigation {investigation_id} not found")
        if investigation.state != "SURFACE_READY":
            raise ScanStateConflict(
                f"secrets analysis requires SURFACE_READY state, got {investigation.state}"
            )
        application = self.session.get(ApplicationRow, investigation.application_id)
        authorization = self.session.get(AuthorizationRow, investigation.authorization_id)
        if application is None or authorization is None:
            raise ScanStateConflict("secrets analysis requires an existing APK and authorization")
        if (
            authorization.revoked_at is not None
            or is_expired(authorization.expires_at)
            or authorization.apk_sha256 != application.sha256
        ):
            raise ScanStateConflict("APK authorization is no longer valid for this artifact")
        if artifact_key != application.artifact_key:
            raise ScanStateConflict("worker job artifact does not match the investigation APK")
        already_applied = self.session.execute(
            select(WorkerJobRow).where(
                WorkerJobRow.investigation_id == investigation_id,
                WorkerJobRow.kind == "secrets_analysis",
                WorkerJobRow.applied_at.is_not(None),
            ).limit(1)
        ).scalar_one_or_none()
        if already_applied is not None:
            # A second run would duplicate candidates and evidence. Refuse
            # BEFORE any compute is queued; the applied result stands.
            raise ScanStateConflict(
                f"secrets analysis was already applied for this investigation "
                f"(worker job {already_applied.id})"
            )
        active = self.session.execute(
            select(WorkerJobRow).where(
                WorkerJobRow.investigation_id == investigation_id,
                WorkerJobRow.kind == "secrets_analysis",
                WorkerJobRow.status.in_(("queued", "running", "succeeded")),
                WorkerJobRow.applied_at.is_(None),
            ).limit(1)
        ).scalar_one_or_none()
        if active is not None:
            raise ScanStateConflict(
                f"secrets-analysis worker job {active.id} is already active or awaiting application"
            )
        job = WorkerJobRow(
            id=str(uuid4()),
            investigation_id=investigation_id,
            kind="secrets_analysis",
            artifact_key=artifact_key,
            status="queued",
            attempts=0,
            created_at=utcnow(),
        )
        return self._flush_new(job)

    def claim_apply(self, job_id: str) -> WorkerJobRow:
        """Race-safe apply gate: exactly one concurrent applier can move a
        succeeded, unapplied job into the applied state. The conditional
        UPDATE is atomic on Postgres (the loser blocks on the row lock, then
        re-evaluates the WHERE and matches 0 rows). On failure the whole
        request transaction rolls back, applied_at included, so a transient
        mid-apply failure stays retryable."""
        result = self.session.execute(
            update(WorkerJobRow)
            .where(
                WorkerJobRow.id == job_id,
                WorkerJobRow.status == "succeeded",
                WorkerJobRow.applied_at.is_(None),
            )
            .values(applied_at=utcnow())
        )
        if result.rowcount != 1:
            raise ScanStateConflict(
                "provider-analysis worker result has already been applied or is not ready"
            )
        return self.get(job_id)

    def terminal_reject(self, job_id: str, code: str, detail: str) -> None:
        """Mark a succeeded-but-unappliable job terminally rejected so the
        investigation is not stuck (a rejected job never blocks re-enqueue).
        Evidence is retained on the row (error_code/error_detail). Intended to
        run in its own committed session because the rejecting request
        transaction rolls back with its HTTP error."""
        now = utcnow()
        result = self.session.execute(
            update(WorkerJobRow)
            .where(
                WorkerJobRow.id == job_id,
                WorkerJobRow.status == "succeeded",
                WorkerJobRow.applied_at.is_(None),
            )
            .values(
                status="rejected",
                error_code=code[:80],
                error_detail=detail[:4000],
                finished_at=now,
                lease_until=None,
            )
        )
        if result.rowcount != 1:
            # Another actor applied or rejected it concurrently; its outcome wins.
            raise ScanStateConflict(
                "provider-analysis worker job changed state during rejection"
            )

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
                WorkerJobRow.kind.in_(
                    ("recon_manifest", "dex_index", "jadx_decompile",
                     "provider_analysis", "secrets_analysis")
                ),
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
        # The lease must outlive the job's tool timeout or a slow worker loses
        # ownership mid-run and its late result hits a job it no longer owns.
        lease_minutes = {"jadx_decompile": 10, "provider_analysis": 20,
                         "secrets_analysis": 20}.get(row.kind, 5)
        row.lease_until = (
            datetime.now(timezone.utc) + timedelta(minutes=lease_minutes)
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        self.session.flush()
        return row

    def succeed(self, job_id: str, worker_id: str, result: dict,
                staged_sha256: str | None = None) -> None:
        row = self.get(job_id)
        if row.status != "running" or row.worker_id != worker_id:
            raise ScanStateConflict("worker does not own this running job")
        row.status = "succeeded"
        row.result_json = result
        row.staged_sha256 = staged_sha256
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
