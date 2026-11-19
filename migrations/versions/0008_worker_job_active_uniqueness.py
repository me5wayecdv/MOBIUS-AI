"""active worker job uniqueness + terminal rejected status

Revision ID: 0008
Revises: 0007

One active worker job per (investigation, kind): queued, running, or
succeeded-and-unapplied. This is the database guarantee behind the read-then-
insert check in WorkerQueue.enqueue_*, which races without it. Also widens the
status check constraint with 'rejected', the terminal state for a succeeded
job whose payload can never be applied (the rejecting request rolls back, so
the mark is committed separately by the API).
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

_ACTIVE = "status IN ('queued','running') OR (status='succeeded' AND applied_at IS NULL)"


def upgrade() -> None:
    # batch mode: SQLite cannot ALTER constraints; on Postgres this is the
    # same drop-and-recreate, just scoped.
    with op.batch_alter_table("worker_jobs") as batch:
        batch.drop_constraint("worker_job_status_known", type_="check")
        batch.create_check_constraint(
            "worker_job_status_known",
            "status IN ('queued','running','succeeded','failed','cancelled','rejected')",
        )
    # Fail loudly rather than dedupe: pre-existing duplicate ACTIVE rows are
    # data only the owner may reconcile; the migration reports and stops.
    bind = op.get_bind()
    duplicates = bind.execute(sa.text(
        "SELECT investigation_id, kind, COUNT(*) AS n FROM worker_jobs "
        f"WHERE {_ACTIVE} GROUP BY investigation_id, kind HAVING COUNT(*) > 1"
    )).fetchall()
    if duplicates:
        raise RuntimeError(
            "existing duplicate active worker jobs found; refusing to create "
            f"the uniqueness index over them: {[(d[0], d[1], d[2]) for d in duplicates]}"
        )
    # sqlite_where must match the model metadata predicate exactly: a full
    # unique index on sqlite would reject legitimate terminal-state history.
    op.create_index(
        "uq_worker_jobs_active",
        "worker_jobs",
        ["investigation_id", "kind"],
        unique=True,
        sqlite_where=sa.text(_ACTIVE),
        postgresql_where=sa.text(_ACTIVE),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_worker_jobs_active",
        table_name="worker_jobs",
        sqlite_where=sa.text(_ACTIVE),
        postgresql_where=sa.text(_ACTIVE),
    )
    with op.batch_alter_table("worker_jobs") as batch:
        batch.drop_constraint("worker_job_status_known", type_="check")
        batch.create_check_constraint(
            "worker_job_status_known",
            "status IN ('queued','running','succeeded','failed','cancelled')",
        )
