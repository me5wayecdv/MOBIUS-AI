"""durable isolated worker jobs

Revision ID: 0002
Revises: 0001
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "worker_jobs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("investigation_id", sa.String(length=40), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("artifact_key", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="queued"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("worker_id", sa.String(length=120), nullable=True),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("started_at", sa.String(length=40), nullable=True),
        sa.Column("finished_at", sa.String(length=40), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued','running','succeeded','failed','cancelled')",
            name="worker_job_status_known",
        ),
    )
    op.create_index("ix_worker_jobs_claim", "worker_jobs", ["status", "created_at"])
    op.create_index("ix_worker_jobs_investigation", "worker_jobs", ["investigation_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_worker_jobs_investigation", table_name="worker_jobs")
    op.drop_index("ix_worker_jobs_claim", table_name="worker_jobs")
    op.drop_table("worker_jobs")
