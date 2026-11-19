"""host-side staged-input digest on worker jobs

Revision ID: 0009
Revises: 0008
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("worker_jobs", sa.Column("staged_sha256", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("worker_jobs", "staged_sha256")
