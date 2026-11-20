"""gate-category scoring metadata on frontier entries

Revision ID: 0010
Revises: 0009
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("frontier_entries", sa.Column("gate_category", sa.String(length=80), nullable=True))


def downgrade() -> None:
    op.drop_column("frontier_entries", "gate_category")
