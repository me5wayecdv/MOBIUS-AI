"""bind PoC approval records to the exact immutable plan digest

Revision ID: 0007
Revises: 0006
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("approvals", sa.Column("plan_sha256", sa.String(length=64), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    count = bind.execute(sa.text("SELECT COUNT(*) FROM approvals WHERE plan_sha256 IS NOT NULL")).scalar_one()
    if count:
        raise RuntimeError("refusing to downgrade PoC plan approval provenance; approval audit data is retained")
    op.drop_column("approvals", "plan_sha256")
