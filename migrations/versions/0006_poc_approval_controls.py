"""add PoC approval, timeout, cancellation and cleanup metadata

Revision ID: 0006
Revises: 0005
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

def upgrade() -> None:
    with op.batch_alter_table("poc_runs") as batch:
        batch.drop_constraint("poc_run_status_known", type_="check")
        batch.create_check_constraint("poc_run_status_known", "status IN ('passed','failed','cancelled','timed_out')")
        batch.add_column(sa.Column("approval_id", sa.String(length=40), nullable=True))
        batch.add_column(sa.Column("cancel_requested_at", sa.String(length=40), nullable=True))
        batch.add_column(sa.Column("cleanup_json", sa.JSON(), nullable=True))
        batch.create_foreign_key("fk_poc_run_approval", "approvals", ["approval_id"], ["id"])

def downgrade() -> None:
    bind = op.get_bind()
    count = bind.execute(sa.text("SELECT COUNT(*) FROM poc_runs")).scalar_one()
    if count:
        raise RuntimeError("refusing to downgrade populated poc_runs; execution audit records are retained")
    with op.batch_alter_table("poc_runs") as batch:
        batch.drop_constraint("fk_poc_run_approval", type_="foreignkey")
        batch.drop_column("cleanup_json")
        batch.drop_column("cancel_requested_at")
        batch.drop_column("approval_id")
        batch.drop_constraint("poc_run_status_known", type_="check")
        batch.create_check_constraint("poc_run_status_known", "status IN ('passed','failed')")
