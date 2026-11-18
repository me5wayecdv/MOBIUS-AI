"""persist reproducible PoC execution records and evidence links

Revision ID: 0005
Revises: 0004
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "poc_runs",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("investigation_id", sa.String(length=40), nullable=False),
        sa.Column("plan_id", sa.String(length=40), nullable=False),
        sa.Column("authorization_id", sa.String(length=40), nullable=False),
        sa.Column("target_sha256", sa.String(length=64), nullable=False),
        sa.Column("hypothesis_ids", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("exit_status", sa.String(length=20), nullable=False),
        sa.Column("input_sha256", sa.String(length=64), nullable=False),
        sa.Column("output_sha256", sa.String(length=64), nullable=False),
        sa.Column("input_json", sa.JSON(), nullable=False),
        sa.Column("output_json", sa.JSON(), nullable=False),
        sa.Column("tool_versions", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.String(length=40), nullable=False),
        sa.Column("finished_at", sa.String(length=40), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"]),
        sa.ForeignKeyConstraint(["authorization_id"], ["authorizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("investigation_id", "id", name="uq_poc_run_investigation_id"),
        sa.CheckConstraint("status IN ('passed','failed')", name="poc_run_status_known"),
    )
    op.create_index(
        "ix_poc_runs_investigation_created", "poc_runs", ["investigation_id", "created_at"]
    )
    op.create_table(
        "poc_run_evidence",
        sa.Column("investigation_id", sa.String(length=40), nullable=False),
        sa.Column("run_id", sa.String(length=40), nullable=False),
        sa.Column("evidence_id", sa.String(length=40), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.ForeignKeyConstraint(
            ["investigation_id", "run_id"],
            ["poc_runs.investigation_id", "poc_runs.id"],
            name="fk_poc_run_evidence_run_same_investigation",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id", "evidence_id"],
            ["evidence.investigation_id", "evidence.id"],
            name="fk_poc_run_evidence_evidence_same_investigation",
        ),
        sa.PrimaryKeyConstraint("investigation_id", "run_id", "evidence_id"),
    )


def downgrade() -> None:
    bind = op.get_bind()
    for table in ("poc_run_evidence", "poc_runs"):
        count = bind.execute(sa.text(f"SELECT COUNT(*) FROM {table}")).scalar_one()
        if count:
            raise RuntimeError(f"refusing to downgrade populated {table}; PoC evidence is retained")
    op.drop_table("poc_run_evidence")
    op.drop_index("ix_poc_runs_investigation_created", table_name="poc_runs")
    op.drop_table("poc_runs")
