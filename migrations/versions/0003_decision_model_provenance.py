"""persist model decision provenance

Revision ID: 0003
Revises: 0002
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("decisions", sa.Column("provider", sa.String(length=40), nullable=True))
    op.add_column("decisions", sa.Column("model_role", sa.String(length=20), nullable=True))
    op.add_column("decisions", sa.Column("requested_model", sa.String(length=120), nullable=True))
    op.add_column("decisions", sa.Column("system_prompt_sha256", sa.String(length=64), nullable=True))
    op.add_column("decisions", sa.Column("input_sha256", sa.String(length=64), nullable=True))
    op.add_column("decisions", sa.Column("schema_sha256", sa.String(length=64), nullable=True))
    op.add_column("decisions", sa.Column("response_sha256", sa.String(length=64), nullable=True))
    op.add_column("decisions", sa.Column("schema_name", sa.String(length=120), nullable=True))
    op.add_column("decisions", sa.Column("output_json", sa.JSON(), nullable=True))
    op.add_column("decisions", sa.Column("input_tokens", sa.Integer(), nullable=True))
    op.add_column("decisions", sa.Column("output_tokens", sa.Integer(), nullable=True))
    op.add_column("decisions", sa.Column("latency_ms", sa.Integer(), nullable=True))
    op.add_column("decisions", sa.Column("temperature", sa.Float(), nullable=True))
    op.add_column("decisions", sa.Column("max_tokens", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("decisions", "max_tokens")
    op.drop_column("decisions", "temperature")
    op.drop_column("decisions", "latency_ms")
    op.drop_column("decisions", "output_tokens")
    op.drop_column("decisions", "input_tokens")
    op.drop_column("decisions", "output_json")
    op.drop_column("decisions", "schema_name")
    op.drop_column("decisions", "response_sha256")
    op.drop_column("decisions", "schema_sha256")
    op.drop_column("decisions", "input_sha256")
    op.drop_column("decisions", "system_prompt_sha256")
    op.drop_column("decisions", "requested_model")
    op.drop_column("decisions", "model_role")
    op.drop_column("decisions", "provider")
