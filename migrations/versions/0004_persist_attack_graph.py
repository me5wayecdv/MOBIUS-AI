"""persist investigation-scoped attack graph and provenance links

Revision ID: 0004
Revises: 0003
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Additive schema only. CI applies this migration to disposable SQLite/PostgreSQL
    # databases; never point this migration at a valuable or production database.
    op.create_table(
        "graph_nodes",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("investigation_id", sa.String(length=40), nullable=False),
        sa.Column("node_type", sa.String(length=40), nullable=False),
        sa.Column("label", sa.Text(), nullable=False),
        sa.Column("ref", sa.String(length=1000), nullable=True),
        sa.Column("assertion", sa.String(length=20), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(["investigation_id"], ["investigations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("investigation_id", "id", name="uq_graph_node_investigation_id"),
        sa.UniqueConstraint("investigation_id", "node_type", "ref", name="uq_graph_node_identity"),
    )
    op.create_index(
        "ix_graph_nodes_investigation_type", "graph_nodes", ["investigation_id", "node_type"]
    )
    op.create_table(
        "graph_edges",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("investigation_id", sa.String(length=40), nullable=False),
        sa.Column("source_id", sa.String(length=40), nullable=False),
        sa.Column("target_id", sa.String(length=40), nullable=False),
        sa.Column("relation", sa.String(length=60), nullable=False),
        sa.Column("assertion", sa.String(length=20), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["investigation_id", "source_id"],
            ["graph_nodes.investigation_id", "graph_nodes.id"],
            name="fk_graph_edge_source_same_investigation",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id", "target_id"],
            ["graph_nodes.investigation_id", "graph_nodes.id"],
            name="fk_graph_edge_target_same_investigation",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("investigation_id", "id", name="uq_graph_edge_investigation_id"),
        sa.UniqueConstraint(
            "investigation_id", "source_id", "target_id", "relation",
            name="uq_graph_edge_identity",
        ),
        sa.CheckConstraint(
            "assertion <> 'hypothesis' OR (rationale IS NOT NULL AND length(rationale) > 0)",
            name="graph_hypothesis_states_why",
        ),
    )
    op.create_index(
        "ix_graph_edges_investigation_source", "graph_edges", ["investigation_id", "source_id"]
    )
    op.create_index(
        "ix_graph_edges_investigation_target", "graph_edges", ["investigation_id", "target_id"]
    )
    op.create_table(
        "graph_node_evidence",
        sa.Column("investigation_id", sa.String(length=40), nullable=False),
        sa.Column("node_id", sa.String(length=40), nullable=False),
        sa.Column("evidence_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["investigation_id", "node_id"],
            ["graph_nodes.investigation_id", "graph_nodes.id"],
            name="fk_graph_node_evidence_node_same_investigation",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id", "evidence_id"],
            ["evidence.investigation_id", "evidence.id"],
            name="fk_graph_node_evidence_evidence_same_investigation",
        ),
        sa.PrimaryKeyConstraint("investigation_id", "node_id", "evidence_id"),
    )
    op.create_table(
        "graph_edge_evidence",
        sa.Column("investigation_id", sa.String(length=40), nullable=False),
        sa.Column("edge_id", sa.String(length=40), nullable=False),
        sa.Column("evidence_id", sa.String(length=40), nullable=False),
        sa.ForeignKeyConstraint(
            ["investigation_id", "edge_id"],
            ["graph_edges.investigation_id", "graph_edges.id"],
            name="fk_graph_edge_evidence_edge_same_investigation",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id", "evidence_id"],
            ["evidence.investigation_id", "evidence.id"],
            name="fk_graph_edge_evidence_evidence_same_investigation",
        ),
        sa.PrimaryKeyConstraint("investigation_id", "edge_id", "evidence_id"),
    )


def downgrade() -> None:
    # The migration test suite rolls back a freshly-created, empty disposable database.
    # Refuse to drop any graph table once it contains data: graph provenance is retained.
    bind = op.get_bind()
    for table in (
        "graph_edge_evidence", "graph_node_evidence", "graph_edges", "graph_nodes"
    ):
        count = bind.execute(sa.text(f"SELECT COUNT(*) FROM {table}")).scalar_one()
        if count:
            raise RuntimeError(
                f"refusing to downgrade populated {table}; graph data is retained"
            )
    op.drop_table("graph_edge_evidence")
    op.drop_table("graph_node_evidence")
    op.drop_index("ix_graph_edges_investigation_target", table_name="graph_edges")
    op.drop_index("ix_graph_edges_investigation_source", table_name="graph_edges")
    op.drop_table("graph_edges")
    op.drop_index("ix_graph_nodes_investigation_type", table_name="graph_nodes")
    op.drop_table("graph_nodes")
