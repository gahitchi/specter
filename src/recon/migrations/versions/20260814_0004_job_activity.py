"""Persist compact live graph state for durable jobs.

Revision ID: 20260814_0004
Revises: 20260814_0003
Create Date: 2026-08-14
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260814_0004"
down_revision = "20260814_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if "job_activity_nodes" in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        "job_activity_nodes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "job_id",
            sa.Integer(),
            sa.ForeignKey("jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("node_key", sa.String(64), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("job_id", "node_key", name="uq_job_activity_node"),
    )
    op.create_index("ix_job_activity_nodes_job_id", "job_activity_nodes", ["job_id"])
    op.create_index("ix_job_activity_nodes_sequence", "job_activity_nodes", ["sequence"])


def downgrade() -> None:
    op.drop_table("job_activity_nodes")
