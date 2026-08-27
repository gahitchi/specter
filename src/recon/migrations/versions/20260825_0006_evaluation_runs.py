"""Add durable evaluation history.

Revision ID: 20260825_0006
Revises: 20260825_0005
Create Date: 2026-08-25
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260825_0006"
down_revision = "20260825_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "evaluation_runs" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "evaluation_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("dataset_name", sa.String(160), nullable=False),
        sa.Column("dataset_sha256", sa.String(64), nullable=False),
        sa.Column("provenance", sa.String(40), nullable=False),
        sa.Column("cases", sa.Integer(), nullable=False),
        sa.Column("claims", sa.Integer(), nullable=False),
        sa.Column("precision", sa.Float(), nullable=False),
        sa.Column("recall", sa.Float(), nullable=False),
        sa.Column("gate_status", sa.String(30), nullable=False),
        sa.Column("report", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    for name in ("dataset_name", "dataset_sha256", "provenance", "gate_status"):
        op.create_index(f"ix_evaluation_runs_{name}", "evaluation_runs", [name])


def downgrade() -> None:
    op.drop_table("evaluation_runs")
