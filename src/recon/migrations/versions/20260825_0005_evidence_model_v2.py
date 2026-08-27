"""Add first-class evidence provenance, temporal state, and contradictions.

Revision ID: 20260825_0005
Revises: 20260814_0004
Create Date: 2026-08-25
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260825_0005"
down_revision = "20260814_0004"
branch_labels = None
depends_on = None


_OBSERVATION_COLUMNS = (
    sa.Column("collector", sa.String(120), nullable=True),
    sa.Column("origin", sa.String(240), nullable=True),
    sa.Column("evidence_class", sa.String(40), nullable=True),
    sa.Column("independence_key", sa.String(200), nullable=True),
    sa.Column("claim_key", sa.String(64), nullable=True),
    sa.Column("extractions", sa.JSON(), nullable=True),
    sa.Column("confidence_dimensions", sa.JSON(), nullable=True),
    sa.Column("policy", sa.JSON(), nullable=True),
    sa.Column("completeness", sa.String(20), nullable=True),
    sa.Column("temporal_status", sa.String(20), nullable=True),
    sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
    sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
    sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
)


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = {column["name"] for column in inspector.get_columns("observations")}
    additions = [column for column in _OBSERVATION_COLUMNS if column.name not in existing]
    if additions:
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table("observations", recreate="always") as batch:
                for column in additions:
                    batch.add_column(column)
        else:
            for column in additions:
                op.add_column("observations", column)

    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("observations")}
    for name in (
        "collector", "origin", "evidence_class", "independence_key", "claim_key",
        "completeness", "temporal_status", "observed_at",
    ):
        index_name = f"ix_observations_{name}"
        if index_name not in indexes:
            op.create_index(index_name, "observations", [name])

    if "observation_contradictions" not in sa.inspect(bind).get_table_names():
        op.create_table(
            "observation_contradictions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("run_id", sa.Integer(), sa.ForeignKey("runs.id"), nullable=False),
            sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=False),
            sa.Column("claim_key", sa.String(64), nullable=False),
            sa.Column(
                "earlier_observation_id",
                sa.Integer(),
                sa.ForeignKey("observations.id"),
                nullable=False,
            ),
            sa.Column(
                "later_observation_id",
                sa.Integer(),
                sa.ForeignKey("observations.id"),
                nullable=False,
            ),
            sa.Column("kind", sa.String(60), nullable=False),
            sa.Column("severity", sa.String(20), nullable=False),
            sa.Column("reasons", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint(
                "earlier_observation_id",
                "later_observation_id",
                "kind",
                name="uq_observation_contradiction",
            ),
        )
        for name in (
            "run_id", "target_id", "claim_key", "earlier_observation_id",
            "later_observation_id", "kind", "severity",
        ):
            op.create_index(
                f"ix_observation_contradictions_{name}",
                "observation_contradictions",
                [name],
            )


def downgrade() -> None:
    op.drop_table("observation_contradictions")
    with op.batch_alter_table("observations") as batch:
        for column in reversed(_OBSERVATION_COLUMNS):
            batch.drop_column(column.name)
