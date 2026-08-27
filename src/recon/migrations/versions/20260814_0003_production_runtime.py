"""Add tenant and target ownership to durable jobs.

Revision ID: 20260814_0003
Revises: 20260813_0002
Create Date: 2026-08-14
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260814_0003"
down_revision = "20260813_0002"
branch_labels = None
depends_on = None


def _columns(bind) -> set[str]:
    return {column["name"] for column in sa.inspect(bind).get_columns("jobs")}


def _indexes(bind) -> set[str]:
    return {index["name"] for index in sa.inspect(bind).get_indexes("jobs")}


def upgrade() -> None:
    bind = op.get_bind()
    existing = _columns(bind)
    additions = []
    if "owner_id" not in existing:
        additions.append(sa.Column(
            "owner_id",
            sa.Integer(),
            sa.ForeignKey("users.id", name="fk_jobs_owner_id_users"),
            nullable=True,
        ))
    if "target_id" not in existing:
        additions.append(sa.Column(
            "target_id",
            sa.Integer(),
            sa.ForeignKey("targets.id", name="fk_jobs_target_id_targets"),
            nullable=True,
        ))
    if additions:
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table("jobs", recreate="always") as batch:
                for column in additions:
                    batch.add_column(column)
        else:
            for column in additions:
                op.add_column("jobs", column)

    indexes = _indexes(bind)
    for name, column in (
        ("ix_jobs_owner_id", "owner_id"),
        ("ix_jobs_target_id", "target_id"),
    ):
        if name not in indexes:
            op.create_index(name, "jobs", [column])


def downgrade() -> None:
    with op.batch_alter_table("jobs") as batch:
        batch.drop_index("ix_jobs_target_id")
        batch.drop_index("ix_jobs_owner_id")
        batch.drop_column("target_id")
        batch.drop_column("owner_id")
