"""Establish the versioned 0.9 schema and adopt legacy databases.

Revision ID: 20260813_0001
Revises:
Create Date: 2026-08-13
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

from recon.store.models_db import Base

revision = "20260813_0001"
down_revision = None
branch_labels = None
depends_on = None


_LEGACY_NULLABLE_COLUMNS = {
    "runs": ("finished_at", "provenance"),
    "observations": ("entity_id", "url", "breakdown", "trace", "fingerprint"),
    "entities": ("label", "breakdown"),
    "sources": ("breaker_until", "last_error"),
    "jobs": ("run_id", "leased_at", "error"),
    "schedules": ("last_run_at",),
    "change_events": ("source", "label"),
}


def upgrade() -> None:
    bind = op.get_bind()
    # This first revision doubles as adoption for pre-Alembic installations:
    # missing tables are created, existing investigation tables are preserved.
    Base.metadata.create_all(bind=bind)

    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    metadata_tables = {table.name: table for table in Base.metadata.sorted_tables}
    for table_name, column_names in _LEGACY_NULLABLE_COLUMNS.items():
        if table_name not in tables:
            continue
        existing = {column["name"] for column in inspector.get_columns(table_name)}
        table = metadata_tables[table_name]
        for column_name in column_names:
            if column_name in existing:
                continue
            model_column = table.c[column_name]
            op.add_column(
                table_name,
                sa.Column(column_name, model_column.type, nullable=True),
            )


def downgrade() -> None:
    # Downgrading the initial revision is intentionally destructive and should
    # only be used for disposable development databases.
    Base.metadata.drop_all(bind=op.get_bind())
