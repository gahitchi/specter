"""Add authenticated users, sessions, ownership, and pair-review labels.

Revision ID: 20260813_0002
Revises: 20260813_0001
Create Date: 2026-08-13
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260813_0002"
down_revision = "20260813_0001"
branch_labels = None
depends_on = None


def _columns(inspector, table: str) -> set[str]:
    return {column["name"] for column in inspector.get_columns(table)}


def _add_index(name: str, table: str, columns: list[str]) -> None:
    bind = op.get_bind()
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes(table)}
    if name not in indexes:
        op.create_index(name, table, columns)


def _add_foreign_key_column(table: str, column: sa.Column) -> None:
    """Add a referenced column without relying on SQLite ALTER CONSTRAINT."""
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table(table, recreate="always") as batch:
            batch.add_column(column)
        return
    op.add_column(table, column)


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "users" not in tables:
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("username", sa.String(64), nullable=False, unique=True),
            sa.Column("display_name", sa.String(120), nullable=False, server_default=""),
            sa.Column("password_hash", sa.Text(), nullable=False),
            sa.Column("role", sa.String(20), nullable=False, server_default="analyst"),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("failed_logins", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    _add_index("ix_users_username", "users", ["username"])
    _add_index("ix_users_role", "users", ["role"])
    _add_index("ix_users_active", "users", ["active"])

    inspector = sa.inspect(bind)
    if "user_sessions" not in inspector.get_table_names():
        op.create_table(
            "user_sessions",
            sa.Column("token_hash", sa.String(64), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("csrf_token", sa.String(64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        )
    _add_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
    _add_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"])

    inspector = sa.inspect(bind)
    if "entity_pair_reviews" not in inspector.get_table_names():
        op.create_table(
            "entity_pair_reviews",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("left_observation_id", sa.Integer(),
                      sa.ForeignKey("observations.id"), nullable=False),
            sa.Column("right_observation_id", sa.Integer(),
                      sa.ForeignKey("observations.id"), nullable=False),
            sa.Column("same_identity", sa.Boolean(), nullable=False),
            sa.Column("reviewer_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("reviewer", sa.String(120), nullable=False),
            sa.Column("verification_method", sa.String(200), nullable=False),
            sa.Column("note", sa.Text(), nullable=False, server_default=""),
            sa.Column("features", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
    for name, column in (
        ("ix_entity_pair_reviews_left_observation_id", "left_observation_id"),
        ("ix_entity_pair_reviews_right_observation_id", "right_observation_id"),
        ("ix_entity_pair_reviews_same_identity", "same_identity"),
        ("ix_entity_pair_reviews_reviewer_user_id", "reviewer_user_id"),
    ):
        _add_index(name, "entity_pair_reviews", [column])

    additions = {
        "targets": sa.Column(
            "owner_id",
            sa.Integer(),
            sa.ForeignKey("users.id", name="fk_targets_owner_id_users"),
            nullable=True,
        ),
        "observation_reviews": sa.Column(
            "reviewer_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", name="fk_observation_reviews_reviewer_user_id_users"),
            nullable=True,
        ),
        "audit_events": sa.Column(
            "actor_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", name="fk_audit_events_actor_user_id_users"),
            nullable=True,
        ),
    }
    inspector = sa.inspect(bind)
    for table, column in additions.items():
        if column.name not in _columns(inspector, table):
            _add_foreign_key_column(table, column)
        _add_index(f"ix_{table}_{column.name}", table, [column.name])


def downgrade() -> None:
    for table, column in (
        ("audit_events", "actor_user_id"),
        ("observation_reviews", "reviewer_user_id"),
        ("targets", "owner_id"),
    ):
        with op.batch_alter_table(table) as batch:
            batch.drop_index(f"ix_{table}_{column}")
            batch.drop_column(column)
    op.drop_table("entity_pair_reviews")
    op.drop_table("user_sessions")
    op.drop_table("users")
