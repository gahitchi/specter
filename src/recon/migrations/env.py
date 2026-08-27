from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from recon.store.models_db import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = os.environ.get("RECON_DB_DSN") or config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    supplied_connection = config.attributes.get("connection")
    if supplied_connection is not None:
        context.configure(
            connection=supplied_connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=supplied_connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()
        return

    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = (
        os.environ.get("RECON_DB_DSN") or config.get_main_option("sqlalchemy.url")
    )
    connectable = engine_from_config(
        section, prefix="sqlalchemy.", poolclass=pool.NullPool, future=True
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
