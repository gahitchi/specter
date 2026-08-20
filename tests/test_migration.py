"""Alembic adopts a pre-migration SQLite database without losing its rows."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from recon.store.db import Database
from recon.store import models_db
from recon.store.repo import _target_query_predicate

_OLD_OBSERVATIONS = """
CREATE TABLE observations (
  id INTEGER PRIMARY KEY, run_id INTEGER, target_id INTEGER, entity_id INTEGER,
  source TEXT, category TEXT, label TEXT, url TEXT, verdict TEXT,
  confidence FLOAT, reasons JSON, signals JSON, data JSON,
  fingerprint TEXT, reliability FLOAT, created_at DATETIME
)
"""


def test_postgres_target_query_comparison_casts_json_to_jsonb():
    predicate = _target_query_predicate({"username": "alice"}, "postgresql")
    statement = sa.select(models_db.Target).where(predicate)
    compiled = str(statement.compile(dialect=postgresql.dialect()))

    assert "CAST(targets.query AS JSONB)" in compiled


def test_backfill_adds_missing_column_preserving_rows(tmp_path):
    dsn = f"sqlite:///{tmp_path / 'old.db'}"
    eng = sa.create_engine(dsn)
    with eng.begin() as c:
        c.execute(sa.text(_OLD_OBSERVATIONS))            # pre-breakdown schema
        c.execute(sa.text("INSERT INTO observations (id, source, verdict, confidence) "
                          "VALUES (1, 'username:GitHub', 'FOUND', 0.9)"))
    eng.dispose()

    with Database(dsn) as db:
        db.create_all()                                   # migration adds 'breakdown'

        insp = sa.inspect(db.engine)
        cols = {c["name"] for c in insp.get_columns("observations")}
        assert "breakdown" in cols
        # Existing row survives the migration.
        with db.session() as s:
            row = s.execute(
                sa.text("SELECT source, breakdown FROM observations WHERE id=1")
            ).one()
            assert row[0] == "username:GitHub"
            assert row[1] is None


def test_database_is_at_packaged_migration_head(fresh_db):
    assert fresh_db.schema_revision() == "20260814_0004"
    tables = set(sa.inspect(fresh_db.engine).get_table_names())
    assert {
        "observation_reviews", "source_health_checks", "audit_events",
        "job_activity_nodes",
    } <= tables


def test_account_migration_upgrades_existing_sqlite_schema(tmp_path):
    dsn = f"sqlite:///{tmp_path / 'version_09.db'}"
    eng = sa.create_engine(dsn)
    with eng.begin() as connection:
        connection.execute(sa.text(
            "CREATE TABLE targets (id INTEGER PRIMARY KEY, label VARCHAR(200), "
            "query JSON NOT NULL, watchlist BOOLEAN NOT NULL, created_at DATETIME NOT NULL)"
        ))
        connection.execute(sa.text(
            "CREATE TABLE observations (id INTEGER PRIMARY KEY)"
        ))
        connection.execute(sa.text(
            "CREATE TABLE observation_reviews (id INTEGER PRIMARY KEY, "
            "observation_id INTEGER NOT NULL, run_id INTEGER NOT NULL, "
            "target_id INTEGER NOT NULL, decision VARCHAR(20) NOT NULL, note TEXT NOT NULL, "
            "reviewer VARCHAR(120) NOT NULL, created_at DATETIME NOT NULL)"
        ))
        connection.execute(sa.text(
            "CREATE TABLE audit_events (id INTEGER PRIMARY KEY, action VARCHAR(80) NOT NULL, "
            "actor VARCHAR(120) NOT NULL, object_type VARCHAR(40) NOT NULL, "
            "object_id INTEGER, detail JSON NOT NULL, created_at DATETIME NOT NULL)"
        ))
        connection.execute(sa.text(
            "CREATE TABLE jobs (id INTEGER PRIMARY KEY, run_id INTEGER, "
            "kind VARCHAR(40) NOT NULL, payload JSON NOT NULL, status VARCHAR(20) NOT NULL, "
            "attempts INTEGER NOT NULL, leased_at DATETIME, error TEXT, "
            "created_at DATETIME NOT NULL)"
        ))
        connection.execute(sa.text(
            "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"
        ))
        connection.execute(sa.text(
            "INSERT INTO alembic_version (version_num) VALUES ('20260813_0001')"
        ))
        connection.execute(sa.text(
            "INSERT INTO targets (id, label, query, watchlist, created_at) "
            "VALUES (7, 'legacy target', '{}', 0, CURRENT_TIMESTAMP)"
        ))
    eng.dispose()

    with Database(dsn) as db:
        db.create_all()
        inspector = sa.inspect(db.engine)
        assert db.schema_revision() == "20260814_0004"
        assert "owner_id" in {column["name"] for column in inspector.get_columns("targets")}
        assert "reviewer_user_id" in {
            column["name"] for column in inspector.get_columns("observation_reviews")
        }
        assert "actor_user_id" in {
            column["name"] for column in inspector.get_columns("audit_events")
        }
        target_fks = inspector.get_foreign_keys("targets")
        assert any(fk["constrained_columns"] == ["owner_id"] for fk in target_fks)
        job_columns = {column["name"] for column in inspector.get_columns("jobs")}
        assert {"owner_id", "target_id"} <= job_columns
        with db.session() as session:
            assert session.execute(
                sa.text("SELECT label FROM targets WHERE id=7")
            ).scalar_one() == "legacy target"
