"""Database engine + session management.

Local-first default is a SQLite file; set RECON_DB_DSN (or config.storage_dsn)
to a Postgres URL for scale-out. One SQLAlchemy layer covers both.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Iterator, Optional

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..config import SETTINGS, env_value


class Database:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        connect_args = (
            {"check_same_thread": False, "timeout": 30}
            if dsn.startswith("sqlite")
            else {}
        )
        engine_options = {"future": True, "connect_args": connect_args}
        if not dsn.startswith("sqlite"):
            engine_options.update({
                "pool_pre_ping": True,
                "pool_size": SETTINGS.db_pool_size,
                "max_overflow": SETTINGS.db_max_overflow,
                "pool_recycle": SETTINGS.db_pool_recycle_seconds,
            })
        self.engine: Engine = create_engine(dsn, **engine_options)
        if dsn.startswith("sqlite"):
            self._enable_sqlite_concurrency(self.engine)
        self._Session = sessionmaker(self.engine, expire_on_commit=False, future=True)

    @staticmethod
    def _enable_sqlite_concurrency(engine: Engine) -> None:
        """The recursive engine runs modules concurrently, each doing a little
        reliability bookkeeping. On the default SQLite file that means concurrent
        writers; without these pragmas a writer can hit 'database is locked' and a
        module silently fails to run. WAL lets readers and a writer coexist, and
        busy_timeout makes a contending writer wait rather than error."""
        @event.listens_for(engine, "connect")
        def _set_pragmas(dbapi_conn, _record):  # pragma: no cover - driver callback
            cur = dbapi_conn.cursor()
            try:
                cur.execute("PRAGMA busy_timeout=30000")
                try:
                    cur.execute("PRAGMA journal_mode=WAL")
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower():
                        raise
                cur.execute("PRAGMA synchronous=NORMAL")
                cur.execute("PRAGMA foreign_keys=ON")
            finally:
                cur.close()

    def create_all(self) -> None:
        """Upgrade this database to the packaged Alembic head revision.

        Kept under the historical method name so existing integrations continue
        to work; schema creation and upgrades are now both migration-driven.
        """
        from alembic import command
        from alembic.config import Config

        migrations = Path(__file__).resolve().parents[1] / "migrations"
        config = Config()
        config.set_main_option("script_location", str(migrations))
        config.set_main_option("sqlalchemy.url", self.dsn.replace("%", "%%"))

        def upgrade(connection) -> None:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")

        with self.engine.connect() as connection:
            if connection.dialect.name != "sqlite":
                with connection.begin():
                    upgrade(connection)
                return

            # Every local service validates migrations at startup. Serialize that
            # check across processes so a fresh database cannot race while Alembic
            # creates its version table or applies the first revision.
            connection.exec_driver_sql("BEGIN EXCLUSIVE")
            try:
                upgrade(connection)
            except Exception:
                connection.rollback()
                raise
            connection.commit()

    def migration_head(self) -> str | None:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        migrations = Path(__file__).resolve().parents[1] / "migrations"
        config = Config()
        config.set_main_option("script_location", str(migrations))
        return ScriptDirectory.from_config(config).get_current_head()

    def ensure_schema(self, *, auto_upgrade: bool) -> None:
        if auto_upgrade:
            self.create_all()
            return
        current = self.schema_revision()
        head = self.migration_head()
        if current != head:
            raise RuntimeError(
                f"database schema is not current (current={current or 'none'}, head={head}); "
                "run `specter db-upgrade` before starting the service"
            )

    def ping(self) -> None:
        with self.engine.connect() as connection:
            connection.execute(text("SELECT 1"))

    def schema_revision(self) -> str | None:
        from alembic.runtime.migration import MigrationContext

        with self.engine.connect() as connection:
            return MigrationContext.configure(connection).get_current_revision()

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self._Session()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    def close(self) -> None:
        """Dispose the engine's connection pool, closing pooled DBAPI handles.

        Without this, an abandoned Database leaks its SQLite connections until
        the interpreter's GC reclaims them (surfacing as ResourceWarning under
        warnings-as-errors). Idempotent and safe to call more than once."""
        self.engine.dispose()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _default_dsn() -> str:
    dsn = env_value("RECON_DB_DSN", SETTINGS.storage_dsn) or SETTINGS.storage_dsn
    if dsn.startswith("sqlite") and ":memory:" not in dsn:
        # Ensure parent dir exists for file-based sqlite.
        path = dsn.split("///", 1)[-1]
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
    return dsn


_DB: Optional[Database] = None


def get_db() -> Database:
    global _DB
    if _DB is None:
        _DB = Database(_default_dsn())
        _DB.ensure_schema(auto_upgrade=SETTINGS.auto_migrate)
    return _DB


def init_db(dsn: str | None = None) -> Database:
    """(Re)initialize the global database and create tables. Used by CLI/tests."""
    global _DB
    if _DB is not None:
        _DB.close()  # release the previous engine's pooled connections
    _DB = Database(dsn or _default_dsn())
    _DB.create_all()
    return _DB


def close_db() -> None:
    global _DB
    if _DB is not None:
        _DB.close()
        _DB = None
