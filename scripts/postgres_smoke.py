"""Exercise the migrated PostgreSQL schema and durable queue bookkeeping."""

from __future__ import annotations

import os
import uuid

from recon.auth import create_user
from recon.jobs.base import LocalQueue
from recon.models import Query
from recon.store import db as db_mod
from recon.store import models_db as m
from recon.store import repo


def main() -> None:
    dsn = os.environ["RECON_DB_DSN"]
    database = db_mod.init_db(dsn)
    try:
        if database.engine.dialect.name != "postgresql":
            raise RuntimeError("PostgreSQL smoke test is not connected to PostgreSQL")
        if database.schema_revision() != database.migration_head():
            raise RuntimeError("PostgreSQL schema is not at the packaged migration head")
        suffix = uuid.uuid4().hex[:12]
        with database.session() as session:
            owner = create_user(
                session,
                f"smoke-{suffix}",
                f"smoke-only-{suffix}-password",
            )
            target = repo.get_or_create_target(
                session,
                Query(username=f"smoke-{suffix}"),
                owner_id=owner.id,
            )
            run = repo.create_run(session, target)
            repo.finish_run(session, run, "done", {"hits": 0})
            owner_id, target_id, run_id = owner.id, target.id, run.id

        queue = LocalQueue()
        job_id = queue.enqueue(
            "scan",
            {"query": {"username": f"smoke-{suffix}"}},
            owner_id=owner_id,
            target_id=target_id,
        )
        leased = queue.lease()
        if not leased or leased["id"] != job_id or leased["owner_id"] != owner_id:
            raise RuntimeError("durable PostgreSQL job lease did not preserve ownership")
        queue.complete(job_id, run_id)
        with database.session() as session:
            job = session.get(m.Job, job_id)
            if not job or job.status != "done" or job.run_id != run_id:
                raise RuntimeError("durable PostgreSQL job completion was not persisted")
    finally:
        db_mod.close_db()


if __name__ == "__main__":
    main()
