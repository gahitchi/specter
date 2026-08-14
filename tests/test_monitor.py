"""Scheduler: schedules enqueue durable scans; cron validation."""

import pytest

from recon.models import Query
from recon.monitor.scheduler import MonitorScheduler, enqueue_scan_for_target, validate_cron
from recon.jobs.base import LocalQueue
from recon.store import get_db, repo
from recon.store import models_db as m


def test_validate_cron():
    assert validate_cron("0 */6 * * *")
    assert not validate_cron("not a cron")


def test_schedule_enqueues_scan_for_target_query():
    db = get_db()
    with db.session() as s:
        t = repo.get_or_create_target(s, Query(username="alice", email="a@x.com"),
                                      watchlist=True)
        tid = t.id
        repo.create_schedule(s, tid, "0 0 * * *")

    job_id = enqueue_scan_for_target(tid)
    q = LocalQueue()
    assert q.status(job_id) == "queued"

    leased = q.lease()
    assert leased["payload"]["query"]["username"] == "alice"
    assert leased["payload"]["query"]["email"] == "a@x.com"


def test_scheduler_reconciles_disabled_schedules():
    db = get_db()
    with db.session() as session:
        target = repo.get_or_create_target(session, Query(username="alice"))
        schedule = repo.create_schedule(session, target.id, "0 0 * * *")
        schedule_id = schedule.id

    scheduler = MonitorScheduler()
    assert scheduler.load() == 1
    assert scheduler.sched.get_job(f"sched-{schedule_id}") is not None

    with db.session() as session:
        session.get(m.Schedule, schedule_id).enabled = False

    assert scheduler.load() == 0
    assert scheduler.sched.get_job(f"sched-{schedule_id}") is None


@pytest.mark.asyncio
async def test_scheduler_starts_on_the_active_event_loop():
    scheduler = MonitorScheduler()
    assert scheduler.start() == 0
    assert scheduler.sched.running is True
    assert scheduler.sched.get_job("reconcile-schedules") is not None
    scheduler.shutdown()
