"""Store-backed result cache + circuit-breaker / reliability bookkeeping.

All DB access is synchronous; callers invoke these via asyncio.to_thread.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Optional

from sqlalchemy.exc import IntegrityError

from ..config import SETTINGS
from ..models import Finding, Query
from ..store import get_db
from ..store import models_db as m


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _aware(d: dt.datetime | None) -> dt.datetime | None:
    """SQLite returns naive datetimes; treat stored values as UTC for comparison."""
    if d is None:
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def cache_key(connector: str, query: Query) -> str:
    relevant = query.normalized().model_dump(exclude_none=True)
    blob = json.dumps(relevant, sort_keys=True)
    digest = hashlib.sha256(blob.encode()).hexdigest()[:24]
    return f"{connector}:{digest}"


def get_cached(connector: str, query: Query) -> Optional[list[Finding]]:
    db = get_db()
    key = cache_key(connector, query)
    with db.session() as s:
        entry = s.get(m.CacheEntry, key)
        if not entry:
            return None
        if entry.expires_at and _aware(entry.expires_at) < _now():
            return None
        return [Finding(**f) for f in entry.payload.get("findings", [])]


def set_cached(connector: str, query: Query, findings: list[Finding]) -> None:
    db = get_db()
    key = cache_key(connector, query)
    ttl = SETTINGS.cache_ttl_seconds
    with db.session() as s:
        entry = s.get(m.CacheEntry, key)
        payload = {"findings": [f.model_dump() for f in findings]}
        if entry:
            entry.payload = payload
            entry.created_at = _now()
            entry.expires_at = _now() + dt.timedelta(seconds=ttl)
        else:
            s.add(m.CacheEntry(key=key, payload=payload, created_at=_now(),
                               expires_at=_now() + dt.timedelta(seconds=ttl)))


# --- Generic key-based cache (used by the recursive engine's modules) -------
# Modules are keyed by an artifact, not a whole Query, and a replayed module
# must reproduce BOTH its findings AND the artifacts it emitted (so recursion
# still proceeds on a cache hit). The payload therefore carries both lists.

def get_cached_key(key: str) -> Optional[dict]:
    """Return {"findings": [...], "artifacts": [...]} payload or None if absent/expired."""
    db = get_db()
    with db.session() as s:
        entry = s.get(m.CacheEntry, key)
        if not entry:
            return None
        if entry.expires_at and _aware(entry.expires_at) < _now():
            return None
        return entry.payload


def set_cached_key(key: str, payload: dict) -> None:
    db = get_db()
    ttl = SETTINGS.cache_ttl_seconds
    with db.session() as s:
        entry = s.get(m.CacheEntry, key)
        if entry:
            entry.payload = payload
            entry.created_at = _now()
            entry.expires_at = _now() + dt.timedelta(seconds=ttl)
        else:
            s.add(m.CacheEntry(key=key, payload=payload, created_at=_now(),
                               expires_at=_now() + dt.timedelta(seconds=ttl)))


# --- Source reliability + circuit breaker ----------------------------------

def _get_source(s, name: str, kind: str, prior: float) -> m.Source:
    src = s.get(m.Source, name)
    if src:
        return src
    # The recursive engine runs sibling modules concurrently; on first encounter
    # of a source two threads can race to INSERT the same row. The loser hits a
    # UNIQUE violation — catch it, roll back, and read the winner's row instead of
    # letting the exception abort the module mid-flight.
    src = m.Source(name=name, kind=kind, reliability=prior)
    s.add(src)
    try:
        s.flush()
    except IntegrityError:
        s.rollback()
        src = s.get(m.Source, name)
        if src is None:  # extremely unlikely (writer not yet committed) — retry
            src = m.Source(name=name, kind=kind, reliability=prior)
            s.add(src)
            s.flush()
    return src


def breaker_open(name: str, kind: str, prior: float) -> bool:
    """True if the source's breaker is open and still cooling down."""
    db = get_db()
    with db.session() as s:
        src = _get_source(s, name, kind, prior)
        if src.breaker_state == "open" and _aware(src.breaker_until) and _aware(src.breaker_until) > _now():
            return True
        if src.breaker_state == "open":
            src.breaker_state = "half_open"  # cooldown elapsed -> allow a trial
        return False


def record_success(name: str, kind: str, prior: float) -> None:
    db = get_db()
    with db.session() as s:
        src = _get_source(s, name, kind, prior)
        src.successes += 1
        src.breaker_state = "closed"
        src.breaker_until = None
        src.last_error = None
        # EMA toward 1.0 on success.
        src.reliability = round(0.9 * src.reliability + 0.1 * 1.0, 4)


def record_failure(name: str, kind: str, prior: float, error: str) -> None:
    db = get_db()
    with db.session() as s:
        src = _get_source(s, name, kind, prior)
        src.failures += 1
        src.last_error = error[:500]
        src.reliability = round(0.9 * src.reliability + 0.1 * 0.0, 4)
        recent_fail_ratio = src.failures / max(1, src.successes + src.failures)
        if src.failures >= SETTINGS.breaker_fail_threshold and recent_fail_ratio > 0.5:
            src.breaker_state = "open"
            src.breaker_until = _now() + dt.timedelta(seconds=SETTINGS.breaker_cooldown_seconds)


def current_reliability(name: str, kind: str, prior: float) -> float:
    db = get_db()
    with db.session() as s:
        return _get_source(s, name, kind, prior).reliability
