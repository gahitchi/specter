"""Account, password, session, and role primitives for authenticated mode."""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .store import models_db as m

ROLES = {"admin", "analyst", "reviewer"}
SESSION_COOKIE = "recon_session"
SECURE_SESSION_COOKIE = "__Host-recon_session"
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,63}$")
_PASSWORD = PasswordHasher(time_cost=2, memory_cost=19_456, parallelism=1)
_DUMMY_HASH: str | None = None


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _utc(value: dt.datetime) -> dt.datetime:
    return value.replace(tzinfo=dt.timezone.utc) if value.tzinfo is None else value


def normalize_username(username: str) -> str:
    normalized = username.strip().casefold()
    if not _USERNAME_RE.fullmatch(normalized):
        raise ValueError(
            "username must be 3-64 lowercase letters, numbers, dots, underscores, or hyphens"
        )
    return normalized


def validate_password(password: str) -> None:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    if len(password.encode("utf-8")) > 1024:
        raise ValueError("password is too long")


def hash_password(password: str) -> str:
    validate_password(password)
    return _PASSWORD.hash(password)


def _dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = _PASSWORD.hash("unusable authentication sentinel")
    return _DUMMY_HASH


def _verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _PASSWORD.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


@dataclass(frozen=True)
class Principal:
    user_id: int | None
    username: str
    display_name: str
    role: str
    csrf_token: str | None = None

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def can(self, action: str) -> bool:
        if self.is_admin:
            return True
        permissions = {
            "analyst": {
                "scan", "read_own", "review_own", "export_own", "delete_own",
            },
            "reviewer": {"read_all", "review_all"},
        }
        return action in permissions.get(self.role, set())


LOCAL_PRINCIPAL = Principal(None, "local", "Local administrator", "admin")


@dataclass(frozen=True)
class SessionCredentials:
    token: str
    csrf_token: str
    expires_at: dt.datetime


def create_user(
    session: Session,
    username: str,
    password: str,
    *,
    role: str = "analyst",
    display_name: str = "",
) -> m.User:
    username = normalize_username(username)
    if role not in ROLES:
        raise ValueError(f"role must be one of: {', '.join(sorted(ROLES))}")
    if session.execute(select(m.User.id).where(m.User.username == username)).first():
        raise ValueError(f"user {username!r} already exists")
    user = m.User(
        username=username,
        display_name=display_name.strip()[:120],
        password_hash=hash_password(password),
        role=role,
        active=True,
    )
    session.add(user)
    session.flush()
    return user


def set_password(session: Session, user: m.User, password: str) -> None:
    user.password_hash = hash_password(password)
    user.failed_logins = 0
    user.locked_until = None
    session.execute(delete(m.UserSession).where(m.UserSession.user_id == user.id))


def authenticate(session: Session, username: str, password: str) -> m.User | None:
    try:
        username = normalize_username(username)
    except ValueError:
        username = ""
    user = session.execute(select(m.User).where(m.User.username == username)).scalar_one_or_none()
    now = _now()
    stored_hash = user.password_hash if user is not None else _dummy_hash()
    verified = _verify_password(stored_hash, password[:1024])
    if user is None:
        return None
    if not user.active or (user.locked_until and _utc(user.locked_until) > now):
        return None
    if not verified:
        user.failed_logins += 1
        if user.failed_logins >= 5:
            minutes = min(60, 5 * (2 ** min(user.failed_logins - 5, 3)))
            user.locked_until = now + dt.timedelta(minutes=minutes)
        return None
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    if _PASSWORD.check_needs_rehash(user.password_hash):
        user.password_hash = _PASSWORD.hash(password)
    return user


def create_session(session: Session, user: m.User, *, hours: int = 12) -> SessionCredentials:
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    now = _now()
    expires_at = now + dt.timedelta(hours=hours)
    session.add(m.UserSession(
        token_hash=hashlib.sha256(token.encode("ascii")).hexdigest(),
        user_id=user.id,
        csrf_token=csrf_token,
        created_at=now,
        last_seen_at=now,
        expires_at=expires_at,
    ))
    return SessionCredentials(token, csrf_token, expires_at)


def principal_for_token(session: Session, token: str | None) -> Principal | None:
    if not token or len(token) > 256:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = session.get(m.UserSession, token_hash)
    if row is None:
        return None
    now = _now()
    if _utc(row.expires_at) <= now or not row.user.active:
        session.delete(row)
        return None
    row.last_seen_at = now
    return Principal(
        row.user.id,
        row.user.username,
        row.user.display_name,
        row.user.role,
        row.csrf_token,
    )


def revoke_session(session: Session, token: str | None) -> None:
    if token and len(token) <= 256:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        row = session.get(m.UserSession, token_hash)
        if row is not None:
            session.delete(row)


def prune_sessions(session: Session) -> int:
    result = session.execute(delete(m.UserSession).where(m.UserSession.expires_at <= _now()))
    return int(result.rowcount or 0)


def active_admin_count(session: Session) -> int:
    return int(session.scalar(
        select(func.count()).select_from(m.User).where(
            m.User.role == "admin", m.User.active.is_(True)
        )
    ) or 0)


def get_user(session: Session, username: str) -> m.User | None:
    try:
        normalized = normalize_username(username)
    except ValueError:
        return None
    return session.execute(select(m.User).where(m.User.username == normalized)).scalar_one_or_none()


def list_users(session: Session) -> list[m.User]:
    return list(session.execute(select(m.User).order_by(m.User.username)).scalars())
