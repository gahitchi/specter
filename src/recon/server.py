"""Local dashboard and JSON API.

The server binds to loopback. Investigation data stays in local storage, while
collection requests necessarily send the supplied identifiers to the selected
public sources. Host and origin checks protect the local API from browser-based
cross-site requests and DNS rebinding.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .auth import (
    LOCAL_PRINCIPAL,
    SECURE_SESSION_COOKIE,
    SESSION_COOKIE,
    Principal,
    authenticate,
    create_session,
    create_user,
    list_users,
    principal_for_token,
    revoke_session,
)
from .config import SETTINGS, env_value
from .identifiers import IdentifierKind, resolve_query
from .keys import KNOWN_KEYS, VAULT
from .models import Query
from .modules.registry import MODULES
from .orchestrator import run_stream, scan
from .observability import METRICS, configure_logging
from .security import LoginRateLimiter, RequestBodyLimitMiddleware
from .store import get_db, repo

_OPTIONAL_KEY_USERS = {"github": ["github"], "hibp": ["breach"]}
_IDENTIFIER_MAX = 320
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
        "script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "Cross-Origin-Resource-Policy": "same-origin",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}
_REQUEST_LOG = logging.getLogger("recon.http")
LOGIN_LIMITER = LoginRateLimiter(SETTINGS.login_attempts_per_minute)


class ScanPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str | None = Field(default=None, max_length=_IDENTIFIER_MAX)
    subject_type: IdentifierKind | None = None
    username: str | None = Field(default=None, max_length=_IDENTIFIER_MAX)
    email: str | None = Field(default=None, max_length=_IDENTIFIER_MAX)
    phone: str | None = Field(default=None, max_length=_IDENTIFIER_MAX)
    domain: str | None = Field(default=None, max_length=_IDENTIFIER_MAX)
    name: str | None = Field(default=None, max_length=_IDENTIFIER_MAX)
    url: str | None = Field(default=None, max_length=_IDENTIFIER_MAX)
    ip_address: str | None = Field(default=None, max_length=_IDENTIFIER_MAX)
    label: str | None = Field(default=None, max_length=200)
    watchlist: bool = False

    def query(self) -> Query:
        return self.resolve()[0]

    def resolve(self) -> tuple[Query, dict[str, Any]]:
        values = self.model_dump(
            include={
                "username", "email", "phone", "domain", "name", "url", "ip_address"
            }
        )
        return resolve_query(
            self.subject,
            hint=self.subject_type,
            default_phone_region=SETTINGS.phone_default_region,
            **values,
        )


class KeyPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(max_length=40)
    value: str = Field(default="", max_length=8192)


class ReviewPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["accepted", "rejected", "unresolved"]
    note: str = Field(default="", max_length=4000)
    reviewer: str = Field(default="local", min_length=1, max_length=120)


class DeletePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: bool
    actor: str = Field(default="local", min_length=1, max_length=120)


class RetentionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    days: int = Field(ge=1, le=36500)
    dry_run: bool = True
    actor: str = Field(default="local", min_length=1, max_length=120)


class ExportPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    redacted: bool = True
    actor: str = Field(default="local", min_length=1, max_length=120)


class LoginPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class UserPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=1024)
    display_name: str = Field(default="", max_length=120)
    role: Literal["admin", "analyst", "reviewer"] = "analyst"


class UserUpdatePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["admin", "analyst", "reviewer"] | None = None
    active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=1024)


class PairReviewPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    left_observation_id: int = Field(gt=0)
    right_observation_id: int = Field(gt=0)
    same_identity: bool
    verification_method: str = Field(min_length=5, max_length=200)
    note: str = Field(default="", max_length=4000)


def _modules_for_key(name: str) -> list[str]:
    used = [module.name for module in MODULES if name in module.requires_keys]
    return used or _OPTIONAL_KEY_USERS.get(name, [])


def _resolve_query_or_422(
    subject: str | None = None,
    subject_type: str | IdentifierKind | None = None,
    **values: str | None,
) -> tuple[Query, dict[str, Any]]:
    if subject is not None and len(subject) > _IDENTIFIER_MAX:
        raise HTTPException(status_code=422, detail="identifier is too long")
    for value in values.values():
        if value is not None and len(value) > _IDENTIFIER_MAX:
            raise HTTPException(status_code=422, detail="identifier is too long")
    try:
        return resolve_query(
            subject,
            hint=subject_type,
            default_phone_region=SETTINGS.phone_default_region,
            **values,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _query_or_422(**values: str | None) -> Query:
    return _resolve_query_or_422(**values)[0]


def _same_origin(request: Request, origin: str) -> bool:
    parsed = urlsplit(origin)
    return (
        parsed.scheme in {"http", "https"}
        and parsed.netloc.lower() == request.headers.get("host", "").lower()
        and parsed.scheme == request.url.scheme
    )


PACKAGE_DIR = Path(__file__).resolve().parent
WEB_DIR = PACKAGE_DIR / "web"
ICON_PATH = PACKAGE_DIR / "assets" / "specter.png"


@asynccontextmanager
async def _lifespan(_app):
    configure_logging(SETTINGS)
    _validate_service_mode()
    if SETTINGS.auth_required:
        from .auth import prune_sessions

        with get_db().session() as session:
            prune_sessions(session)
    try:
        yield
    finally:
        from .store.db import close_db

        close_db()


app = FastAPI(
    title="Specter",
    version=__version__,
    lifespan=_lifespan,
    docs_url=None if SETTINGS.production_mode else "/docs",
    redoc_url=None if SETTINGS.production_mode else "/redoc",
    openapi_url=None if SETTINGS.production_mode else "/openapi.json",
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=list(SETTINGS.allowed_hosts),
)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=SETTINGS.max_request_body_bytes)


@app.middleware("http")
async def protect_local_app(request: Request, call_next):
    proxy_operational_path = (
        SETTINGS.tls_termination == "proxy"
        and request.url.path in {"/health/live", "/health/ready", "/metrics"}
    )
    if SETTINGS.remote_mode and request.url.scheme != "https" and not proxy_operational_path:
        return JSONResponse({"error": "HTTPS is required in remote mode"}, status_code=426)
    principal = LOCAL_PRINCIPAL
    if SETTINGS.auth_required:
        cookie_name = SECURE_SESSION_COOKIE if SETTINGS.remote_mode else SESSION_COOKIE
        with get_db().session() as session:
            principal = principal_for_token(session, request.cookies.get(cookie_name))
        public = request.url.path in {"/api/auth/login", "/api/auth/status"}
        if request.url.path.startswith("/api/") and not public and principal is None:
            return JSONResponse({"error": "authentication required"}, status_code=401)
    request.state.principal = principal

    if request.url.path.startswith("/api/"):
        if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
            return JSONResponse({"error": "cross-site request rejected"}, status_code=403)
        origin = request.headers.get("origin")
        if origin and not _same_origin(request, origin):
            return JSONResponse({"error": "cross-origin request rejected"}, status_code=403)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            content_type = request.headers.get("content-type", "").split(";", 1)[0].lower()
            if content_type != "application/json":
                return JSONResponse({"error": "application/json required"}, status_code=415)
            if (
                SETTINGS.auth_required
                and request.url.path != "/api/auth/login"
                and principal is not None
                and request.headers.get("x-csrf-token") != principal.csrf_token
            ):
                return JSONResponse({"error": "CSRF token missing or invalid"}, status_code=403)

    response = await call_next(request)
    return response


@app.middleware("http")
async def observe_and_secure(request: Request, call_next):
    started = time.perf_counter()
    request_id = secrets.token_hex(16)
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
    except Exception:
        duration = time.perf_counter() - started
        METRICS.record(request.method, 500, duration)
        _REQUEST_LOG.exception(
            "request failed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": 500,
                "duration_ms": round(duration * 1000, 2),
            },
        )
        raise
    for name, value in _SECURITY_HEADERS.items():
        response.headers[name] = value
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Request-ID"] = request_id
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    duration = time.perf_counter() - started
    METRICS.record(request.method, status, duration)
    _REQUEST_LOG.info(
        "request",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status": status,
            "duration_ms": round(duration * 1000, 2),
        },
    )
    return response


def _row(obj: Any, fields: tuple[str, ...]) -> dict:
    return {field: getattr(obj, field) for field in fields}


def _compact_run_stats(stats: dict | None) -> dict:
    stats = stats or {}
    compact = {
        key: stats.get(key)
        for key in ("total", "hits", "artifacts", "insights", "stop_reason")
        if key in stats
    }
    profile = stats.get("profile") or {}
    if profile:
        compact["profile"] = {
            key: profile.get(key) for key in ("title", "status", "confidence")
        }
    reasoning = stats.get("reasoning") or {}
    if reasoning:
        compact["reasoning"] = {
            "objective": reasoning.get("objective"),
            "confidence": reasoning.get("confidence"),
            "next_actions": len(reasoning.get("next_actions") or []),
        }
    if "error" in stats:
        compact["error"] = stats["error"]
    return compact


def _principal(request: Request) -> Principal:
    return getattr(request.state, "principal", LOCAL_PRINCIPAL)


def _require(principal: Principal, action: str) -> None:
    if not principal.can(action):
        raise HTTPException(status_code=403, detail="permission denied")


def _can_access_target(session, principal: Principal, target_id: int, *, write: bool = False):
    target = session.get(repo.m.Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail=f"target {target_id} not found")
    broad = principal.can("review_all") if write else principal.can("read_all")
    if not principal.is_admin and not broad and target.owner_id != principal.user_id:
        raise HTTPException(status_code=404, detail=f"target {target_id} not found")
    return target


def _can_access_run(session, principal: Principal, run_id: int, *, write: bool = False):
    run = session.get(repo.m.Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"run {run_id} not found")
    _can_access_target(session, principal, run.target_id, write=write)
    return run


@app.get("/api/auth/status")
async def api_auth_status(request: Request) -> JSONResponse:
    principal = getattr(request.state, "principal", None)
    return JSONResponse({
        "required": SETTINGS.auth_required,
        "remote": SETTINGS.remote_mode,
        "production": SETTINGS.production_mode,
        "live_scans_enabled": SETTINGS.allow_live_scans,
        "authenticated": principal is not None,
        "user": (
            {
                "id": principal.user_id,
                "username": principal.username,
                "display_name": principal.display_name,
                "role": principal.role,
            }
            if principal is not None else None
        ),
        "csrf_token": principal.csrf_token if principal is not None else None,
    })


@app.post("/api/auth/login")
async def api_login(request: Request, payload: LoginPayload) -> JSONResponse:
    if not SETTINGS.auth_required:
        return JSONResponse({"error": "authentication mode is disabled"}, status_code=400)
    client = request.client.host if request.client else "unknown"
    if not await LOGIN_LIMITER.allow(client):
        return JSONResponse(
            {"error": "too many sign-in attempts"},
            status_code=429,
            headers={"Retry-After": "60"},
        )
    with get_db().session() as session:
        from .governance import add_audit_event

        user = authenticate(session, payload.username, payload.password)
        if user is None:
            add_audit_event(
                session, "auth.failed", "session", None,
                actor=payload.username.strip()[:120] or "unknown",
                detail={"reason": "invalid credentials"},
            )
            return JSONResponse({"error": "invalid credentials"}, status_code=401)
        credentials = create_session(session, user, hours=SETTINGS.session_hours)
        add_audit_event(
            session, "auth.succeeded", "user", user.id,
            actor=user.username, actor_user_id=user.id,
        )
        username, role = user.username, user.role
    response = JSONResponse({"authenticated": True, "username": username, "role": role,
                             "csrf_token": credentials.csrf_token})
    cookie_name = SECURE_SESSION_COOKIE if SETTINGS.remote_mode else SESSION_COOKIE
    response.set_cookie(
        cookie_name,
        credentials.token,
        httponly=True,
        secure=SETTINGS.remote_mode,
        samesite="strict",
        path="/",
        max_age=SETTINGS.session_hours * 3600,
    )
    return response


@app.post("/api/auth/logout")
async def api_logout(request: Request) -> JSONResponse:
    cookie_name = SECURE_SESSION_COOKIE if SETTINGS.remote_mode else SESSION_COOKIE
    with get_db().session() as session:
        from .governance import add_audit_event

        principal = _principal(request)
        revoke_session(session, request.cookies.get(cookie_name))
        add_audit_event(
            session, "auth.logged_out", "user", principal.user_id,
            actor=principal.username, actor_user_id=principal.user_id,
        )
    response = JSONResponse({"authenticated": False})
    response.delete_cookie(cookie_name, path="/")
    response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    return response


@app.get("/api/users")
async def api_users(request: Request) -> JSONResponse:
    principal = _principal(request)
    _require(principal, "admin")
    with get_db().session() as session:
        return JSONResponse([
            {
                **_row(user, ("id", "username", "display_name", "role", "active")),
                "created_at": user.created_at.isoformat(),
                "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            }
            for user in list_users(session)
        ])


@app.post("/api/users")
async def api_create_user(request: Request, payload: UserPayload) -> JSONResponse:
    principal = _principal(request)
    _require(principal, "admin")
    try:
        with get_db().session() as session:
            user = create_user(
                session,
                payload.username,
                payload.password,
                role=payload.role,
                display_name=payload.display_name,
            )
            from .governance import add_audit_event
            add_audit_event(
                session, "user.created", "user", user.id,
                actor=principal.username, actor_user_id=principal.user_id,
                detail={"username": user.username, "role": user.role},
            )
            return JSONResponse(_row(user, ("id", "username", "display_name", "role", "active")))
    except ValueError:
        return JSONResponse({"error": "invalid user details"}, status_code=400)


@app.patch("/api/users/{user_id}")
async def api_update_user(
    request: Request, user_id: int, payload: UserUpdatePayload
) -> JSONResponse:
    from .auth import active_admin_count, set_password
    from .governance import add_audit_event

    principal = _principal(request)
    _require(principal, "admin")
    try:
        with get_db().session() as session:
            user = session.get(repo.m.User, user_id)
            if user is None:
                return JSONResponse({"error": f"user {user_id} not found"}, status_code=404)
            removing_admin = user.role == "admin" and (
                payload.role not in {None, "admin"} or payload.active is False
            )
            if removing_admin and active_admin_count(session) <= 1:
                return JSONResponse(
                    {"error": "cannot disable or demote the last active administrator"},
                    status_code=400,
                )
            if payload.role is not None:
                user.role = payload.role
            if payload.active is not None:
                user.active = payload.active
            if payload.password is not None:
                set_password(session, user, payload.password)
            add_audit_event(
                session, "user.updated", "user", user.id,
                actor=principal.username, actor_user_id=principal.user_id,
                detail={"role": user.role, "active": user.active,
                        "password_reset": payload.password is not None},
            )
            return JSONResponse(_row(user, ("id", "username", "display_name", "role", "active")))
    except ValueError:
        return JSONResponse({"error": "invalid user update"}, status_code=400)


@app.get("/api/expansion")
async def api_expansion(request: Request) -> JSONResponse:
    from .maturity import assess

    principal = _principal(request)
    result = assess(get_db())
    return JSONResponse({
        **result,
        "requested": SETTINGS.expansion_requested,
        "ml_model_configured": bool(SETTINGS.ml_model_file),
        "remote_mode": SETTINGS.remote_mode,
        "multi_user": SETTINGS.auth_required,
        "role": principal.role,
    })


@app.post("/api/pair-reviews")
async def api_pair_review(request: Request, payload: PairReviewPayload) -> JSONResponse:
    from .governance import add_audit_event
    from .ml_identity import review_pair

    principal = _principal(request)
    try:
        with get_db().session() as session:
            for observation_id in (
                payload.left_observation_id, payload.right_observation_id
            ):
                observation = session.get(repo.m.Observation, observation_id)
                if observation is None:
                    raise LookupError(f"observation {observation_id} not found")
                _can_access_target(session, principal, observation.target_id, write=True)
            row = review_pair(
                session,
                payload.left_observation_id,
                payload.right_observation_id,
                payload.same_identity,
                reviewer=principal.username,
                reviewer_user_id=principal.user_id,
                verification_method=payload.verification_method,
                note=payload.note,
            )
            add_audit_event(
                session, "entity_pair.reviewed", "entity_pair_review", row.id,
                actor=principal.username, actor_user_id=principal.user_id,
                detail={"same_identity": row.same_identity},
            )
            return JSONResponse({
                **_row(row, ("id", "left_observation_id", "right_observation_id",
                             "same_identity", "reviewer", "verification_method", "note")),
                "features": row.features,
                "created_at": row.created_at.isoformat(),
            })
    except (LookupError, ValueError):
        return JSONResponse({"error": "invalid pair review"}, status_code=400)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/icon.png", include_in_schema=False)
async def application_icon() -> FileResponse:
    return FileResponse(
        ICON_PATH,
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=31536000, immutable"},
    )


@app.get("/api/search")
async def search(
    request: Request,
    subject: str | None = None,
    subject_type: IdentifierKind | None = None,
    username: str | None = None,
    email: str | None = None,
    phone: str | None = None,
    domain: str | None = None,
    name: str | None = None,
    url: str | None = None,
    ip_address: str | None = None,
) -> StreamingResponse:
    principal = _principal(request)
    _require(principal, "scan")
    if not SETTINGS.allow_live_scans:
        raise HTTPException(
            status_code=409,
            detail="live scans are disabled; submit a durable scan instead",
        )
    query, intake = _resolve_query_or_422(
        subject,
        subject_type,
        username=username,
        email=email,
        phone=phone,
        domain=domain,
        name=name,
        url=url,
        ip_address=ip_address,
    )

    async def event_gen():
        yield f"data: {json.dumps({'type': 'intake', 'intake': intake})}\n\n"
        async for event in run_stream(query, intake=intake):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/scan")
async def api_scan(request: Request, payload: ScanPayload) -> JSONResponse:
    principal = _principal(request)
    _require(principal, "scan")
    try:
        query, intake = payload.resolve()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if SETTINGS.queue_backend == "arq":
        from .governance import add_audit_event
        from .jobs import get_queue

        job_payload = {
            "query": query.model_dump(exclude_none=True),
            "intake": intake,
            "label": payload.label,
            "watchlist": payload.watchlist,
        }
        job_id = await asyncio.to_thread(
            get_queue().enqueue,
            "scan",
            job_payload,
            owner_id=principal.user_id,
        )
        with get_db().session() as session:
            add_audit_event(
                session,
                "scan.queued",
                "job",
                job_id,
                actor=principal.username,
                actor_user_id=principal.user_id,
            )
        return JSONResponse(
            {"job_id": job_id, "status": "queued", "intake": intake},
            status_code=202,
            headers={"Location": f"/api/jobs/{job_id}"},
        )
    activity_nodes: dict[str, dict] = {}

    async def capture_activity(activity: dict) -> None:
        activity_nodes[str(activity["id"])] = dict(activity)

    result = await scan(
        query,
        label=payload.label,
        watchlist=payload.watchlist,
        owner_id=principal.user_id,
        activity_callback=capture_activity,
        intake=intake,
    )
    return JSONResponse({
        "run_id": result["run_id"],
        "target_id": result["target_id"],
        "summary": result["summary"],
        "profile": result["summary"].get("profile"),
        "intake": intake,
        "reasoning": result["reasoning"],
        "changes": result["changes"],
        "hits": sum(1 for finding in result["findings"] if finding.is_hit),
        "activity": sorted(
            activity_nodes.values(), key=lambda item: int(item.get("sequence") or 0)
        ),
    })


@app.get("/api/jobs/{job_id}")
async def api_job(request: Request, job_id: int) -> JSONResponse:
    principal = _principal(request)
    with get_db().session() as session:
        job = session.get(repo.m.Job, job_id)
        if job is None or (
            not principal.can("read_all") and job.owner_id != principal.user_id
        ):
            raise HTTPException(status_code=404, detail=f"job {job_id} not found")
        result = {
            **_row(job, ("id", "status", "attempts", "run_id", "target_id")),
            "error": job.error if job.status == "error" else None,
            "created_at": job.created_at.isoformat(),
        }
        if job.run_id is not None:
            run = session.get(repo.m.Run, job.run_id)
            if run is not None:
                result["target_id"] = run.target_id
                result["stats"] = run.stats
        return JSONResponse(result)


@app.get("/api/jobs/{job_id}/activity")
async def api_job_activity(
    request: Request, job_id: int, after: int = 0, limit: int = 500
) -> JSONResponse:
    principal = _principal(request)
    after = max(0, after)
    limit = max(1, min(limit, 500))
    with get_db().session() as session:
        job = session.get(repo.m.Job, job_id)
        if job is None or (
            not principal.can("read_all") and job.owner_id != principal.user_id
        ):
            raise HTTPException(status_code=404, detail=f"job {job_id} not found")
        rows = repo.list_job_activity(
            session, job_id, after=after, limit=limit + 1
        )
        has_more = len(rows) > limit
        rows = rows[:limit]
        activities = [dict(row.payload) for row in rows]
        cursor = max(
            [after, *(int(activity.get("sequence") or 0) for activity in activities)]
        )
        return JSONResponse({
            "job_id": job_id,
            "attempts": job.attempts,
            "cursor": cursor,
            "has_more": has_more,
            "activities": activities,
        })


@app.get("/api/targets")
async def api_targets(request: Request, watchlist: bool = False) -> JSONResponse:
    principal = _principal(request)
    with get_db().session() as session:
        rows = repo.list_targets(
            session,
            watchlist_only=watchlist,
            owner_id=principal.user_id,
            include_all=principal.can("read_all"),
        )
        return JSONResponse([
            {
                **_row(target, ("id", "label", "watchlist")),
                "query": target.query,
                "created_at": target.created_at.isoformat(),
            }
            for target in rows
        ])


@app.get("/api/runs")
async def api_runs(request: Request, target_id: int | None = None) -> JSONResponse:
    principal = _principal(request)
    with get_db().session() as session:
        if target_id is not None:
            _can_access_target(session, principal, target_id)
        rows = repo.list_runs(
            session, target_id=target_id, owner_id=principal.user_id,
            include_all=principal.can("read_all")
        )
        return JSONResponse([
            {
                **_row(run, ("id", "target_id", "status")),
                "stats": _compact_run_stats(run.stats),
                "provenance": run.provenance,
                "started_at": run.started_at.isoformat(),
                "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            }
            for run in rows
        ])


@app.get("/api/runs/{run_id}/provenance")
async def api_run_provenance(request: Request, run_id: int) -> JSONResponse:
    principal = _principal(request)
    with get_db().session() as session:
        run = _can_access_run(session, principal, run_id)
        return JSONResponse({"run_id": run_id, "provenance": run.provenance})


@app.get("/api/runs/{run_id}/reasoning")
async def api_run_reasoning(request: Request, run_id: int) -> JSONResponse:
    principal = _principal(request)
    with get_db().session() as session:
        run = _can_access_run(session, principal, run_id)
        return JSONResponse({
            "run_id": run_id,
            "reasoning": (run.stats or {}).get("reasoning"),
        })


@app.get("/api/runs/{run_id}/profile")
async def api_run_profile(request: Request, run_id: int) -> JSONResponse:
    principal = _principal(request)
    with get_db().session() as session:
        run = _can_access_run(session, principal, run_id)
        return JSONResponse({
            "run_id": run_id,
            "profile": (run.stats or {}).get("profile"),
        })


@app.get("/api/runs/{run_id}/observations")
async def api_run_observations(request: Request, run_id: int) -> JSONResponse:
    from .governance import latest_reviews

    with get_db().session() as session:
        principal = _principal(request)
        _can_access_run(session, principal, run_id)
        observations = repo.observations_for_run(session, run_id)
        reviews = latest_reviews(session, run_id=run_id)
        return JSONResponse({
            "run_id": run_id,
            "observations": [
                {
                    **_row(
                        observation,
                        ("id", "source", "category", "label", "url", "verdict",
                         "confidence", "reliability", "reasons", "collector", "origin",
                         "evidence_class", "independence_key", "claim_key", "completeness",
                         "temporal_status"),
                    ),
                    "extractions": observation.extractions or [],
                    "confidence_dimensions": observation.confidence_dimensions,
                    "policy": observation.policy or {},
                    "observed_at": (
                        observation.observed_at.isoformat()
                        if observation.observed_at else None
                    ),
                    "first_seen_at": (
                        observation.first_seen_at.isoformat()
                        if observation.first_seen_at else None
                    ),
                    "last_seen_at": (
                        observation.last_seen_at.isoformat()
                        if observation.last_seen_at else None
                    ),
                    "review": (
                        {
                            **_row(reviews[observation.id], ("id", "decision", "note", "reviewer")),
                            "created_at": reviews[observation.id].created_at.isoformat(),
                        }
                        if observation.id in reviews else None
                    ),
                }
                for observation in observations
            ],
        })


@app.get("/api/runs/{run_id}/contradictions")
async def api_run_contradictions(request: Request, run_id: int) -> JSONResponse:
    with get_db().session() as session:
        _can_access_run(session, _principal(request), run_id)
        rows = repo.contradictions_for_run(session, run_id)
        return JSONResponse({
            "run_id": run_id,
            "contradictions": [
                {
                    **_row(
                        row,
                        ("id", "claim_key", "earlier_observation_id",
                         "later_observation_id", "kind", "severity", "reasons"),
                    ),
                    "created_at": row.created_at.isoformat(),
                }
                for row in rows
            ],
        })


@app.post("/api/observations/{observation_id}/review")
async def api_review_observation(
    request: Request, observation_id: int, payload: ReviewPayload
) -> JSONResponse:
    from .governance import review_observation

    try:
        with get_db().session() as session:
            principal = _principal(request)
            observation = session.get(repo.m.Observation, observation_id)
            if observation is None:
                raise LookupError(f"observation {observation_id} not found")
            _can_access_target(session, principal, observation.target_id, write=True)
            review = review_observation(
                session,
                observation_id,
                payload.decision,
                note=payload.note,
                reviewer=principal.username if SETTINGS.auth_required else payload.reviewer,
                reviewer_user_id=principal.user_id,
            )
            return JSONResponse({
                **_row(review, ("id", "observation_id", "run_id", "target_id",
                                "decision", "note", "reviewer")),
                "created_at": review.created_at.isoformat(),
            })
    except LookupError:
        return JSONResponse({"error": "observation not found"}, status_code=404)


@app.get("/api/reviews")
async def api_reviews(
    request: Request, run_id: int | None = None, target_id: int | None = None
) -> JSONResponse:
    from .governance import review_history

    with get_db().session() as session:
        principal = _principal(request)
        if run_id is not None:
            _can_access_run(session, principal, run_id)
        if target_id is not None:
            _can_access_target(session, principal, target_id)
        reviews = review_history(session, run_id=run_id, target_id=target_id)
        if not principal.can("read_all"):
            allowed = {
                target.id for target in repo.list_targets(
                    session, owner_id=principal.user_id, include_all=False
                )
            }
            reviews = [review for review in reviews if review.target_id in allowed]
        return JSONResponse([
            {
                **_row(review, ("id", "observation_id", "run_id", "target_id",
                               "decision", "note", "reviewer")),
                "created_at": review.created_at.isoformat(),
            }
            for review in reviews
        ])


@app.get("/api/targets/{target_id}/entities")
async def api_entities(request: Request, target_id: int) -> JSONResponse:
    principal = _principal(request)
    with get_db().session() as session:
        _can_access_target(session, principal, target_id)
        entities = repo.list_entities(session, target_id)
        return JSONResponse([
            {
                **_row(entity, ("id", "label", "confidence")),
                "attributes": entity.attributes,
                "flags": entity.flags,
                "breakdown": entity.breakdown,
                "confidence_shadow": (entity.breakdown or {}).get("shadow_total"),
                "sources": sorted({observation.source for observation in entity.observations}),
            }
            for entity in entities
        ])


@app.get("/api/changes")
async def api_changes_all(request: Request, target_id: int | None = None) -> JSONResponse:
    principal = _principal(request)
    with get_db().session() as session:
        if target_id is not None:
            _can_access_target(session, principal, target_id)
        rows = repo.list_changes(
            session, target_id=target_id, owner_id=principal.user_id,
            include_all=principal.can("read_all")
        )
        return JSONResponse([
            {
                **_row(change, ("id", "kind", "source", "label")),
                "target_id": change.target_id,
                "detail": change.detail,
                "created_at": change.created_at.isoformat(),
            }
            for change in rows
        ])


@app.get("/api/targets/{target_id}/changes")
async def api_changes(request: Request, target_id: int) -> JSONResponse:
    return await api_changes_all(request=request, target_id=target_id)


@app.get("/api/runs/{run_id}/graph")
async def api_run_graph(request: Request, run_id: int) -> JSONResponse:
    principal = _principal(request)
    with get_db().session() as session:
        _can_access_run(session, principal, run_id)
        artifacts = repo.list_artifacts(session, run_id)
        edges = repo.list_artifact_edges(session, run_id)
        return JSONResponse({
            "run_id": run_id,
            "nodes": [
                {
                    "id": artifact.id,
                    "type": artifact.type,
                    "value": artifact.value,
                    "depth": artifact.depth,
                    "source_module": artifact.source_module,
                    "confidence": artifact.confidence,
                    "data": artifact.data,
                }
                for artifact in artifacts
            ],
            "edges": [
                {
                    "source": edge.src_artifact_id,
                    "target": edge.dst_artifact_id,
                    "module": edge.module,
                }
                for edge in edges
            ],
        })


@app.get("/api/runs/{run_id}/rules")
async def api_run_rules(request: Request, run_id: int) -> JSONResponse:
    severity = {"high": 3, "medium": 2, "low": 1, "info": 0}
    with get_db().session() as session:
        _can_access_run(session, _principal(request), run_id)
        rows = repo.list_rule_findings(session, run_id)
        items = [
            {
                **_row(row, ("rule_id", "title", "severity", "description", "key")),
                "evidence": row.evidence,
                "detail": row.detail,
            }
            for row in rows
        ]
    items.sort(key=lambda item: -severity.get(item["severity"], 0))
    return JSONResponse({"run_id": run_id, "insights": items})


@app.get("/api/rules")
async def api_rules() -> JSONResponse:
    from .rules import rule_catalogue

    return JSONResponse(rule_catalogue())


@app.get("/api/calibration")
async def api_calibration(request: Request) -> JSONResponse:
    _require(_principal(request), "read_all")
    with get_db().session() as session:
        rows = repo.list_calibration(session, limit=20)
        history = [
            {
                **_row(row, ("id", "n", "positives", "negatives", "brier", "ece",
                              "found_threshold")),
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]
        return JSONResponse({"latest": rows[0].report if rows else None, "history": history})


@app.get("/api/calibration/labels")
async def api_reviewed_calibration_labels(request: Request) -> JSONResponse:
    _require(_principal(request), "read_all")
    from .governance import reviewed_calibration_labels

    with get_db().session() as session:
        labels = reviewed_calibration_labels(session)
    positives = sum(1 for label in labels if label["present"])
    return JSONResponse({
        "labels": labels,
        "n": len(labels),
        "positives": positives,
        "negatives": len(labels) - positives,
    })


@app.get("/api/analytics")
async def api_analytics(request: Request) -> JSONResponse:
    _require(_principal(request), "read_all")
    from . import analytics

    return JSONResponse(analytics.compute(get_db()))


@app.get("/api/sources")
async def api_sources() -> JSONResponse:
    from .sources import CONTRACTS

    with get_db().session() as session:
        states = {source.name: source for source in repo.list_sources(session)}
        checks = repo.latest_source_health_checks(session)
        return JSONResponse([
            {
                "name": module.name,
                "kind": module.kind_label,
                "enabled": module.enabled and (not module.expansion or SETTINGS.expansion_requested) and (
                    states[module.name].enabled if module.name in states else True
                ),
                "reliability": (
                    states[module.name].reliability
                    if module.name in states else module.reliability_prior
                ),
                "successes": states[module.name].successes if module.name in states else 0,
                "failures": states[module.name].failures if module.name in states else 0,
                "breaker_state": (
                    states[module.name].breaker_state if module.name in states else "closed"
                ),
                "contract": CONTRACTS[module.name].as_dict(),
                "expansion": module.expansion,
                "latest_check": (
                    {
                        **_row(checks[module.name], ("canary", "status", "duration_ms", "requests")),
                        "created_at": checks[module.name].created_at.isoformat(),
                    }
                    if module.name in checks else None
                ),
            }
            for module in MODULES
        ])


@app.get("/api/modules")
async def api_modules() -> JSONResponse:
    from .sources import CONTRACTS
    from .adapters.maigret import compatibility as maigret_compatibility

    return JSONResponse([
        {
            "name": module.name,
            "consumes": sorted(kind.value for kind in module.consumes),
            "produces": sorted(kind.value for kind in module.produces),
            "keyless": not module.requires_keys,
            "requires_keys": list(module.requires_keys),
            "passive": module.passive,
            "reliability_prior": module.reliability_prior,
            "enabled": (
                module.enabled
                and (not module.expansion or SETTINGS.expansion_requested)
                and VAULT.has_all(module.requires_keys)
            ),
            "expansion": module.expansion,
            "capabilities": module.declared_capabilities,
            "evidence_policy": module.evidence_policy.model_dump(mode="json"),
            "gated": module.expansion and not SETTINGS.expansion_requested,
            "contract": CONTRACTS[module.name].as_dict(),
            "compatibility": (
                maigret_compatibility(SETTINGS.maigret_executable).as_dict()
                if module.name == "maigret" else None
            ),
        }
        for module in MODULES
    ])


@app.get("/api/keys")
async def api_keys(request: Request) -> JSONResponse:
    _require(_principal(request), "admin")
    VAULT.reload()
    return JSONResponse([
        {**key, "modules": _modules_for_key(key["name"])} for key in VAULT.status()
    ])


@app.post("/api/keys")
async def api_set_key(request: Request, payload: KeyPayload) -> JSONResponse:
    principal = _principal(request)
    _require(principal, "admin")
    if not SETTINGS.allow_key_writes:
        return JSONResponse(
            {"error": "credential writes are disabled; use injected secrets"},
            status_code=403,
        )
    name = payload.name.lower()
    if name not in {key["name"] for key in KNOWN_KEYS}:
        return JSONResponse({"error": f"unknown key '{name}'"}, status_code=400)
    value = payload.value.strip()
    if value:
        VAULT.set(name, value)
    else:
        VAULT.clear(name)
    from .governance import add_audit_event
    with get_db().session() as session:
        add_audit_event(
            session, "credential.updated", "credential", None,
            actor=principal.username, actor_user_id=principal.user_id,
            detail={"name": name, "configured": bool(value)},
        )
    return JSONResponse({
        "name": name,
        "configured": VAULT.has(name),
        "source": VAULT.source(name),
    })


@app.post("/api/targets/{target_id}/export")
async def api_target_export(
    request: Request, target_id: int, payload: ExportPayload
) -> JSONResponse:
    from .governance import add_audit_event, target_export

    try:
        with get_db().session() as session:
            principal = _principal(request)
            _can_access_target(session, principal, target_id)
            exported = target_export(session, target_id, redacted=payload.redacted)
            add_audit_event(
                session,
                "target.exported",
                "target",
                target_id,
                actor=principal.username if SETTINGS.auth_required else payload.actor,
                actor_user_id=principal.user_id,
                detail={"redacted": payload.redacted},
            )
            return JSONResponse(exported)
    except LookupError:
        return JSONResponse({"error": "target not found"}, status_code=404)


@app.delete("/api/targets/{target_id}")
async def api_delete_target(request: Request, target_id: int, payload: DeletePayload) -> JSONResponse:
    from .governance import purge_target

    if not payload.confirm:
        return JSONResponse({"error": "explicit confirmation is required"}, status_code=400)
    try:
        with get_db().session() as session:
            principal = _principal(request)
            _can_access_target(session, principal, target_id, write=True)
            deleted = purge_target(
                session, target_id,
                actor=principal.username if SETTINGS.auth_required else payload.actor,
                actor_user_id=principal.user_id,
            )
            return JSONResponse({"target_id": target_id, "deleted": deleted})
    except LookupError:
        return JSONResponse({"error": "target not found"}, status_code=404)


@app.post("/api/retention")
async def api_retention(request: Request, payload: RetentionPayload) -> JSONResponse:
    principal = _principal(request)
    _require(principal, "admin")
    from .governance import apply_retention

    with get_db().session() as session:
        return JSONResponse(apply_retention(
            session,
            payload.days,
            dry_run=payload.dry_run,
            actor=principal.username if SETTINGS.auth_required else payload.actor,
            actor_user_id=principal.user_id,
        ))


@app.get("/api/audit")
async def api_audit(request: Request, limit: int = 200) -> JSONResponse:
    from sqlalchemy import select

    _require(_principal(request), "admin")
    limit = max(1, min(limit, 1000))
    with get_db().session() as session:
        events = list(session.execute(
            select(repo.m.AuditEvent).order_by(
                repo.m.AuditEvent.created_at.desc(), repo.m.AuditEvent.id.desc()
            ).limit(limit)
        ).scalars())
        return JSONResponse([
            {
                **_row(event, ("id", "action", "actor", "object_type", "object_id", "detail")),
                "created_at": event.created_at.isoformat(),
            }
            for event in events
        ])


async def _readiness() -> tuple[bool, dict[str, Any]]:
    components: dict[str, Any] = {}
    try:
        db = get_db()
        await asyncio.to_thread(db.ping)
        current = await asyncio.to_thread(db.schema_revision)
        head = await asyncio.to_thread(db.migration_head)
        components["database"] = {
            "ready": current == head,
            "revision": current,
            "head": head,
        }
    except Exception:
        components["database"] = {"ready": False}

    if SETTINGS.queue_backend == "arq":
        client = None
        try:
            from redis.asyncio import Redis

            dsn = env_value("RECON_REDIS_DSN", "redis://localhost:6379")
            client = Redis.from_url(dsn or "redis://localhost:6379")
            await asyncio.wait_for(client.ping(), timeout=2.0)
            components["queue"] = {"ready": True, "backend": "arq"}
        except Exception:
            components["queue"] = {"ready": False, "backend": "arq"}
        finally:
            if client is not None:
                await client.aclose()
    else:
        components["queue"] = {"ready": True, "backend": "local"}

    return all(component["ready"] for component in components.values()), components


@app.get("/health/live", include_in_schema=False)
async def health_live() -> JSONResponse:
    return JSONResponse({"status": "alive", "version": __version__})


@app.get("/health/ready", include_in_schema=False)
async def health_ready() -> JSONResponse:
    ready, components = await _readiness()
    return JSONResponse(
        {"status": "ready" if ready else "not_ready", "components": components},
        status_code=200 if ready else 503,
        headers={"Cache-Control": "no-store"},
    )


@app.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> PlainTextResponse:
    if not SETTINGS.metrics_enabled:
        raise HTTPException(status_code=404, detail="not found")
    if SETTINGS.metrics_token:
        supplied = request.headers.get("authorization", "")
        expected = f"Bearer {SETTINGS.metrics_token}"
        if not hmac.compare_digest(supplied, expected):
            return PlainTextResponse("unauthorized\n", status_code=401)
    ready, _components = await _readiness()
    return PlainTextResponse(
        METRICS.render(ready=ready, version=__version__),
        media_type="text/plain; version=0.0.4; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )


app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


def _validate_service_mode() -> None:
    db = get_db()
    if SETTINGS.production_mode:
        if not SETTINGS.remote_mode or not SETTINGS.auth_required:
            raise RuntimeError("production service requires authenticated remote mode")
        if SETTINGS.auto_migrate:
            raise RuntimeError("production service requires RECON_AUTO_MIGRATE=0")
        if not db.dsn.startswith(("postgresql://", "postgresql+")):
            raise RuntimeError("production service requires PostgreSQL")
        if SETTINGS.queue_backend != "arq":
            raise RuntimeError("production service requires RECON_QUEUE_BACKEND=arq")
        if SETTINGS.allow_live_scans:
            raise RuntimeError("production service does not permit live in-request scans")
        if SETTINGS.allow_key_writes:
            raise RuntimeError("production service does not permit dashboard credential writes")
        if SETTINGS.metrics_enabled and (
            not SETTINGS.metrics_token or len(SETTINGS.metrics_token) < 32
        ):
            raise RuntimeError("production metrics require a token of at least 32 characters")
    if SETTINGS.auth_required:
        from .auth import active_admin_count
        from .expansion import require_ready

        require_ready(db, "multi_user")
        with db.session() as session:
            if active_admin_count(session) == 0:
                raise RuntimeError("authenticated mode requires an active administrator account")
    if SETTINGS.remote_mode:
        from .expansion import require_ready

        require_ready(db, "remote_dashboard")
        if SETTINGS.host in {"127.0.0.1", "localhost", "::1"}:
            raise RuntimeError("remote mode requires a non-loopback RECON_HOST")
        if "*" in SETTINGS.allowed_hosts:
            raise RuntimeError("remote mode does not permit wildcard trusted hosts")
        if SETTINGS.production_mode and any(
            host in {"127.0.0.1", "localhost", "testserver", "[::1]"}
            for host in SETTINGS.allowed_hosts
        ):
            raise RuntimeError("production trusted hosts cannot include local development hosts")
        if SETTINGS.tls_termination == "direct":
            cert = Path(SETTINGS.tls_cert_file or "")
            key = Path(SETTINGS.tls_key_file or "")
            if not cert.is_file() or not key.is_file():
                raise RuntimeError(
                    "direct TLS requires readable RECON_TLS_CERT and RECON_TLS_KEY"
                )
        elif "*" in SETTINGS.forwarded_allow_ips:
            raise RuntimeError("proxy TLS requires explicit trusted proxy IPs or networks")


def main() -> None:
    import uvicorn

    _validate_service_mode()
    configure_logging(SETTINGS)
    ssl_options = {}
    if SETTINGS.remote_mode and SETTINGS.tls_termination == "direct":
        ssl_options = {
            "ssl_certfile": SETTINGS.tls_cert_file,
            "ssl_keyfile": SETTINGS.tls_key_file,
        }
    proxy_options = {
        "proxy_headers": SETTINGS.tls_termination == "proxy",
        "forwarded_allow_ips": ",".join(SETTINGS.forwarded_allow_ips),
    }
    uvicorn.run(
        app,
        host=SETTINGS.host,
        port=SETTINGS.port,
        server_header=False,
        access_log=False,
        log_config=None,
        timeout_keep_alive=5,
        **proxy_options,
        **ssl_options,
    )


if __name__ == "__main__":
    main()
