"""Central configuration. Thresholds here control the precision/recall tradeoff
of the false-positive engine — tune them in one place."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__

_PACKAGE_DIR = Path(__file__).resolve().parent


def env_value(name: str, default: str | None = None) -> str | None:
    """Read an environment value or its Docker/Kubernetes-style *_FILE variant."""
    direct = os.environ.get(name)
    file_name = os.environ.get(f"{name}_FILE")
    if direct is not None and file_name:
        raise ValueError(f"set only one of {name} and {name}_FILE")
    if direct is not None:
        return direct
    if file_name:
        path = Path(file_name)
        if not path.is_file():
            raise ValueError(f"{name}_FILE does not point to a readable file")
        if path.stat().st_size > 65_536:
            raise ValueError(f"{name}_FILE is unexpectedly large")
        return path.read_text(encoding="utf-8").strip()
    return default


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_csv(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = os.environ.get(name)
    if not value:
        return default
    return tuple(item.strip().lower() for item in value.split(",") if item.strip())


def _env_items(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = os.environ.get(name)
    if not value:
        return default
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _production_default(local: bool, production: bool) -> bool:
    return production if os.environ.get("RECON_ENV", "development").lower() == "production" else local


@dataclass(frozen=True)
class Settings:
    # --- Runtime profile ---
    environment: str = field(
        default_factory=lambda: os.environ.get("RECON_ENV", "development").strip().lower()
    )
    auto_migrate: bool = field(
        default_factory=lambda: _env_bool(
            "RECON_AUTO_MIGRATE", _production_default(True, False)
        )
    )

    # --- HTTP ---
    user_agent: str = (
        f"Specter/{__version__} "
        "(+https://github.com/gahitchi/osint-recon; authorized research only)"
    )
    request_timeout: float = 12.0
    max_concurrency: int = 24
    per_host_min_interval: float = 0.5  # seconds between hits to the same host
    max_redirects: int = 5
    respect_robots: bool = True
    max_body_bytes: int = 512_000  # cap body we read/fingerprint

    # --- False-positive verdict thresholds (0..1) ---
    # If real response is at least this similar to the "absent" baseline body,
    # treat it as a soft-404 and reject.
    baseline_similarity_reject: float = 0.92
    # Confidence at/above which we emit FOUND.
    found_confidence: float = 0.75
    # Below found_confidence but at/above this -> UNCERTAIN (shown, flagged).
    uncertain_confidence: float = 0.40
    # When True, corroboration breadth is weighted by *independent source classes*
    # rather than distinct source names (see trust/independence.py). Ships False
    # in Phase 5a (shadow-only); flipped on once calibration validates it.
    confidence_independence: bool = False

    # Random control-probe username: prefix + this many random chars.
    control_probe_len: int = 18
    # Reproducibility: when true, the control-probe username is derived
    # deterministically from probe_seed (+ site), so a given input yields the
    # same baseline and thus the same verdicts across runs. (#8)
    deterministic: bool = bool(__import__("os").environ.get("RECON_DETERMINISTIC"))
    probe_seed: int = 1337

    # --- Collectors enabled by default (full automation) ---
    enabled_collectors: tuple[str, ...] = (
        "username",
        "email",
        "phone",
        "domain",
        "name",
    )

    # Sites/categories excluded by default (auth-walled / ToS-restricted).
    excluded_site_tags: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"instagram", "discord", "facebook", "twitter", "x", "linkedin", "snapchat"}
        )
    )

    # --- Recursive engine (event-driven graph traversal) ---
    # Hard ceilings so recursion is bounded and predictable. A scan stops as soon
    # as any ceiling is hit and reports the stop reason (never runs away).
    max_depth: int = 3            # how many pivots deep the frontier may grow
    max_artifacts: int = 500      # total distinct artifacts admitted to the graph
    max_requests: int = 2000      # total outbound requests, including robots/redirects
    # strict  = only expand artifacts that chain back to a seed (subdomains/IPs of
    #           seed domains, handle pivots of seed identities); external domains
    #           discovered via links are recorded but not expanded.
    # aggressive = follow external pivots too (noisier, wider).
    scope_mode: str = "strict"    # strict | aggressive
    passive_only: bool = True     # never run modules marked passive=False

    # --- Paths ---
    # Point RECON_SITES_FILE at a full WhatsMyName wmn-data.json (600+ sites) to
    # broaden username coverage; the curated seed is the zero-setup default.
    sites_data_file: str = field(
        default_factory=lambda: os.environ.get(
            "RECON_SITES_FILE", str(_PACKAGE_DIR / "data" / "sites.json")
        )
    )
    reports_dir: str = "reports"

    # --- Storage / scale (pluggable; local-first defaults) ---
    storage_dsn: str = "sqlite:///data/recon.db"  # set RECON_DB_DSN to a Postgres URL
    queue_backend: str = field(
        default_factory=lambda: os.environ.get("RECON_QUEUE_BACKEND", "local").lower()
    )  # local | arq
    job_lease_seconds: int = 300
    job_max_attempts: int = 3
    job_retention_days: int = field(
        default_factory=lambda: int(os.environ.get("RECON_JOB_RETENTION_DAYS", "30"))
    )
    cache_ttl_seconds: int = 6 * 3600
    breaker_fail_threshold: int = 4
    breaker_cooldown_seconds: int = 300
    db_pool_size: int = field(
        default_factory=lambda: int(os.environ.get("RECON_DB_POOL_SIZE", "5"))
    )
    db_max_overflow: int = field(
        default_factory=lambda: int(os.environ.get("RECON_DB_MAX_OVERFLOW", "10"))
    )
    db_pool_recycle_seconds: int = field(
        default_factory=lambda: int(os.environ.get("RECON_DB_POOL_RECYCLE", "1800"))
    )

    # --- Correlation / entity resolution thresholds ---
    name_match_threshold: float = 0.92  # Jaro-Winkler (mirrors Specter)
    er_merge_threshold: float = 6.0  # summed match weight -> auto-merge
    er_review_threshold: float = 3.0  # summed match weight -> REVIEW (never silent)

    # --- Server ---
    host: str = field(default_factory=lambda: os.environ.get("RECON_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.environ.get("RECON_PORT", "8000")))
    remote_mode: bool = field(default_factory=lambda: _env_bool("RECON_REMOTE_MODE"))
    auth_required: bool = field(default_factory=lambda: _env_bool("RECON_AUTH_REQUIRED"))
    allowed_hosts: tuple[str, ...] = field(default_factory=lambda: _env_csv(
        "RECON_ALLOWED_HOSTS", ("127.0.0.1", "localhost", "testserver", "[::1]")
    ))
    session_hours: int = field(
        default_factory=lambda: int(os.environ.get("RECON_SESSION_HOURS", "12"))
    )
    expansion_requested: bool = field(
        default_factory=lambda: _env_bool("RECON_ENABLE_EXPANSION")
    )
    tls_cert_file: str | None = field(
        default_factory=lambda: os.environ.get("RECON_TLS_CERT") or None
    )
    tls_key_file: str | None = field(
        default_factory=lambda: os.environ.get("RECON_TLS_KEY") or None
    )
    tls_termination: str = field(
        default_factory=lambda: os.environ.get("RECON_TLS_TERMINATION", "direct").lower()
    )
    forwarded_allow_ips: tuple[str, ...] = field(default_factory=lambda: _env_items(
        "RECON_FORWARDED_ALLOW_IPS", ("127.0.0.1",)
    ))
    max_request_body_bytes: int = field(
        default_factory=lambda: int(os.environ.get("RECON_MAX_REQUEST_BODY_BYTES", "65536"))
    )
    login_attempts_per_minute: int = field(
        default_factory=lambda: int(os.environ.get("RECON_LOGIN_ATTEMPTS_PER_MINUTE", "20"))
    )
    metrics_enabled: bool = field(
        default_factory=lambda: _env_bool("RECON_METRICS_ENABLED", True)
    )
    metrics_token: str | None = field(
        default_factory=lambda: env_value("RECON_METRICS_TOKEN") or None
    )
    allow_live_scans: bool = field(
        default_factory=lambda: _env_bool(
            "RECON_ALLOW_LIVE_SCANS", _production_default(True, False)
        )
    )
    allow_key_writes: bool = field(
        default_factory=lambda: _env_bool(
            "RECON_ALLOW_KEY_WRITES", _production_default(True, False)
        )
    )
    log_format: str = field(
        default_factory=lambda: os.environ.get(
            "RECON_LOG_FORMAT",
            "json" if os.environ.get("RECON_ENV", "development").lower() == "production" else "text",
        ).lower()
    )
    log_level: str = field(
        default_factory=lambda: os.environ.get("RECON_LOG_LEVEL", "INFO").upper()
    )
    ml_model_file: str | None = field(
        default_factory=lambda: os.environ.get("RECON_ML_MODEL") or None
    )

    def __post_init__(self) -> None:
        if self.environment not in {"development", "test", "production"}:
            raise ValueError("RECON_ENV must be development, test, or production")
        if self.scope_mode not in {"strict", "aggressive"}:
            raise ValueError("scope_mode must be 'strict' or 'aggressive'")
        if self.queue_backend not in {"local", "arq"}:
            raise ValueError("queue_backend must be 'local' or 'arq'")
        positive = {
            "request_timeout": self.request_timeout,
            "max_concurrency": self.max_concurrency,
            "max_redirects": self.max_redirects,
            "max_body_bytes": self.max_body_bytes,
            "max_artifacts": self.max_artifacts,
            "max_requests": self.max_requests,
            "job_lease_seconds": self.job_lease_seconds,
            "job_max_attempts": self.job_max_attempts,
            "job_retention_days": self.job_retention_days,
            "port": self.port,
            "session_hours": self.session_hours,
            "db_pool_size": self.db_pool_size,
            "db_pool_recycle_seconds": self.db_pool_recycle_seconds,
            "max_request_body_bytes": self.max_request_body_bytes,
            "login_attempts_per_minute": self.login_attempts_per_minute,
        }
        invalid = [name for name, value in positive.items() if value <= 0]
        if invalid:
            raise ValueError(f"settings must be positive: {', '.join(invalid)}")
        if self.max_depth < 0 or self.per_host_min_interval < 0:
            raise ValueError("max_depth and per_host_min_interval cannot be negative")
        for name in ("baseline_similarity_reject", "found_confidence",
                     "uncertain_confidence"):
            value = getattr(self, name)
            if not 0 <= value <= 1:
                raise ValueError(f"{name} must be between 0 and 1")
        if self.uncertain_confidence > self.found_confidence:
            raise ValueError("uncertain_confidence cannot exceed found_confidence")
        if self.remote_mode and not self.auth_required:
            raise ValueError("RECON_REMOTE_MODE requires RECON_AUTH_REQUIRED=1")
        if not self.allowed_hosts:
            raise ValueError("allowed_hosts cannot be empty")
        if self.db_max_overflow < 0:
            raise ValueError("db_max_overflow cannot be negative")
        if self.tls_termination not in {"direct", "proxy"}:
            raise ValueError("RECON_TLS_TERMINATION must be direct or proxy")
        if self.tls_termination == "proxy" and not self.forwarded_allow_ips:
            raise ValueError("proxy TLS termination requires RECON_FORWARDED_ALLOW_IPS")
        if self.log_format not in {"text", "json"}:
            raise ValueError("RECON_LOG_FORMAT must be text or json")

    @property
    def production_mode(self) -> bool:
        return self.environment == "production"


SETTINGS = Settings()
