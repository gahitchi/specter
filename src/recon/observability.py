"""Low-cardinality metrics and privacy-conscious structured logging."""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from collections import Counter
from typing import Any

from .config import Settings


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        for name in ("request_id", "method", "path", "status", "duration_ms"):
            value = getattr(record, name, None)
            if value is not None:
                payload[name] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)


def configure_logging(settings: Settings) -> None:
    level = getattr(logging, settings.log_level, logging.INFO)
    formatter: logging.Formatter
    if settings.log_format == "json":
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"
        )
    for name in ("recon", "uvicorn", "uvicorn.error"):
        logger = logging.getLogger(name)
        if getattr(logger, "_recon_configured", False):
            continue
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(formatter)
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
        logger._recon_configured = True  # type: ignore[attr-defined]
    logging.getLogger("uvicorn.access").disabled = True


class RequestMetrics:
    _buckets = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

    def __init__(self) -> None:
        self.started_at = time.time()
        self._lock = threading.Lock()
        self._requests: Counter[tuple[str, str]] = Counter()
        self._duration_count = 0
        self._duration_sum = 0.0
        self._duration_buckets: Counter[float] = Counter()

    def record(self, method: str, status: int, duration: float) -> None:
        with self._lock:
            self._requests[(method.upper(), str(status))] += 1
            self._duration_count += 1
            self._duration_sum += duration
            for bucket in self._buckets:
                if duration <= bucket:
                    self._duration_buckets[bucket] += 1

    def render(self, *, ready: bool, version: str) -> str:
        with self._lock:
            requests = dict(self._requests)
            count = self._duration_count
            total = self._duration_sum
            buckets = dict(self._duration_buckets)
        lines = [
            "# HELP recon_build_info Build information.",
            "# TYPE recon_build_info gauge",
            f'recon_build_info{{version="{version}"}} 1',
            "# HELP recon_process_start_time_seconds Process start time.",
            "# TYPE recon_process_start_time_seconds gauge",
            f"recon_process_start_time_seconds {self.started_at:.3f}",
            "# HELP recon_ready Whether the service is ready.",
            "# TYPE recon_ready gauge",
            f"recon_ready {1 if ready else 0}",
            "# HELP recon_http_requests_total HTTP requests by method and status.",
            "# TYPE recon_http_requests_total counter",
        ]
        for (method, status), value in sorted(requests.items()):
            lines.append(
                f'recon_http_requests_total{{method="{method}",status="{status}"}} {value}'
            )
        lines.extend([
            "# HELP recon_http_request_duration_seconds HTTP request duration.",
            "# TYPE recon_http_request_duration_seconds histogram",
        ])
        for bucket in self._buckets:
            lines.append(
                f'recon_http_request_duration_seconds_bucket{{le="{bucket}"}} '
                f"{buckets.get(bucket, 0)}"
            )
        lines.extend([
            f'recon_http_request_duration_seconds_bucket{{le="+Inf"}} {count}',
            f"recon_http_request_duration_seconds_sum {total:.6f}",
            f"recon_http_request_duration_seconds_count {count}",
        ])
        return "\n".join(lines) + "\n"


METRICS = RequestMetrics()
