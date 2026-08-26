# syntax=docker/dockerfile:1.7

FROM python:3.12-slim-bookworm@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134 AS builder

COPY --from=ghcr.io/astral-sh/uv:0.11.16@sha256:440fd6477af86a2f1b38080c539f1672cd22acb1b1a47e321dba5158ab08864d /uv /uvx /bin/
WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src

RUN uv sync --frozen --no-dev --no-editable \
    --extra postgres --extra distributed --extra secure --extra ml


FROM python:3.12-slim-bookworm@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134 AS runtime

ARG VERSION=0.11.0
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="Specter" \
      org.opencontainers.image.description="Evidence-aware OSINT research framework for authorized investigations" \
      org.opencontainers.image.source="https://github.com/gahitchi/specter" \
      org.opencontainers.image.documentation="https://github.com/gahitchi/specter/blob/main/PRODUCTION.md" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="MIT"

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RECON_ENV=production \
    RECON_AUTO_MIGRATE=0

RUN groupadd --gid 10001 recon \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin recon \
    && mkdir -p /app /data /reports \
    && chown -R recon:recon /app /data /reports

WORKDIR /app
COPY --from=builder --chown=recon:recon /app/.venv /app/.venv

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3)" || exit 1

ENTRYPOINT ["recon"]
CMD ["serve"]
