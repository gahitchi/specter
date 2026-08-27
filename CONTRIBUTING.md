# Contributing

Thank you for improving Specter. Contributions should preserve its core
principles: authorized use, bounded collection, evidence provenance, explicit
uncertainty, and fail-closed production behavior.

## Before opening an issue

- Remove credentials, tokens, cookies, personal identifiers, investigation
  evidence, reports, and database contents.
- Use GitHub Security Advisories for vulnerabilities, as described in
  `SECURITY.md`.
- Search existing issues before filing a duplicate.
- For source breakage, identify the source and observed behavior without posting
  a real subject's data.

## Development setup

Python 3.10 through 3.14 and `uv` are supported.

```bash
git clone https://github.com/gahitchi/specter.git
cd specter
uv sync --locked --all-extras
uv run pytest -q
uv run ruff check .
uv run bandit -q -c pyproject.toml -r src scripts
```

Tests must be deterministic and offline by default. Never commit live canary
identities or configure CI to query real people. Network-facing behavior should
use mocked transports or operator-controlled test artifacts.

## Pull requests

- Keep each change focused and explain the user-visible behavior.
- Add tests for bug fixes and behavior changes.
- Update documentation, migrations, source contracts, and the changelog when the
  change affects them.
- Preserve compatibility across SQLite for local use and PostgreSQL for the
  supported production profile.
- Do not weaken request limits, tenant isolation, authentication, provenance, or
  maturity gates to make a test pass.

By contributing, you agree that your contribution is licensed under the MIT
license in this repository and that you will follow `CODE_OF_CONDUCT.md`.
