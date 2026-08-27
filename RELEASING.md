# Releasing

Releases are built by GitHub Actions from an annotated `vX.Y.Z` tag. Do not
upload artifacts built on a workstation. A release publishes checksummed Python
distributions, a Linux AMD64/ARM64 GHCR image, provenance and SBOM attestations,
and a GitHub Release. PyPI receives the exact attested release distributions
through a separate trusted-publishing workflow.

## One-time repository setup

1. Enable GitHub Actions with read/write workflow permissions.
2. Create a protected GitHub environment named `pypi` with required maintainer
   approval and no stored publishing token.
3. Check whether `osint-recon` is available on PyPI. If it is unclaimed,
   configure a pending trusted publisher for owner `gahitchi`, repository
   `osint-recon`, workflow `publish-pypi.yml`, and environment `pypi`. After the
   first upload, confirm that the publisher is attached to the new project.
4. Make the GHCR package public, or configure registry authentication on every
   deployment host. Enable immutable GitHub Releases and immutable GHCR tags
   when those repository and package settings are available.
5. Protect `main`; require CI and CodeQL, review, resolved conversations, and
   linear history. Restrict tag creation for `v*` to maintainers.

Confirm that the PyPI name remains unclaimed immediately before the first
release; package-name availability can change at any time.

## Release checklist

1. Confirm `CHANGELOG.md` contains the intended version and replace
   `Unreleased` in that version's heading with the release date.
2. Set the same version in `pyproject.toml`, `src/recon/__init__.py`, the default
   `RECON_IMAGE_REF`, and the Dockerfile build argument. Refresh `uv.lock`.
3. Back up and upgrade copies of real pre-release SQLite and PostgreSQL
   databases. Record successful recovery point and recovery time tests.
4. Run explicitly authorized designated source canaries once and inspect
   failures rather than retrying until green. Run calibration and the externally
   verified evaluation, then `specter maturity`; high-risk expansion releases
   require `READY`.
5. For expansion releases, verify tenant-isolation and CSRF tests, inspect
   held-out model metrics, test the sanitized source-pack manifest, and start
   remote mode with disposable TLS and explicit trusted hosts.
6. Run the complete local gate:

```bash
uv sync --locked --all-extras
uv run ruff check .
uv run pytest -q
uv run bandit -q -c pyproject.toml -r src scripts
uv export --locked --extra pdf --extra postgres --extra distributed \
  --extra secure --extra ml --no-dev --no-emit-project \
  --format requirements-txt --output-file audit-requirements.txt
uv run pip-audit --no-deps --disable-pip -r audit-requirements.txt
uv build --clear --no-create-gitignore
uv run twine check dist/*.whl dist/*.tar.gz
uv run python scripts/release_check.py --dist-dir dist
uv run python scripts/operational_drill.py
```

7. Restore the latest PostgreSQL backup in an isolated environment, run
   `db-upgrade` and `db-check`, and smoke-test the dashboard, readiness probe,
   worker dispatch, and scheduler.
8. Commit the version, dated changelog, and lockfile together. Review the exact
   commit, then create and push an annotated tag:

```bash
git tag -a vX.Y.Z -m "Specter vX.Y.Z"
git push origin vX.Y.Z
```

9. Wait for the release workflow and the approval-gated PyPI workflow. Verify
   the GitHub Release files, PyPI metadata, container architectures, and
   attestations before announcing the release.
10. Pull the GHCR image by digest into staging, complete a test investigation
    with a non-administrator account, run `operational_drill.py` against staging
    with that digest, then promote the same digest to production.

Never place API keys, canary identities, investigation databases, backups,
reports, model training labels, or raw source-pack data in a release artifact.
