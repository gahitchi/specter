# Support policy

`osint-recon` is pre-1.0. Only the latest minor release receives fixes. Security
issues should be reported as described in `SECURITY.md`; ordinary defects should
use GitHub Issues with secrets and subject data removed.

Supported runtimes are Python 3.10 through 3.14 on current Linux runners and
Python 3.12 on current Windows runners. SQLite is the supported local database.
The supported production profile is Linux containers with PostgreSQL,
Redis/arq, Caddy, separate workers, and a separate scheduler as defined in
`compose.production.yaml`. PostgreSQL migrations and the production image are
exercised by CI. PDF output, encrypted exports, and OS keyring storage remain
optional configurations.

Published production images target Linux AMD64 and ARM64. Other container
platforms and custom reverse proxies may work, but are not release-gated.

External sites and APIs are outside the project's control. A source is supported
only while its declared contract, parser tests, and designated canary remain
healthy. A broken or policy-incompatible source may be disabled rather than
worked around.

Database upgrades are supported only through packaged Alembic revisions. Back up
the database before upgrading, and do not skip revisions.
