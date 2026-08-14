# Security policy

## Supported versions

Only the latest published minor release receives security fixes while the
project is pre-1.0. Older releases and untagged development snapshots are not
supported deployment targets.

| Version | Supported |
| --- | --- |
| Latest 0.x minor | Yes |
| Older 0.x minors | No |

Please report vulnerabilities privately through GitHub's **Security advisories**
tab for this repository. Include the affected version or commit, reproduction
steps, impact, and any suggested remediation. Do not include live credentials or
personal investigation data.

Do not open a public issue until a fix is available or the maintainer confirms
that disclosure is appropriate. Reports are acknowledged and handled on a
best-effort basis; this volunteer project does not promise a response SLA.

The dashboard binds to loopback by default and rejects untrusted Host, Origin,
and cross-site browser requests. Gated remote mode requires direct TLS or an
explicitly trusted TLS proxy, an
explicit trusted-host list, Argon2id-protected accounts, server-side opaque
sessions, SameSite/HttpOnly/Secure cookies, CSRF tokens, roles, and target
ownership checks. It refuses to start remotely when the maturity gate, TLS
material, trusted hosts, or administrator bootstrap is missing. API keys use
environment variables, the optional operating-system
keyring, or a local plaintext file with restrictive permissions. The keyring
backend is preferable on shared machines.

The supported production profile additionally requires PostgreSQL, Redis/arq,
one-shot migrations, secret files, authenticated metrics, bounded request
bodies, and worker-dispatched scans. Only the TLS proxy publishes host ports.
See `PRODUCTION.md` for the supported topology and incident procedures.

OSINT collection is not offline: scans send supplied identifiers to the public
sources selected by the enabled modules. Reports, databases, caches, and fetched
datasets remain local unless the operator moves or publishes them.

Target exports are redacted by default and can be encrypted with the optional
secure dependency. Retention and subject deletion are explicit actions with an
audit trail. Back up a database before applying schema migrations or deletion.

Identity models are JSON numeric artifacts rather than executable pickle files.
They can only add a review suggestion to ambiguous pairs and never authorize an
automatic merge. Training requires independently verified labels and held-out
false-positive and calibration checks.
