# Expansion maturity gate

Broader source packs, machine-learning identity review, network-exposed
dashboards, and multi-user features are implemented but remain blocked until
`recon maturity` reports `READY`. This is an evidence gate, not a roadmap
estimate, and `RECON_ENABLE_EXPANSION=1` cannot override it.

The automated gate requires:

1. Every enabled module has a complete source contract.
2. The database is at the packaged Alembic head.
3. The latest representative calibration has at least 100 usable samples, at
   least 20 positive and 20 negative samples, ECE at or below 0.10, and a false
   positive rate at or below 0.05.
4. Every enabled network source has a passing designated canary no more than 14
   days old.

Ground truth must be independently verified. Do not duplicate rows, generate
synthetic positives, or label the tool's own verdict as truth to satisfy the
threshold. Investigator decisions can be exported with `recon review-labels`,
but the operator remains responsible for verification and representative
sampling.

Before tagging a release, also complete the manual checks in `RELEASING.md`.
The gate is expected to remain blocked on a new installation until real labels
and explicitly authorized canaries are supplied. Live canaries are never run by
the repository's default scheduled automation.

Once the gate passes, enable only the capability being evaluated and repeat its
specific checks. New expansion sources have their own contracts and canaries.
An identity model must also pass its held-out false-positive and calibration
thresholds. Remote mode additionally requires authentication, a non-loopback
bind, TLS key material, explicit trusted hosts, and at least one active
administrator.
