# Expansion maturity gate

Broader source packs, machine-learning identity review, network-exposed
dashboards, and multi-user features are implemented but remain blocked until
`specter maturity` reports `READY`. This is an evidence gate, not a roadmap
estimate, and `RECON_ENABLE_EXPANSION=1` cannot override it.

The automated gate requires:

1. Every enabled module has a complete source contract.
2. The database is at the packaged Alembic head.
3. The latest representative calibration has at least 100 usable samples, at
   least 20 positive and 20 negative samples, ECE at or below 0.10, and a false
   positive rate at or below 0.01.
4. The latest evaluation uses independently verified cases from at least 25
   distinct subjects, meets the minimum category and phone-case coverage, and
   passes its verdict, profile, action, stop-policy, precision, and recall
   thresholds, including at least 0.99 precision and a false-positive rate at
   or below 0.01.
5. Every enabled network source has a passing designated canary no more than 14
   days old.

Ground truth must be independently and blindly verified. Do not duplicate rows,
generate synthetic positives, select only easy cases, or label the tool's own
verdict as truth to satisfy the threshold. Use the private review-set workflow
in **Advanced > Confidence quality** or `specter evaluation-kit`; its reviewer
sheet deliberately omits Specter's decisions and scores. Investigator decisions
can be exported with `specter review-labels`, but they are calibration candidates,
not independent evaluation truth.

When no outside reviewer or additional subjects are available, use **Private
self-check** with one shared person label for all clues belonging to the same
identity. This operator pilot can reveal defects and establish a personal
baseline, but its `operator_pilot` provenance can never satisfy the expansion
gate.

Run `specter evaluate --dataset reviewed-cases.json --require-ready` to persist
the evaluation. The packaged snapshot file proves only that the evaluator works;
it is permanently marked as a functional fixture and cannot satisfy this gate.
Frozen snapshots evaluate interpretation and decision behavior. They do not
prove that a public source is reachable today; designated canaries cover that
separate question. The complete protocol is in `EVALUATION.md`.

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
