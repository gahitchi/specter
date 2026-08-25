# Extending Specter

Specter accepts three extension shapes. Each has a different trust boundary.

## Native modules

A native module declares a versioned execution contract through `Module`:

- consumed and produced artifact types;
- passive or active interaction;
- estimated request cost used by the information-gain planner;
- capabilities and required keys;
- expansion-gate status;
- evidence policy, including candidate-only and corroboration requirements.

It also needs a `SourceContract` describing the operator, data sent, rate
policy, evidence returned, and applicable terms. Network modules need an
operator-controlled canary. Findings should carry direct origin, extraction,
temporal, and completeness data. Search results and external-tool output are
candidates until the underlying page or record is verified directly.

`validate_contracts()` is the machine-readable conformance gate. A new module
must include offline replay/parser tests, blocked and malformed response tests,
budget tests, and at least one false-positive case before registration.

## External tools

External processes use `AdapterManifest` and `ExternalObservation` version 1.0.
Candidate-only adapters cannot confirm an identity or create automatic pivots.
The conformance checker rejects undeclared artifact types, missing source
independence, unsafe permissions, and network adapters that do not disclose the
data sent.

## Data-only source packs

Username source packs contain no executable code. The installer accepts only
bounded, credential-free public HTTPS templates, rejects local-network targets,
deduplicates entries, and writes a content-addressed manifest. A source pack
remains disabled until the maturity gate passes.

Do not add a source solely to increase source count. A source should contribute
a distinct evidence class, improve measured coverage on independently reviewed
cases, and have a sustainable interaction and maintenance policy.
