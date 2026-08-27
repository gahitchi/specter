# Quality evaluation protocol

Specter may claim measured quality only from authorized, representative cases
that were judged independently without first revealing Specter's verdicts. The
packaged functional fixture tests the evaluator; it is not accuracy evidence.

Specter also supports a private operator pilot. This lets a developer check the
tool against their own information when no independent reviewer or additional
subjects are available. Pilot results are useful for finding defects, but they
are always marked non-independent and can never make the release gate `READY`.

## What the evaluation measures

The evaluation freezes the findings from a completed investigation, then
measures how those findings compare with reviewed ground truth and how the
current profile, planner, and stop policy interpret them. Release evidence uses
independent ground truth; operator pilots use the operator's own checks. This
makes the result reproducible.

It does not rerun collection. Public pages and search results change over time,
so live reruns are a separate source-health question covered by designated
canaries and staging drills.

## Sampling plan

Write the sampling rule before seeing results. Include ordinary successes,
ordinary absences, ambiguous pages, changed or recycled identifiers, blocked
sources, and cases where different people share similar clues. Do not select
cases because Specter performed well on them.

The readiness gate requires at least:

- 50 distinct cases;
- 25 distinct subjects;
- 15 positive and 15 negative reviewed claims;
- 3 starting-clue categories;
- 10 phone-led cases.

Use only identities and assets covered by one of these bases:

- the evaluator's own identity;
- documented authorization from the subject;
- a controlled test account or asset;
- a public organization asset, such as an official business number or domain.

Do not commit review kits, completed sheets, evaluation datasets, reports, or
subject identifiers to Git. The desktop stores them in Specter's local data
directory.

## Private operator pilot

Choose **Private self-check** when you only have your own authorized data. Use
the same non-identifying person label for every related investigation. For
example, a phone number, two email addresses, and several usernames belonging
to one person should all use `me`; they are multiple clues and may create
multiple cases, but they remain one subject.

The self-check sheet hides Specter's recorded verdicts and confidence scores to
reduce confirmation bias. Because the operator may already have seen the run,
the result is not described as blind or independent. Its dataset provenance is
`operator_pilot`, and the readiness gate remains `NEEDS_EVIDENCE` regardless of
the measured scores.

## Blind review

1. Complete an authorized investigation.
2. In **Advanced > Confidence quality**, open **Quality review set**, choose
   **Independent release evaluation**, and add the finished run with a
   non-identifying case label.
3. Download the blind review CSV. It contains the subject, source, claim, and
   evidence location, but not Specter's verdict, confidence, or reasons.
4. Give the CSV to a reviewer who did not develop Specter and has not seen its
   decisions for those cases.
5. The reviewer independently verifies every claim and fills all repeated case
   fields consistently. Use `none` when no planner action is required.
6. Import the completed CSV. Specter rejects changed claims, missing decisions,
   future review dates, unknown actions, mismatched authorization, and reviews
   that are not declared independent.

The reviewer identifier may be a stable pseudonym. Keep supporting evidence and
authorization records outside the dataset, under the operator's access and
retention policy.

## Interpretation

`READY` means the latest reviewed snapshot meets the documented sample and
performance thresholds, including at least 99% precision and at most a 1%
false-positive rate. With the minimum negative sample, one false positive is
enough to fail the gate. It does not mean every conclusion is correct, every
source is available, or the tool can identify a person from weak evidence.

Publish aggregate metrics, dataset version, review protocol version, collection
window, and known limitations. Do not publish subject-level rows. Re-evaluate
after material changes to collectors, evidence policy, profile synthesis,
reasoning, or source coverage.
