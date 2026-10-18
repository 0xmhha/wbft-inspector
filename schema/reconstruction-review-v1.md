# Reconstructed review packet, version 1

Format: `wbft-reconstruction-review/1`. One packet contains one reconstructed
processing comparison. The maximum document is 512 KiB with at most 32 nested
levels. Optional fields are omitted; null, duplicate keys, unknown fields and
trailing documents are rejected.

The envelope contains:

- `classification: cross_implementation_candidate` and
  `specification_verdict: not_evaluated`.
- Parent `result_sha256`, linked `core_version`, `execution_version`,
  `comparison_model` and `all_improvements_off: true`.
- Declared `network`, recording `node`, selected `height` completeness and
  issues, and exact `log_run`.
- `source` log/profile/normalizer fingerprints, processing capture identity,
  processing instance, frame run and fingerprint, chain/genesis/binary
  fingerprints, source commit and capture completeness/issues.
- Positive integer `position` for storage pagination, distinct from
  `step.input.ordinal` and `step.input.source.sequence`.
- `step` with the reconstructed input, original source pointers, observed and
  computed projections, issues and difference candidates.

Processing-boundary clocks are not wire arrival times. A derived timer
identity is not an original native journal generation. Projections cover
observable context, own unsigned messages, timer arms and sealed-header
handovers; packet delivery, signatures and application import success are
outside this model. Optional application arguments are SHA-256 metadata,
never block bodies or arbitrary operational error strings.

The reader checks pointer domains: processing boundaries and application
answers refer to `input_observations`, log pointers refer to the declared
log run, and frame pointers refer to a safe frame basename and the declared
frame run. Positive ordinals and instances and nonnegative clocks use canonical
decimal strings; full views support 256 bits. Declared source fingerprints
remain evidence references, not independently authenticated facts.

Validation output has format `wbft-reconstruction-review-validation/1` and
retains the packet and packet checksum. `expected_checksum_verified` is true
only when an independently supplied expected checksum matched. The separate
`parent_result_verified` and `source_truth_verified` fields remain false;
`specification_verdict` remains `not_evaluated`. Structure or checksum success
cannot create a specification PASS.
