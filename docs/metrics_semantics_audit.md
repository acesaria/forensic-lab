# Metrics Semantics Audit

Run inspected:
`shared/experiments/ubuntu-22.04_userland_father_ldpreload_20260629-181530`

This audit checks whether low Father_LDPRELOAD candidate precision after clean
baseline comparison is a metric formula bug or a consequence of raw
candidate-stream semantics.

## Conclusion

The current metrics are not formula-buggy. They are semantically raw.

`candidate_diagnostics` intentionally scores the full `DetectionClaim` stream
after GT-aware matching. It includes unmatched candidates even when baseline
metadata marks them `present_in_baseline` or when baseline downgraded their
confidence. That is useful for measuring detector noise, but it should not be
read as actionable-candidate precision.

Do not redefine `candidate_diagnostics`. Add a separately named diagnostic if
the CLI/report should show a baseline-adjusted view.

Recommended new metric name:
`baseline_adjusted_candidate_diagnostics`

Recommended policy:
when baseline comparison is available, exclude candidates with
`entity.baseline.status == present_in_baseline`; retain
`new_vs_baseline`, `changed_vs_baseline`, and `unknown_baseline_status`.

This keeps the raw detector-noise metric intact and adds a clearer
post-baseline/actionable candidate diagnostic.

## Current Formulas

### `candidate_diagnostics`

Location: `matcher/engine.py::compute_metrics`.

Inputs:

- `candidates`: every built candidate from `DetectionClaim` records.
- `matches`: GT-aware match results from `_match`.

Formula:

- TP = count of `MatchResult.relation == "tp"`
- FP = count of `MatchResult.relation == "fp"`
- FN = count of `MatchResult.relation == "fn"`
- precision = TP / (TP + FP)
- recall = TP / (TP + FN)
- F1 = harmonic mean of precision and recall

Important semantics:

- instance-level TPs and class-only/support TPs both count as candidate TP.
- unmatched candidates count as FP.
- baseline-present candidates are not excluded.
- confidence-downgraded candidates are not excluded.
- timeline-only candidates are not excluded.
- support-only/class matches are not separated here.

This is a raw candidate-stream diagnostic.

### `reconstruction_summary`

Location: `matcher/engine.py::_reconstruction_summary`.

Inputs:

- expectations from `artifact_expectations.jsonl`
- match results

Formula:

- `strong_instance_matched_expected`: distinct expected artifact IDs with
  `relation=tp` and `match_level=instance`.
- `class_only_supported_expected`: distinct expected artifact IDs with
  `relation=tp` and `match_level=class`.
- `missed_expected`: expected total minus strong-or-class supported total.
- `strong_instance_recall`: strong instance matches / expected total.
- `class_support_coverage`: class-only support / expected total.
- `strong_or_supported_coverage`: strong-or-class supported / expected total.
- `critical_strong_instance_recall`: strong instance matches over critical
  expected artifacts.

This is the thesis-relevant reconstruction layer. It is not changed by whether
candidate diagnostics are raw or baseline-adjusted.

### `baseline_comparison`

Location: `matcher/engine.py::_baseline_comparison_summary`.

Inputs:

- `candidate.entity["baseline"]` metadata attached by baseline-aware detection.

Formula:

- `available`: true if candidate baseline metadata exists.
- `baseline_input`: identity from the first candidate baseline row.
- `baseline_path_count`, `compromised_path_count`, and `status_counts`: copied
  from the comparison metadata.
- `candidate_status_counts`: count of candidate baseline statuses.
- `candidate_downgrades`: count of candidates with
  `filter_action == "confidence_downgraded"`.
- `candidate_suppressions`: count of candidates with
  `filter_action == "suppressed"`.

This is support/triage metadata. It does not infer maliciousness and does not
change matcher formulas.

### `strict_candidate_stream_precision`

Location: `matcher/engine.py::compute_metrics`, as
`final_reconstruction["precision"]`.

Formula:

- strong TP = instance-level TP count.
- FP = unmatched candidates + class-only/support matches.
- FN = expected artifacts not covered by strong instance matches.
- precision = strong TP / (strong TP + FP).

This is intentionally strict and still uses the candidate stream denominator.
It is not a pure final reconstruction precision metric and should not be a
headline thesis metric.

### `noise_reduction`

Location: `matcher/engine.py::_noise_reduction`.

Formula:

- raw findings = number of `ToolFinding` records.
- candidate claims = number of built candidates.
- strong instance matches = instance-level TP count.
- raw-to-candidate reduction = 1 - candidate claims / raw findings.
- raw-to-strong reconstruction reduction = 1 - strong instance matches / raw
  findings.

This is count reduction only. It is explicitly not baseline-aware.

## Current Father Numbers

| metric | value |
| --- | ---: |
| DetectionClaim count | 259 |
| candidate TP | 10 |
| candidate FP | 249 |
| candidate FN | 0 |
| candidate precision | 0.0386 |
| candidate recall | 1.0000 |
| candidate F1 | 0.0743 |
| strong instance matched expected artifacts | 7 |
| class-only supported expected artifacts | 3 |
| missed expected artifacts | 0 |
| strong instance recall | 0.7000 |
| strict candidate-stream precision | 0.0270 |
| raw findings | 8696 |
| raw-to-candidate reduction | 0.9702 |
| raw-to-strong-reconstruction reduction | 0.9992 |

Baseline summary:

| baseline field | value |
| --- | ---: |
| baseline available | true |
| baseline input | lab-ubuntu-22.04:baseline |
| baseline path count | 67262 |
| compromised path count | 686 |
| candidate new_vs_baseline | 126 |
| candidate present_in_baseline | 127 |
| candidate unknown_baseline_status | 6 |
| candidate downgrades | 116 |
| candidate suppressions | 0 |

## Alternative Baseline-Adjusted Diagnostics

These numbers were computed by rerunning the matcher over filtered
`DetectionClaim` sets in `/tmp/forensic-lab-metrics-semantics-audit`. They are
diagnostic alternatives only. No detector rules, matcher formulas, baseline
cache, or scenario expectations were changed.

| diagnostic variant | claims input | TP | FP | FN | precision | recall | F1 | strong | class support | missed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| raw candidate diagnostics | 259 | 10 | 249 | 0 | 0.0386 | 1.0000 | 0.0743 | 7 | 3 | 0 |
| exclude present_in_baseline claims | 132 | 10 | 122 | 0 | 0.0758 | 1.0000 | 0.1408 | 7 | 3 | 0 |
| exclude confidence_downgraded claims | 143 | 10 | 133 | 0 | 0.0699 | 1.0000 | 0.1307 | 7 | 3 | 0 |
| exclude timeline-only present_in_baseline claims | 143 | 10 | 133 | 0 | 0.0699 | 1.0000 | 0.1307 | 7 | 3 | 0 |
| only new_vs_baseline + unknown_baseline_status | 132 | 10 | 122 | 0 | 0.0758 | 1.0000 | 0.1408 | 7 | 3 | 0 |
| path-dedup raw candidate stream | 160 | 10 | 150 | 0 | 0.0625 | 1.0000 | 0.1176 | 7 | 3 | 0 |
| path-dedup non-present baseline claims | 57 | 10 | 47 | 0 | 0.1754 | 1.0000 | 0.2985 | 7 | 3 | 0 |
| path-dedup new+unknown claims | 57 | 10 | 47 | 0 | 0.1754 | 1.0000 | 0.2985 | 7 | 3 | 0 |

Observations:

- Excluding `present_in_baseline` claims roughly doubles candidate precision
  from 0.0386 to 0.0758.
- Excluding only confidence-downgraded claims gives 0.0699 precision.
- In this run, confidence-downgraded claims and timeline-only
  present-in-baseline claims are the same 116-claim set.
- Path deduplication has a larger effect, but it changes the counted unit from
  claim/event to path-like candidate group. That should be a separate future
  diagnostic, not a silent replacement.
- The strong reconstruction summary remains 7 strong, 3 class support, 0 missed
  in every variant above.

## Should Existing `candidate_diagnostics` Exclude Baseline-Present Claims?

No.

For raw candidate-stream precision, baseline-present/downgraded claims should
stay in `candidate_diagnostics`. That metric answers: "How noisy was the raw
detector candidate stream?" Under that interpretation, counting all
`DetectionClaim` records is correct.

For actionable candidate precision, baseline-present/downgraded claims should
not be treated the same as new/unknown candidates. That is a different metric.
It should be added with a different name and policy, not substituted into the
existing raw diagnostic.

## Recommendation

Choose option B: add a separate baseline-adjusted/actionable diagnostic metric.

Recommended emitted key:

```text
baseline_adjusted_candidate_diagnostics
```

Recommended report label:

```text
baseline-adjusted candidate diagnostics
```

Recommended fields:

- `description`
- `policy`
- `tp`
- `fp`
- `fn`
- `precision`
- `recall`
- `f1`
- `candidate_count`
- `excluded_present_in_baseline`
- `excluded_confidence_downgraded`
- `baseline_available`

Recommended policy text:

```text
Excludes candidates marked present_in_baseline when a verified baseline is
available; retains new_vs_baseline, changed_vs_baseline, and
unknown_baseline_status candidates. This is an actionable candidate diagnostic,
not a final reconstruction metric.
```

Do not add path deduplication in the same patch. It is useful, but it changes
the diagnostic unit from claim to path-like group and should be reviewed
separately.

## Exact Next Implementation Patch

Small additive matcher/report patch:

1. Keep `candidate_diagnostics` unchanged.
2. In `run_matcher`, after building all candidates, build a filtered candidate
   set excluding `present_in_baseline` when baseline metadata is available.
3. Run `_match` on that filtered candidate set using the same `time_window_s`.
4. Add `baseline_adjusted_candidate_diagnostics` to `metrics.json`.
5. Add one concise section to `score_report.md` and one optional CLI line after
   raw candidate diagnostics.
6. Add focused matcher tests that prove:
   - raw `candidate_diagnostics` still includes baseline-present candidates;
   - `baseline_adjusted_candidate_diagnostics` excludes them;
   - `reconstruction_summary` is unchanged by the added diagnostic;
   - the metric is clearly labeled as diagnostic, not final reconstruction.

This patch should not change detector rules, matcher reconstruction formulas,
scenario expectations, baseline cache behavior, or generated cached artifacts.

## Deferred Options

- Do not change existing `candidate_diagnostics` formula.
- Do not introduce a `FinalClaim` layer for this issue.
- Do not make baseline status alone a maliciousness verdict.
- Defer path-deduplicated candidate diagnostics until after broad filesystem
  rule cleanup.
- Defer rule tuning (`userland_persistence`, `ld_preload_configuration`,
  `suspicious_temp_path`) to a separate detector-rule PR.
