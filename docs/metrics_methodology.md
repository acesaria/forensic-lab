# Metrics Methodology Review

This document reviews current metric semantics in the canonical/declarative
pipeline. It is intentionally critical: the current metrics are useful, but not
all of them are final thesis-quality definitions.

## Current Matching Outcomes

```mermaid
flowchart TD
    A[DetectionClaim candidate] --> B{GT-aware matcher}
    B --> C[Strong instance match]
    B --> D[Class-only/support match]
    B --> E[Unmatched candidate]
    F[Expected artifact] --> B
    C --> G[Counts toward final strong reconstruction]
    D --> H[Context only, not strong reconstruction]
    E --> I[Candidate noise]
```

For the current Father validation:

| metric | value |
|---|---:|
| raw `ToolFinding` records | 7608 |
| `DetectionClaim` records | 255 |
| candidate TP | 10 |
| candidate FP | 245 |
| candidate FN | 0 |
| candidate precision | 0.0392 |
| candidate recall | 1.0000 |
| strong instance matches | 7 |
| class-only/support matches | 3 |
| final precision | 0.0275 |
| final recall | 0.7000 |
| final F1 | 0.0528 |

## Candidate-Level Precision and Recall

Current location: `metrics.json` keys `micro` and `candidate_diagnostics`.

Formula:

- precision = candidate TP / (candidate TP + unmatched candidates)
- recall = candidate TP / (candidate TP + missed expected artifacts)

Important caveat: candidate TP currently includes both strong instance matches
and class-only/support matches.

This metric is useful for detector-layer diagnostics. It is not a final thesis
reconstruction quality metric because `DetectionClaim` is candidate/supporting
evidence, not a final result.

For Father:

- precision = 10 / (10 + 245) = 0.0392
- recall = 10 / (10 + 0) = 1.0000

The high recall means every expected artifact received at least some candidate
match. It does not mean every artifact was concretely reconstructed.

## Final Reconstruction Metrics

Current location: `metrics.json` key `final_reconstruction`.

Current formula:

- strong TP = instance-level matches
- support = class-only matches
- FP = unmatched candidates + class-only/support matches
- FN = expected artifacts not covered by strong instance matches
- precision = strong TP / (strong TP + FP)
- recall = strong TP / (strong TP + FN)

For Father:

- strong TP = 7
- class-only/support = 3
- unmatched candidates = 245
- FP = 245 + 3 = 248
- FN = 10 - 7 = 3
- precision = 7 / (7 + 248) = 0.0275
- recall = 7 / (7 + 3) = 0.7000

This is conservative and correctly prevents class-only support from inflating
headline reconstruction quality.

Methodological risk: the name `final precision` is still debatable because
unmatched candidate claims remain in the denominator. If final reconstruction is
defined as only the selected matched reconstruction set, then unmatched
candidates are detector noise rather than final reconstruction claims. In that
interpretation, this metric is closer to "strong-instance precision over the
candidate stream" than pure final reconstruction precision.

Recommendation for later cleanup: either rename the metric to make the
denominator explicit or define a persisted final reconstruction set and compute
precision over that set. Do not change the formula without a written thesis
definition.

## Evidence Coverage

No pinned `evidence_coverage` key is currently emitted.

Closest current fields:

- `reconstruction.class_level_recall`: class-level coverage, currently 10/10.
- `reconstruction.instance_only_recall`: strong instance coverage, currently
  7/10.
- `final_reconstruction.recall`: same strong-instance recall, currently 0.7000.
- `critical_recall`: candidate-level recall over critical expected artifacts,
  currently 5/5.

Methodological assessment:

- Strong-instance coverage is defensible as "expected artifacts reconstructed at
  concrete instance level."
- Class-level coverage is useful as context, but too weak for headline claims.
- Critical recall is useful but currently candidate-level; it can include
  class-only support.

Recommended later implementation: add an explicit `evidence_coverage` metric
with separate `strong_instance`, `class_support`, and `critical_strong_instance`
fields.

## Source Coverage

No pinned `source_coverage` key is currently emitted.

Closest current fields:

- `source_breakdown`: raw `ToolFinding` counts by source.
- `per_source`: candidate-level precision/recall/F1 grouped by source.
- report sections showing raw counts and claim counts by source.

For Father, `source_breakdown` is:

| source | raw findings |
|---|---:|
| disk | 32 |
| memory | 4112 |
| timeline | 3464 |
| log | 0 |
| unknown | 0 |

Methodological assessment:

- Raw source availability is defensible.
- Per-source candidate PRF is diagnostic, but can be misleading because
  expectations can be eligible for multiple sources and one matched candidate
  can be counted in more than one source perspective.
- A thesis source coverage metric should distinguish "source was available",
  "source produced candidates", and "source contributed strong instance
  reconstruction."

Recommended later implementation: define source coverage over matched
expectations and linked `source_findings`, not over raw detector output alone.

## Noise Reduction Ratio

No pinned `noise_reduction_ratio` key is currently emitted.

A simple diagnostic value is derivable:

- raw findings = 7608
- candidate claims = 255
- reduction = 1 - (255 / 7608) = 0.9665

Methodological assessment:

This number is useful but incomplete. It measures reduction from broad raw
evidence to candidate evidence. It does not measure reduction after baseline
comparison because baseline-aware filtering is not currently implemented in the
canonical path.

Recommended later implementation: report multiple reduction stages:

- raw findings -> candidate claims
- candidate claims -> matched candidates
- raw findings -> strong reconstruction evidence
- later, baseline-filtered findings -> candidate claims

## Pipeline Runtime Seconds

No pinned `pipeline_runtime_seconds` key is currently emitted by the canonical
matcher metrics.

The acquisition manifest does contain acquisition timings:

- memory acquisition seconds: 2.4131500720977783
- disk acquisition seconds: 15.461720705032349

Those are not the same as full pipeline runtime. They exclude at least detector
and matcher runtime, and may not fully represent extraction/runtime cost.

Methodological assessment:

Do not infer pipeline runtime from file timestamps. The current code should not
claim a full post-mortem pipeline runtime metric.

Recommended later implementation: add a small canonical timing summary only
after deciding which phases belong in the runtime definition.

## Observability Gap Rate

No pinned `observability_gap_rate` key is currently emitted.

The ingredients are partially present:

- `ArtifactExpectation.observability`
- `source_eligibility`
- `MatchResult` relation and match level
- strong vs class-only distinction

Current limitation: there is no reason-code taxonomy for why an expectation was
missed at strong instance level. For Father, candidate-level FN is zero, but
strong-instance misses are three. These are not represented as observability
gaps with reasons.

Recommended later implementation: postpone unless the thesis needs it. If
added, derive it from unmatched or weakly matched expected artifacts grouped by
`observability` and `source_eligibility`.

## Methodological Assessment

Defensible now:

- Candidate-level diagnostics are clearly labeled.
- Strong instance matches are separated from class-only support.
- Raw finding fallback is excluded from normal thesis reporting.
- The report now shows enough layers to explain where noise enters.

Questionable now:

- `final precision` is conservative but semantically overloaded because
  unmatched candidate claims are in its denominator.
- Source coverage is not yet a clean thesis metric.
- Evidence coverage exists only as partial recall fields.
- Critical recall can still hide weak class-only support.
- Noise reduction is derivable but not formalized and not baseline-aware.

Recommended next metric cleanup:

1. Define the final reconstruction set explicitly in prose.
2. Rename or clarify `final_reconstruction.precision`.
3. Add explicit pinned metric keys only after definitions are stable.
4. Add source/evidence coverage over strong instance matches first.
5. Leave baseline-aware filtering for a separate implementation patch.
