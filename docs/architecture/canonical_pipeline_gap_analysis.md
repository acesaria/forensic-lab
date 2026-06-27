# Canonical Pipeline Gap Analysis

Date: 2026-06-25

Scope: canonical/declarative `userland_father_ldpreload` only. The legacy
`scenario_01_*`, ART calibration, and `gt_manifest.json -> findings.jsonl`
evaluation stack remain calibration/regression paths and are intentionally not
cleaned here.

## Summary

The canonical Father_LDPRELOAD path already produces the right high-level
artifact chain for post-mortem reconstruction:

`execution_truth.jsonl` / `artifact_expectations.jsonl`
-> `tool_findings.jsonl`
-> `detection_claims.jsonl`
-> `matches.jsonl`
-> `metrics.json` / `score_report.md`

The current records are sufficient for a first implementation of
`claim_recall`, `claim_precision`, `evidence_coverage`, and `source_coverage`.
They are not yet sufficient for clean `noise_reduction_ratio` or
`pipeline_runtime_seconds` without small additions. Baseline comparison is the
largest missing evidence source: current code uses case-window filtering to
reduce baseline noise, but it does not emit baseline-diff findings.

`DetectionClaim` records must be described as candidate/supporting evidence, not
as final reconstruction claims. Final reconstruction is the GT-aware
`MatchResult` relation between an `ArtifactExpectation` and a candidate claim.

> Superseded note (2026-06-27): The architecture review now treats claim
> precision as postponed/undefined until a real final-claim selection layer
> exists, and headline metrics are scored over strong instance reconstruction —
> not over all candidate claims. Where this document still recommends a pinned
> `claim_precision` metric (see the Metrics Input Gap Table), defer to
> `docs/metrics_methodology.md` and `PROJECT_CONTEXT.md`. Treat the rest of this
> document as a point-in-time snapshot.

## Inspected Files

- `AGENTS.md`
- `PROJECT_CONTEXT.md`
- `scenarios.yaml`
- `cli.py`
- `orchestrator/core/orchestrator.py`
- `orchestrator/scenarios/run_context.py`
- `orchestrator/canonical/models.py`
- `orchestrator/adapters/common.py`
- `orchestrator/adapters/sleuthkit/bodyfile.py`
- `orchestrator/adapters/volatility3/json_output.py`
- `orchestrator/adapters/plaso/jsonl.py`
- `orchestrator/adapters/yara/matches.py`
- `detectors/engine.py`
- `detectors/rules/**/*.yml`
- `matcher/engine.py`
- `orchestrator/scenarios/tests/test_userland_father_ldpreload.py`
- `detectors/tests/test_engine.py`
- `matcher/tests/test_matcher_engine.py`
- `orchestrator/adapters/tests/test_tool_adapters.py`

Generated run sampled for current output shape:

- `shared/experiments/ubuntu-22.04_userland_father_ldpreload_20260618-183143`

## Current Canonical Outputs

The VM-backed declarative evaluator writes canonical analysis artifacts in
`orchestrator/core/orchestrator.py::_evaluate_declarative_run`:

- `dumps/execution_truth.jsonl`
- `dumps/artifact_expectations.jsonl`
- `dumps/reference_context.json`
- `dumps/command_log.jsonl`
- `analysis/vol3.json`
- `analysis/bodyfile`
- `analysis/timeline.jsonl`
- `analysis/tool_findings.jsonl`
- `analysis/detection_claims.jsonl`
- `analysis/matches.jsonl`
- `analysis/metrics.json`
- `analysis/score_report.md`

The sampled run contained:

| Artifact | Count |
|---|---:|
| `execution_truth.jsonl` | 7 |
| `artifact_expectations.jsonl` | 10 |
| `tool_findings.jsonl` | 7608 |
| `detection_claims.jsonl` | 266 |
| `matches.jsonl` | 266 |

Sampled `ToolFinding` counts by source/type:

| Source | Artifact Class | Count |
|---|---|---:|
| memory | library_mapping | 2928 |
| timeline | shell_history_log_event | 2767 |
| memory | file | 653 |
| timeline | file | 593 |
| memory | socket | 278 |
| memory | process | 253 |
| timeline | service_unit_file | 81 |
| disk | file | 24 |
| timeline | preload_configuration | 16 |
| timeline | shared_object | 7 |
| disk | preload_configuration | 3 |
| disk | deleted_file_candidate | 3 |
| disk | shell_history_log_event | 1 |
| disk | shared_object | 1 |

Sampled `DetectionClaim` counts by rule/category:

| Rule | Artifact Class | Count |
|---|---|---:|
| `flab.filesystem.suspicious_temp_path` | file | 95 |
| `flab.filesystem.userland_persistence` | service_unit_file | 81 |
| `flab.filesystem.ld_preload_configuration` | preload_configuration | 69 |
| `flab.memory.process_library_correlation` | library_mapping | 10 |
| `flab.memory.process_socket_correlation` | process_socket_correlation | 4 |
| `flab.filesystem.deleted_artifact_cleanup` | deleted_file_candidate | 3 |
| `flab.filesystem.userland_persistence` | file | 3 |
| `flab.filesystem.suspicious_shared_object` | shared_object | 1 |

Sampled `MatchResult` counts:

| Relation | Level | Count |
|---|---|---:|
| tp | instance | 7 |
| tp | class | 3 |
| fp | none | 256 |

## Adapter and Extractor Coverage

### Disk / Filesystem

Current path:

`extract_bodyfile()` -> `adapt_bodyfile()` -> `ToolFinding`

Emitted metadata:

- `source_type`: `disk`
- `tool`: `sleuthkit`
- `artifact_class`: `file`, `shared_object`, `preload_configuration`,
  `service_unit_file`, `shell_history_log_event`, or `deleted_file_candidate`
- `entity`: path value plus inode, mode, size, deleted flag
- `time`: crtime, mtime, or ctime converted to ISO when present
- `raw_ref`: bodyfile line/inode
- `provenance`: adapter, input, row index, parser
- stable `finding_id` assigned at write time

What it reconstructs for Father:

- LD_PRELOAD config path when the path contains `ld.so.preload` or preload-like
  names.
- Shared object path when it ends in `.so` or `.so.*`.
- Deleted marker as `deleted_file_candidate`.
- General files in the run window.

Gap:

- No baseline-diff classification such as `new_vs_baseline`,
  `changed_vs_baseline`, `deleted_vs_baseline`, or baseline reference ID.
- No file hashes in canonical `ToolFinding` unless an upstream adapter adds them;
  bodyfile does not.

### RAM / Volatility3

Current path:

`extract_plugins()` -> `adapt_plugin_rows()` -> `ToolFinding`

Emitted metadata:

- `source_type`: `memory`
- `tool`: `volatility3`
- `artifact_class`: `process`, `socket`, `shell_history_log_event`,
  `library_mapping`, or `file`
- `entity`: process name/path/PID/PPID, socket local/remote data, command, or
  mapped path/PID
- `time`: `unknown`
- `temporal_quality`: `none`
- `raw_ref`: plugin, row, PID
- `provenance`: adapter, plugin, row index, original row
- stable `finding_id` assigned at write time

What it reconstructs for Father:

- Live target process if Volatility process plugins expose it.
- Loaded/mapped shared object path from maps/ELF-style plugins.
- Remote socket correlations if process and socket share a PID.

Gap:

- Memory findings are point-in-time and usually timeless. This is acceptable for
  post-mortem source coverage, but not for timeline/order metrics.
- Correlations are created in detector code, not as first-class reconstruction
  records. That is acceptable if reports label them as candidate evidence.

### Plaso / Timeline

Current path:

`_build_timeline()` -> `adapt_plaso_events()` -> `ToolFinding`

Emitted metadata:

- `source_type`: `timeline`
- `tool`: `plaso`
- `artifact_class`: `preload_configuration`, `shared_object`,
  `service_unit_file`, `shell_history_log_event`, or `file`
- `entity`: path/log-line value
- `time`: parsed Plaso timestamp when present
- `temporal_quality`: exact when timestamp exists
- `raw_ref`: Plaso event index
- `provenance`: adapter, input, row index, parser, data type, timestamp
  description
- stable `finding_id` assigned at write time

What it reconstructs for Father:

- Timeline evidence for lab-controlled files under the case window.
- LD_PRELOAD-ish paths and log/history records.
- Shared object file paths when Plaso exposes filenames.

Gap:

- Current classification is broad and creates many `shell_history_log_event` and
  preload candidates from baseline/system context.
- There is no baseline-diff layer to separate expected system background from
  experiment-created artifacts.

### Baseline-Diff Findings

There is no canonical baseline-diff extractor or adapter in the primary
declarative path.

Current baseline-related behavior:

- VM starts from a baseline snapshot.
- Disk/timeline findings are filtered to the command-log case window.
- No `ToolFinding` records are marked as baseline-only, new, changed, deleted, or
  unchanged relative to a clean baseline image.

For the pinned metrics, baseline diff is the main missing input for
`noise_reduction_ratio` and a stronger `evidence_coverage` story.

## Current Father Reconstruction

The current canonical path can support these Father_LDPRELOAD reconstruction
claims:

| Reconstruction Topic | Current Support | Notes |
|---|---|---|
| LD_PRELOAD configuration evidence | Yes | Disk/timeline adapters classify preload paths; detector emits `flab.filesystem.ld_preload_configuration`. |
| Suspicious shared object evidence | Partial | `.so` path is represented; rule uses generic temp path plus `preload`, `father`, `rootkit` tokens. Baseline/non-baseline status is missing. |
| Changed/new file evidence relative to baseline | No | Files are scoped by time window, not compared to a clean baseline. |
| Deleted marker / cleanup residue | Partial | Bodyfile deleted entries become `deleted_file_candidate`; no content recovery in canonical declarative path. |
| Memory mapped object evidence | Yes | Volatility maps/ELF rows become `library_mapping`; detector correlates process+library by PID. |
| Process evidence | Yes | Volatility process rows become `process`; matching can match process name. |
| Socket evidence | Partial | Volatility socket rows exist; detector correlation requires PID and remote routable endpoint. The Father declarative expectations do not currently include a reverse-shell socket. |
| Timeline evidence around experiment window | Yes | Plaso and bodyfile findings are filtered to the command-log window. |

## Are DetectionClaim Records Final Claims?

No. `DetectionClaim` records are candidate/supporting evidence emitted by
GT-blind rules over `ToolFinding` records. They carry rule ID, confidence,
artifact class, entity, ATT&CK tags, and `source_findings`, but they are not
ground-truth-aware final reconstruction.

Potentially misleading places:

- The class name `DetectionClaim` can sound final. Thesis language should define
  it as "candidate evidence claim".
- `matches.jsonl` field `finding_or_claim_id` is technically correct but less
  clear than a claim-specific field when raw-finding debug fallback is disabled.
- `score_report.md` currently has "Summary", "Class-level coverage", and "Match
  Detail", but it does not show separate raw findings and candidate evidence
  sections.
- The current metric names in `metrics.json` are generic precision/recall/F1
  over matches, not the pinned claim/evidence metric names.

## Where Expected Reconstruction Claims Should Come From

### Option A: derive from `artifact_expectations.jsonl`

Recommended for Father first.

Pros:

- Already exists for declarative scenarios.
- GT-aware matching already uses `ArtifactExpectation`.
- No new source-of-truth file.
- Keeps expected reconstruction tied to scenario-owned artifact expectations.

Cons:

- It currently models expected artifacts/evidence loci, not human-readable
  "claims". Some report wording must explain that expected claim units are
  `ArtifactExpectation` rows.

Minimal implementation:

- Treat each `ArtifactExpectation` as one expected reconstruction unit.
- Compute claim recall/precision from `MatchResult` relation over
  `DetectionClaim` candidates.
- Add optional grouping labels in reporting, not new model fields.

### Option B: add `expected_claims.jsonl`

Not recommended yet.

Pros:

- Clean naming for thesis prose.

Cons:

- Adds another truth artifact and synchronization problem.
- Duplicates `artifact_expectations.jsonl` for Father.
- Increases authoring overhead before the first metrics are stable.

### Option C: extend current canonical models

Not recommended before metrics.

Pros:

- Could add explicit expected-claim wording to `ArtifactExpectation`.

Cons:

- Model migration before proving metric formulas.
- More tests and fixture churn.

## Metrics Input Gap Table

| Metric | Required Inputs | Current Inputs Present? | Missing | Minimal Change |
|---|---|---|---|---|
| `claim_recall` | Expected units, matched claim TPs, missed expected units | Yes: `ArtifactExpectation`, `DetectionClaim`, `MatchResult` | Official pinned key name | Compute as `tp / (tp + fn)` over claim-backed matches; write under `metrics["pinned"]["claim_recall"]`. |
| `claim_precision` | Candidate claims, matched claim TPs, unmatched candidate FPs | Yes | Official pinned key name; ensure raw-finding fallback excluded | Compute as `tp / (tp + fp)` over `DetectionClaim` candidates only. |
| `evidence_coverage` | Expected artifacts by class/source, matched expected artifacts | Mostly | Need formula definition: global vs per critical/noncritical | Start with `matched ArtifactExpectation count / total ArtifactExpectation count`, plus per artifact class. |
| `source_coverage` | Expected source eligibility, matched claim source types | Yes: `source_eligibility`, linked `source_findings`, `ToolFinding.source_type` | Better denominator for sources with no eligible expectations | Compute per source: expected rows eligible for source vs matched rows with candidate sources. |
| `noise_reduction_ratio` | Raw finding count, candidate claim count, possibly baseline-filtered count | Partial: raw count and claim count exist | Baseline-diff count and pre/post filter accounting are absent | First compute `1 - claim_count / raw_tool_finding_count`; later refine with baseline diff. Include caveat. |
| `pipeline_runtime_seconds` | Start/end timing for extraction, adapters, detectors, matcher, total | No | No runtime/provenance timing in canonical artifacts | Add a tiny timing block in `_evaluate_declarative_run` or a `pipeline_summary.json`; do not infer from file mtimes. |
| `observability_gap_rate` | Expected observable support, unmatched expected rows, reason codes | Partial | No explicit miss reason/gap taxonomy | Optional later: derive unmatched expectations grouped by `observability` and `source_eligibility`; add reason codes only if needed. |

## Report Layer Gaps

Required report layers and current state:

| Required Layer | Current State |
|---|---|
| Evidence sources available | Partial: source breakdown by raw `ToolFinding` source exists. |
| Raw `ToolFinding` counts by source/type | Missing in report; available from `tool_findings.jsonl`. |
| Candidate evidence / `DetectionClaim` counts by category | Missing in report; available from `detection_claims.jsonl`. |
| Matched reconstruction evidence | Partial: match detail table exists, but it is long and not grouped. |
| Missed expected artifacts/claims | Partial: FN rows exist in `matches.jsonl`; report does not summarize them clearly. |
| Metrics summary | Present, but current metric names are not pinned thesis names. |

Minimal report change for metric implementation:

- Pass or load raw `ToolFinding` and `DetectionClaim` counts into report
  rendering.
- Add compact tables:
  - raw findings by `source_type` and `artifact_class`
  - candidate claims by `rule_id` and `artifact_class`
  - matched/missed expectations by `artifact_class`
  - pinned metrics summary
- Keep the detailed match table, but cap or move it below summaries.

## Scenario-Flavored or Overfit Rules

Rules with scenario-flavored tokens:

- `detectors/rules/filesystem/suspicious_shared_object.yml`
  - `suspicious_tokens: [preload, father, rootkit]`
- `detectors/rules/memory/process_library_correlation.yml`
  - `path_tokens: [preload, father, rootkit]`

Minimal cleanup plan:

1. Do not remove tokens in this gap-analysis patch.
2. During metric implementation, remove `father` from production rule tokens.
3. Prefer generic predicates: temp path, `.so`, `preload`, `ld.so.preload`,
   process-library PID correlation.
4. If Father-specific terms remain useful for fixture tests, move them to
   fixture-only rules or comments, not default rule packs.

## Canonical-Path Overengineering and KISS Opportunities

- The matcher computes many current metrics (`macro_f1_by_artifact_class`,
  current micro F1, instance-only variants) before the pinned thesis metrics are
  finalized. Keep them if tests rely on them, but add pinned metrics as the
  report headline and avoid expanding the current metric set.
- `Candidate` is an internal projection of `DetectionClaim`; it is useful, but
  the report should not introduce another public noun. Public layers should be
  raw finding, candidate evidence, matched reconstruction, metric.
- Report rendering only receives metrics and matches, so it cannot show raw and
  candidate counts without reloading or passing additional summaries. Add a small
  summary object rather than new model classes.
- The YARA adapter exists but the primary canonical Father path does not call it.
  Avoid wiring it in until the baseline disk/content story is simplified.
- Baseline comparison should be one simple disk-path diff channel first. Avoid a
  broad baseline service or generalized evidence lake.
- `DetectionClaim` naming can stay in code, but thesis/report wording should call
  it candidate evidence.

## Suspicious or Biased Tests

Tests that are valuable:

- `orchestrator/scenarios/tests/test_userland_father_ldpreload.py` protects the
  declarative Father scenario and cached canonical path.
- `detectors/tests/test_engine.py` protects GT-blind detector behavior and claim
  emission.
- `matcher/tests/test_matcher_engine.py` protects claim-required matching and
  debug-only raw fallback.
- Adapter tests protect GT-blind conversion from cached outputs.

Tests that may overfit implementation details:

- `test_rules_have_sigma_lite_metadata` requires an exact minimum set of rule
  IDs. This can make rule simplification feel like a regression even when the
  behavior improves.
- `test_engine_produces_detection_claims_without_ground_truth` asserts many
  specific rule IDs from one fixture. Prefer behavior assertions around expected
  candidate categories when metrics are added.
- `test_matcher_outputs_matches_metrics_and_report` asserts exact counts
  (`tp=4`, `fp=1`, `fn=1`) for synthetic fixtures. Keep one golden fixture, but
  avoid multiplying exact-count tests while formulas are still changing.
- `test_userland_father_cached_pipeline_reaches_detectors_and_matcher` uses
  hand-built findings rather than adapter-produced findings. It is useful as a
  smoke test, but it does not prove disk/RAM/timeline extraction quality.
- Adapter tests assert exact artifact-class sets for small fixtures. Useful for
  contracts, but they do not validate Father reconstruction end to end.

## Minimal Code Changes Before Metric Implementation

1. Add pinned metric computation in canonical `matcher/engine.py`, derived from
   existing `ArtifactExpectation`, `DetectionClaim`, `ToolFinding`, and
   `MatchResult` records.
2. Add a tiny pipeline timing/provenance artifact for canonical evaluation,
   preferably `analysis/pipeline_summary.json` with total seconds and per-phase
   seconds.
3. Add report summaries for raw findings, candidate claims, matched
   expectations, missed expectations, and pinned metrics.
4. Add baseline-diff as a small optional canonical disk finding source:
   compare current disk/bodyfile path inventory against a cached clean baseline
   inventory and emit/annotate `ToolFinding` records with baseline status.
5. Remove `father` from default detector rule tokens once pinned metrics are in
   place, then update tests to assert behavior rather than rule names.

## Intentionally Unchanged

- Legacy ART/scenario_01 code and tests.
- VM lifecycle and acquisition orchestration.
- Detector rule behavior.
- Adapter behavior.
- Matcher algorithms and metric formulas.
- README and scenario README.
- Generated `shared/` outputs.

