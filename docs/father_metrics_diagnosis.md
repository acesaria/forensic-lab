# Father_LDPRELOAD Metrics Diagnosis

Run inspected:
`shared/experiments/ubuntu-22.04_userland_father_ldpreload_20260629-181530`

## Executive Summary

Clean baseline comparison is working, but candidate precision remains low
because candidate diagnostics still count every unmatched candidate claim as an
FP, including claims that baseline correctly marked as present in the clean VM
and confidence-downgraded. Baseline made the evidence more interpretable; it
did not change matcher formulas or remove claims from the diagnostic
denominator.

The FP stream is concentrated in three broad filesystem rules:

- `flab.filesystem.suspicious_temp_path`: 95 FP
- `flab.filesystem.userland_persistence`: 84 FP
- `flab.filesystem.ld_preload_configuration`: 63 FP

Together these produce 242 of 249 FPs. Timeline-derived claims dominate:
216 of 249 FPs come from timeline source findings. Baseline classified 126 FPs
as `present_in_baseline` and downgraded 116 of them, but those claims still
remain FPs in `candidate_diagnostics`.

## Current Metrics

| metric | value |
| --- | --- |
| DetectionClaim count | 259 |
| candidate TP / FP / FN | 10 / 249 / 0 |
| candidate precision / recall / F1 | 0.0386 / 1.0000 / 0.0743 |
| strong instance matches | 7/10 |
| class-only support | 3 |
| baseline available | true |
| baseline input | lab-ubuntu-22.04:baseline |
| baseline path count | 67262 |
| compromised path count | 686 |
| baseline status counts | new=15, changed=0, present=671, unknown=0 |
| candidate status counts | new=126, present=127, unknown=6 |
| candidate downgrades / suppressions | 116 / 0 |
| source coverage ratio | 0.6667 |
| corroboration rate | 0.0 |
| noise reduction | raw=8696, candidates=259, strong=7 |
| methodology warnings | 5 |

## Rule-Level FP Table

| rule_id | FP | source | artifact_class | baseline_status | confidence | downgraded |
| --- | --- | --- | --- | --- | --- | --- |
| `flab.filesystem.suspicious_temp_path` | 95 | timeline:76, disk:19 | file:95 | new_vs_baseline:55, present_in_baseline:40 | 0.70:49, 0.35:32, 0.82:14 | 32 |
| `flab.filesystem.userland_persistence` | 84 | timeline:84 | service_unit_file:81, file:3 | present_in_baseline:84 | 0.35:84 | 84 |
| `flab.filesystem.ld_preload_configuration` | 63 | timeline:56, disk:7 | preload_configuration:63 | new_vs_baseline:63 | 0.86:63 | 0 |
| `flab.memory.process_socket_correlation` | 5 | memory:5 | process_socket_correlation:5 | unknown_baseline_status:5 | 0.72:5 | 0 |
| `flab.filesystem.deleted_artifact_cleanup` | 2 | disk:2 | deleted_file_candidate:2 | present_in_baseline:2 | 0.64:2 | 0 |

## Source-Level FP Table

| source | FP | top_rules | baseline_status | downgraded |
| --- | --- | --- | --- | --- |
| timeline | 216 | userland_persistence:84, suspicious_temp_path:76, ld_preload_configuration:56 | present_in_baseline:116, new_vs_baseline:100 | 116 |
| disk | 28 | suspicious_temp_path:19, ld_preload_configuration:7, deleted_artifact_cleanup:2 | new_vs_baseline:18, present_in_baseline:10 | 0 |
| memory | 5 | process_socket_correlation:5 | unknown_baseline_status:5 | 0 |

## Baseline-Status FP Table

| baseline_status | FP | top_rules | sources | confidence | downgraded |
| --- | --- | --- | --- | --- | --- |
| present_in_baseline | 126 | userland_persistence:84, suspicious_temp_path:40, deleted_artifact_cleanup:2 | timeline:116, disk:10 | 0.35:116, 0.82:8, 0.64:2 | 116 |
| new_vs_baseline | 118 | ld_preload_configuration:63, suspicious_temp_path:55 | timeline:100, disk:18 | 0.86:63, 0.70:49, 0.82:6 | 0 |
| unknown_baseline_status | 5 | process_socket_correlation:5 | memory:5 | 0.72:5 | 0 |

## Baseline-Present FPs

These are the candidates where baseline comparison helped most. They are
mostly clean VM systemd/cron/tmp paths that broad filesystem rules flagged
because they appeared in the timeline case window.

| rule_id | present FP | source | artifact | downgraded | examples |
| --- | --- | --- | --- | --- | --- |
| `flab.filesystem.userland_persistence` | 84 | timeline:84 | service_unit_file:81, file:3 | 84 | `/etc/cron.d`, `/etc/crontab`, `/etc/systemd/system/...`, `/usr/lib/systemd/...` |
| `flab.filesystem.suspicious_temp_path` | 40 | timeline:32, disk:8 | file:40 | 32 | `/tmp/.ICE-unix`, `/tmp/.X11-unix`, `/tmp/.font-unix`, `/tmp/snap-private-tmp` |
| `flab.filesystem.deleted_artifact_cleanup` | 2 | disk:2 | deleted_file_candidate:2 | 0 | `/usr/share/man/man3`, `/usr/share/man/man7/^` |

The 116 downgraded claims should stay visible as diagnostic/support evidence,
but they should not be interpreted as thesis headline reconstruction quality.
If a later presentation layer separates "candidate diagnostics" from
"actionable candidates", these baseline-present timeline-only claims are the
first candidates to hide from headline candidate precision or classify as
support-only.

The 10 baseline-present FPs not downgraded are disk-backed candidates:
8 `suspicious_temp_path` claims and 2 `deleted_artifact_cleanup` claims.
The current downgrade policy only caps present-in-baseline timeline-only
claims. That policy is conservative and explains why these disk-backed claims
remain full-confidence FPs.

## New-vs-Baseline FPs

These candidates are genuinely new relative to the clean VM. Baseline should
not suppress them; the next improvement must come from narrower rule logic or
from better candidate deduplication/support classification.

| rule_id | new FP | source | artifact | confidence | examples |
| --- | --- | --- | --- | --- | --- |
| `flab.filesystem.ld_preload_configuration` | 63 | timeline:56, disk:7 | preload_configuration:63 | 0.86:63 | `/tmp/forensic-lab/father_ldpreload/etc`, `lib`, `markers`, `run`, `source`, `benign_process.out`, `benign_process.pid` |
| `flab.filesystem.suspicious_temp_path` | 55 | timeline:44, disk:11 | file:55 | 0.70:49, 0.82:6 | `/tmp/forensic-lab`, scenario workspace directories, marker file, source archive, source metadata, run files |

The new-vs-baseline stream is inflated by repeated timeline events. For
example, `ld_preload_configuration` has 63 new FPs but only 14 unique paths;
`suspicious_temp_path` has 55 new FPs but only 11 unique paths. Several paths
appear five times due to timeline/bodyfile event multiplicity.

These are not baseline failures. They are broad candidate rules over a
scenario workspace under `/tmp`, plus timeline duplication.

## Unknown-Baseline FPs

The 5 unknown-baseline FPs come from memory process/socket correlation:

| rule_id | unknown FP | source | artifact | examples |
| --- | --- | --- | --- | --- |
| `flab.memory.process_socket_correlation` | 5 | memory:5 | process_socket_correlation:5 | PIDs connected to `192.168.100.1` ephemeral ports |

Baseline path comparison is filesystem-only, so memory socket claims are
correctly marked `unknown_baseline_status`. These require process/socket rule
review, not filesystem baseline filtering.

## Why Baseline Worked But Precision Stayed Low

Baseline availability changed claim metadata and confidence, not the matcher
formula:

- `metrics.json` has `baseline_comparison.available == true`.
- 126 FPs were marked `present_in_baseline`.
- 116 present-in-baseline timeline-only claims were confidence-downgraded to
  0.35.
- `candidate_suppressions` remained 0.
- `candidate_diagnostics` still computes TP/FP/FN from match relations over
  all candidate claims.

Therefore downgraded baseline-present candidates still count as FPs. Candidate
precision stayed low because the denominator is still 259 claims and the FP
count is still 249. Baseline improved interpretability and triage, but it was
intentionally not used to alter matcher semantics.

The remaining poor precision has three causes:

1. Broad timeline filesystem rules emit candidates for many benign baseline
   paths.
2. New scenario workspace paths under `/tmp` trigger broad temp/preload rules
   even when they are only support artifacts.
3. Multiple timeline events for the same path create repeated candidate claims.

## Rule Findings

### `flab.filesystem.userland_persistence`

This rule is the cleanest next cleanup target. It produced 84 FPs, all
baseline-present, all timeline-sourced, all downgraded, and no TP in this run.
The rule currently flags cron/systemd paths broadly enough that ordinary clean
VM services become candidate evidence whenever they appear in the case window.

Recommended direction: stop treating baseline-present timeline-only cron and
systemd paths as primary candidate evidence. The smallest rule-only version is
to remove timeline as a source for this broad rule or split it into a stricter
timeline rule that requires stronger creation/modification evidence.

### `flab.filesystem.ld_preload_configuration`

This rule produced 63 FPs, all new-vs-baseline, but it also supplies several
matched Father artifacts. It is too broad because the token `preload` promotes
any path containing that substring into `preload_configuration`, including
workspace directories and non-config support files.

Recommended direction: make this rule identify actual preload configuration or
LD_PRELOAD command evidence, not every path containing `preload`. Candidate
support files such as source archives and metadata should be covered by a more
generic file/support rule or matched as support, not reclassified as preload
configuration.

This change is higher risk than `userland_persistence` because current Father
strong/class support partly flows through this broad rule.

### `flab.filesystem.suspicious_temp_path`

This rule produced 95 FPs. It correctly identifies that the scenario workspace
is new under `/tmp`, but it treats directories, marker files, source files, and
run outputs as suspicious primary candidates. Baseline cannot suppress these
because they are actually new.

Recommended direction: narrow temp-path evidence to executable files, deleted
files, shared objects, scripts, or other explicitly suspicious file types.
Plain directories and ordinary support files should become support-only or not
emit primary candidates.

### `flab.memory.process_socket_correlation`

This rule produced 5 memory FPs and 1 class-level TP. It is outside filesystem
baseline scope. The current FPs are lab-host connections to ephemeral ports.
Review separately after filesystem rule cleanup.

## Recommended Next Rule Cleanup

Smallest safe patch:

1. Change only `flab.filesystem.userland_persistence`.
2. Remove or split broad timeline-sourced cron/systemd claims so clean
   baseline-present timeline-only services are no longer primary candidates.
3. Keep disk-sourced persistence evidence intact.
4. Re-run cached Father detector/matcher output and the focused detector tests.

Expected effect:

- Candidate count should drop by about 84 if timeline source is removed from
  the broad persistence rule.
- No Father strong instance loss is expected from this specific change because
  `userland_persistence` produced no TP in the inspected run.
- Baseline-present FP pressure should drop substantially.

Next after that:

- Tighten `ld_preload_configuration` to actual preload configuration or
  LD_PRELOAD command evidence.
- Tighten `suspicious_temp_path` to executable/deleted/shared-object/script
  evidence, not directories or ordinary support files.
- Consider path-level timeline deduplication as a diagnostic cleanup, but only
  after rule semantics are less broad.

## Explicit Non-Goals

- Do not change matcher formulas to improve candidate precision.
- Do not hide baseline-present candidates without reporting the policy.
- Do not use scenario ground truth in detector rules.
- Do not add YARA, Sigma, Timesketch, package ownership, or reputation checks.
- Do not change Father artifact expectations to fit current detector output.
- Do not treat candidate precision as the headline thesis metric.
