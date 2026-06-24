# Task: Candidate Evidence Wording Audit

Read `PROJECT_CONTEXT.md` and `AGENTS.md` first.

## Objective

Find wording that treats YAML rules or `DetectionClaim` as final detections
instead of candidate evidence.

## Scope

Audit terminology only. Propose minimal wording changes.

## Files to Inspect

- `detectors/`
- `matcher/`
- `orchestrator/canonical/`
- `orchestrator/evaluation/`
- `detectors/rules/README.md`
- `.github/instructions/forensic-evaluation.instructions.md`
- `PROJECT_CONTEXT.md`

## Forbidden Changes

- Do not change detector behavior.
- Do not change matcher behavior.
- Do not change schemas unless explicitly requested after the audit.
- Do not perform broad renames.

## Expected Output

A report listing wording problems and minimal replacement wording.

## Done Criteria

- The report distinguishes raw finding, candidate evidence, matched
  reconstruction, and metric result.
- No proposed change weakens GT-blindness.
