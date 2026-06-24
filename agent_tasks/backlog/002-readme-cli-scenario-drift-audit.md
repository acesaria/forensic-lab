# Task: README, CLI, and Scenario Drift Audit

Read `PROJECT_CONTEXT.md` and `AGENTS.md` first.

## Objective

Identify drift between README descriptions, CLI commands, and registered
scenarios without editing README yet.

## Scope

Audit only.

## Files to Inspect

- `README.md`
- `cli.py`
- `scenarios.yaml`
- `attacks/scenarios/userland_father_ldpreload/README.md`
- `TODO.md`

## Forbidden Changes

- Do not edit README in this task.
- Do not edit scenario, detector, matcher, evaluation, or VM lifecycle code.
- Do not run VM-facing commands.

## Expected Output

A report with:

- inspected files
- drift findings with file references
- proposed minimal README or instruction fixes
- intentionally unchanged areas

## Done Criteria

- The report clearly separates verified code behavior from stale documentation.
- The report identifies whether `scenario_01_ldpreload`,
  `scenario_01_ldpreload_cleanup`, `art_calibration`, and
  `userland_father_ldpreload` are described consistently.
