# Task: Father_LDPRELOAD Reference Pipeline Audit

Read `PROJECT_CONTEXT.md` and `AGENTS.md` first.

## Objective

Trace the active Father_LDPRELOAD path and identify the smallest steps needed
to make it the reference thesis pipeline.

## Scope

Audit and plan only.

## Files to Inspect

- `scenarios.yaml`
- `orchestrator/attacks/scenario_01_ldpreload.py`
- `attacks/scenarios/userland_father_ldpreload/scenario.yml`
- `attacks/scenarios/userland_father_ldpreload/expected_observables.yml`
- `attacks/scenarios/userland_father_ldpreload/steps.py`
- `detectors/rules/`
- `detectors/engine.py`
- `matcher/engine.py`
- `cli.py`

## Forbidden Changes

- Do not edit scenario code in this task.
- Do not add Timesketch, HashR, THOR Lite, Velociraptor, new Sigma expansion, or
  new tools.
- Do not run VM-facing commands without explicit user approval.
- Do not perform a whole-pipeline rewrite.

## Expected Output

A focused report with:

- inspected files
- current end-to-end path
- gaps or ambiguities
- proposed minimal next changes
- intentionally unchanged areas

## Done Criteria

- The report answers which Father_LDPRELOAD path should be treated as the
  reference path.
- The report explicitly asks: "This system may work, but is it too complex for
  the thesis deadline? Which part can be removed, flattened, or made explicit?"
