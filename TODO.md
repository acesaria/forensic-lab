# Active TODO — Thesis Rescue Plan

## Status

- This file is the active execution plan for the thesis rescue phase.
- Historical plans are archived under
  `docs/archive/stale-planning-2026-07-08/`.
- Do not use archived TODO/REFACTOR/AUDIT files as current instructions.
- Treat old prompt files and walkthroughs as rationale only after checking the
  current source, methodology, and latest run artifacts.

## Current Source Of Truth

1. `PROJECT_CONTEXT.md` and `AGENTS.md`, when present and current.
2. `METHODOLOGY.md` for evaluation vocabulary, matching, and metrics.
3. `TODO.md` for the active execution order.
4. `docs/repo_map.md` for repository orientation.
5. The latest explicit `report.md`, `metrics.json`, and `outcomes.jsonl` for a
   named run.

Generated `shared/` artifacts are evidence for a named run, not standing
project instructions.

## Immediate Next Task

Father/Scenario-F no-cleanup metrics/rule/report cleanup.

Keep this pass focused on making the current no-cleanup Father result
methodologically readable and thesis-defensible. Do not start the cleanup
variant, second scenario, VM orchestration, acquisition, or major tool work in
this task.

Acceptance criteria:

- The expectation-level report is readable.
- Every scored expectation is explainable as `identified`, `supported`,
  `missed`, or `contextual`.
- Broad residual claims are reduced, gated, or explicitly demoted.
- The dynamic-loader/preload configuration rule no longer over-matches
  workspace or source paths.
- Baseline diff includes useful status/hash information where feasible.
- No new major tools are added.

Guardrails:

- Preserve GT-blindness in detectors, adapters, and rules.
- Keep `ToolFinding` as raw/broad evidence and `DetectionClaim` as
  candidate/supporting evidence, not a verdict.
- Score headline metrics at expectation level only.
- Keep VM power-state transitions in the orchestrator.
- Use CLI flags for per-run behavior toggles, not scenario/config edits.

## Next Phases

1. Father cleanup variant.
2. Recheck baseline logic. Check if sha256 is implemented and working. Implement 'two way' diff. Add baseline also for memory (Ex. proclist and lkm.. nothing too complex)
3. One second full-depth scenario, preferably malicious LKM unless CopyFail is
   already stable.
4. Shallow OS/profile matrix.
5. Thesis figures and tables.
6. Writing and freeze.

## Explicit Deferrals

Defer these unless a later task explicitly reopens them:

- Timesketch integration.
- Velociraptor integration.
- AIDE/NSRL integration.
- Graph database or CASE/UCO full ontology.
- Broad Sigma/YARA corpus.
- `auditd` as the default profile evidence source.
- Large test rewrite.
- Broad architecture refactor.
- New major dependencies or platforms.

## Testing Warning

The current tests are useful smoke and behavior guards. They do not prove
forensic correctness, live acquisition reliability, or thesis validity.

Use tests to catch regressions in source shape and methodology invariants, then
validate thesis claims against explicit run artifacts.
