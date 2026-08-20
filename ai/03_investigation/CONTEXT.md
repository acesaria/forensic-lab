# 03 Investigation

## Problem

Turn a completed experiment (`shared/experiments/<RUN_ID>/`) into a reusable,
per-scenario forensic investigation: disk, memory, and timeline evidence plus a
readable per-run report — reproducible from `RUN_ID`, with no hardcoded
offsets/inodes/PIDs. This is not a generic documentation stage.

## Current state

- Reference implementation: `investigations/father/`.
- Disk phase (Father) = canonical Python notebook
  `investigations/father/disk_investigation.ipynb` (+ `investigation_utils.py`).
- Memory + timeline phases (Father) and all other scenarios = plain Bash phase
  scripts (`runme_memory.sh`, `runme_timeline.sh`) + `metrics/*.py`.
- Derived output convention (established, do not change):
  `shared/investigations/<RUN_ID>/{derived/{disk,memory,timeline}/,logs/,report/,investigation.json}`.
- Full architecture-of-record and stage boundaries:
  `ai/03_investigation/references/investigation-architecture.md`.
- Deeper disk-notebook plan with open decisions:
  `ai/03_investigation/output/disk-investigation-refactor-plan.md`.

## Inputs

Per `ai/IDENTITY.md` read order, plus `ai/_config/{conventions,scope,done}.md`,
the relevant `ai/02_experiments/output/<scenario>/` notes, the run's manifest
and acquisition metadata, and the investigation files explicitly named by the
task. Do not read the entire repository.

**Reporting contract:** case reports (`docs/investigations/<scenario>/<run_id>/`)
follow the repo-root **`../archive/METHODOLOGY.md`** — the authority for the evidence-status
vocabulary (`O/P/N/TF/--`), the `U/C/S` classes, coverage math, and the two-table
`runme_case_summary.md` format. Notebook-authoring style is in
`references/investigation-guidelines.md`.

## Next steps

1. Keep each finding anchored to an evidence/output file; state limitations and
   unperformed checks explicitly.
2. Write only under `shared/investigations/<RUN_ID>/`; never modify experiment
   inputs; never create repo-root artifacts.
3. Stop for human review after inventory, contract, cheap validation, and the
   completed one-run investigation.
4. Write the handoff to `ai/03_investigation/output/handoff.md`.
