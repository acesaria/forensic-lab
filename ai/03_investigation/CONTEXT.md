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
- Father's memory and timeline phases use plain Bash scripts
  (`runme_memory.sh`, `runme_timeline.sh`) plus small metric helpers. The other
  three attack scenarios do not yet have investigation workflows in this
  checkout.
- Derived output convention (established, do not change):
  `shared/investigations/<RUN_ID>/{derived/{disk,memory,timeline}/,logs/,report/,investigation.json}`.
- Full architecture-of-record and stage boundaries:
  `ai/03_investigation/references/investigation-architecture.md`.
- Active result-table and descriptive-metrics method:
  `ai/03_investigation/references/results-tables-methodology.md`.
- Deeper disk-notebook plan with open decisions:
  `ai/03_investigation/output/disk-investigation-refactor-plan.md`.

## Inputs

Per `ai/IDENTITY.md` read order, plus `ai/_config/{conventions,scope,done}.md`,
the relevant `ai/02_experiments/output/<scenario>/` notes, the run's manifest
and acquisition metadata, and the investigation files explicitly named by the
task. Do not read the entire repository.

**Reporting contract:** use
`references/results-tables-methodology.md` for the active research questions,
evidence states, reconstruction/coverage table, source-contribution and triage
table, rejected-candidate accounting, recovery rows, temporal error, and review
rule. `ai/archive/METHODOLOGY.md` and investigation `output/` research reports
are background only where they conflict with this simpler contract.
Notebook-authoring style remains in `references/investigation-guidelines.md`.

## Next steps

1. Keep each finding anchored to an evidence/output file; state limitations and
   unperformed checks explicitly.
2. Draft the scenario's reconstruction-item list before assigning results and
   reuse it across distributions.
3. Write derived investigation data only under
   `shared/investigations/<RUN_ID>/`; never modify experiment inputs.
4. Stop for human review after inventory, contract, cheap validation, and the
   completed one-run investigation.
5. Write the handoff to `ai/03_investigation/output/handoff.md`.
