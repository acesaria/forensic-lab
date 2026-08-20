# ICM Index

Single entry point for agents and humans working in `ai/`.

## Project overview

`ai/` is the tracked internal coordination layer for bounded refactors,
experiments, DFIR investigations, simple docs, and thesis `.tex` fragments. It
routes work but is not forensic evidence or a thesis deliverable.

Read in this order: `INDEX.md` → `IDENTITY.md` → `ROUTING.md` → the selected
stage's `CONTEXT.md` → only the files named by the task/context.

## Directory table

| Directory | Purpose | Key files | Status |
|---|---|---|---|
| `_config/` | Workspace rules | `conventions.md`, `scope.md`, `done.md`, `review-report.md` | stable |
| `01_refactor` | Bounded, behavior-preserving refactors | `CONTEXT.md`, `output/father-rootkit-integration.md` | Father integration done |
| `02_experiments` | Run + record one scenario experiment | `CONTEXT.md`, historical `output/father/*` | No active run assumed; use the run named by the task |
| `03_investigation` | Forensic disk/memory/timeline per `RUN_ID` | `CONTEXT.md`, `references/results-tables-methodology.md`, `output/*` | Father is the only implemented investigation; disk/recovery work is incomplete |
| `04_docs` | Simple README/project docs from validated outputs | `CONTEXT.md` | no handoff yet |
| `05_thesis` | `.tex` fragments from validated outputs | `CONTEXT.md` | no fragments yet |

Top-level: `IDENTITY.md` (global rules + read order), `ROUTING.md` (task→stage),
`DECISIONS.md` (active decisions), `STRUCTURE_MAP.md` (current map),
`thesis-finalization-plan.md` (historical planning snapshot; load only when a
task names it), and `archive/` (superseded material).

Migrated into ICM on 2026-08-20 (public-surface cleanup): the delivery plan
(above) and `03_investigation/references/investigation-guidelines.md`
(notebook-authoring guidance, from repo-root `GUIDELINES.md`). The active simple
result-table and metrics contract is
`03_investigation/references/results-tables-methodology.md`; older methodology
and deep-research material is background where it conflicts with that file.

## Agent rules

- Follow the read order above. Do not load files a stage does not require or
  scan the whole repository unless the task explicitly requires it.
- **To work on X, read first:**
  - a bounded code refactor → `01_refactor/CONTEXT.md`
  - running/acquiring a scenario → `02_experiments/CONTEXT.md`
  - forensic analysis of a run → `03_investigation/CONTEXT.md` +
    `03_investigation/references/investigation-architecture.md`
  - README/module docs → `04_docs/CONTEXT.md`
  - LaTeX → `05_thesis/CONTEXT.md`
- **`output/`** files are generated per-task handoffs; they may be added to or
  overwritten. **`references/`** files are stable reusable material; update them
  carefully.
- Each stage's handoff (`output/`) is the input to the next stage
  (`ROUTING.md` handoff chain).
- Real work products live outside `ai/`: experiments in
  `shared/experiments/<RUN_ID>/`, investigations in
  `shared/investigations/<RUN_ID>/`, reusable workflows in
  `investigations/<scenario>/`.

## Short executor prompt

A Claude prompt normally needs only: objective, selected stage, write/read
allowlist, validation, and stop gate, followed by: “Start at `ai/INDEX.md` and
follow ICM routing.” Do not duplicate the ICM context inside the prompt.
