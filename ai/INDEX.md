# ICM Index

Navigable index for agents and humans working in `ai/`. Read this first, then
`ROUTING.md`, then the current stage `CONTEXT.md`.

## Project overview

`ai/` is a **local-only** (gitignored, `/ai/`) AI workspace for finishing and
stabilizing the `linux-multisource-dfir-lab` thesis project: bounded refactors,
scenario experiments, DFIR investigations, simple docs, and thesis `.tex`
fragments derived from validated outputs. It is not part of the thesis
deliverable and is not meant to redesign the project (`IDENTITY.md`,
`_config/scope.md`).

## Directory table

| Directory | Purpose | Key files | Status |
|---|---|---|---|
| `_config/` | Workspace rules | `conventions.md`, `scope.md`, `done.md`, `review-report.md` | stable |
| `01_refactor` | Bounded, behavior-preserving refactors | `CONTEXT.md`, `output/father-rootkit-integration.md` | Father integration done |
| `02_experiments` | Run + record one scenario experiment | `CONTEXT.md`, `output/father/*` | Father final run recorded (`father-u22-20260818-01`) |
| `03_investigation` | Forensic disk/memory/timeline per `RUN_ID` | `CONTEXT.md`, `references/*`, `output/*` | Father disk notebook canonical; open decisions in `output/disk-investigation-refactor-plan.md` |
| `04_docs` | Simple README/project docs from validated outputs | `CONTEXT.md` | no handoff yet |
| `05_thesis` | `.tex` fragments from validated outputs | `CONTEXT.md` | no fragments yet |

Top-level: `IDENTITY.md` (global rules + read order), `ROUTING.md` (task→stage),
`DECISIONS.md` (D-001..D-008), `STRUCTURE_MAP.md` (this cleanup's map),
`thesis-finalization-plan.md` (master delivery plan, migrated from repo-root
`TODO.md`), `icm-cleanup-prompt.md` (reusable maintenance prompt), `archive/`
(superseded files).

Migrated into ICM on 2026-08-20 (public-surface cleanup): the delivery plan
(above) and `03_investigation/references/investigation-guidelines.md`
(notebook-authoring guidance, from repo-root `GUIDELINES.md`). The DFIR
reporting contract stays public in repo-root `archive/METHODOLOGY.md`, which the
accepted case reports cite.

## Agent rules

- **Read order** (`IDENTITY.md`): `IDENTITY.md` → `ROUTING.md` → current stage
  `CONTEXT.md` → files the task names explicitly. Do not load files a stage
  does not require; do not scan the whole repo.
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
