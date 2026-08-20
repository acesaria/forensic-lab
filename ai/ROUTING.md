# Routing

## Navigation

- New here? Read `ai/INDEX.md` first (overview + directory table + agent rules).
- Structure map and source-of-truth vs generated files: `ai/STRUCTURE_MAP.md`.

## Stage order

1. `ai/01_refactor`
2. `ai/02_experiments`
3. `ai/03_investigation`
4. `ai/04_docs`
5. `ai/05_thesis`

## Route tasks

| Task | Stage |
|---|---|
| Code cleanup or bounded refactor | `ai/01_refactor` |
| Attack execution or acquisition | `ai/02_experiments` |
| Runme investigation workflow or DF evidence analysis | `ai/03_investigation` |
| Simple README/module/scenario documentation | `ai/04_docs` |
| LaTeX chapter/subsection writing | `ai/05_thesis` |

## Handoff chain

- `ai/01_refactor/output/` -> `ai/02_experiments`
- `ai/02_experiments/output/` -> `ai/03_investigation`
- `ai/03_investigation/output/` -> `ai/04_docs` and `ai/05_thesis`
- `ai/04_docs/output/` -> `ai/05_thesis`

## Important boundaries

- Experiment inputs are under `shared/experiments/<RUN_ID>/`.
- Investigation outputs are under `shared/investigations/<RUN_ID>/`.
- Reusable investigation workflows are under `investigations/<scenario>/`.
- `docs/` contains project documentation only.
- Do not mix raw acquisition, derived analysis, notebook source, and thesis prose.