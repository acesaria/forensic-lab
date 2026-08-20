# 05 Thesis

## Problem

Draft `.tex` fragments only, derived strictly from validated stage 02/03
experiment/investigation outputs and stage 04 docs. Do not infer unsupported
claims; state limitations honestly; do not edit code or rerun experiments here.

## Current state

- No fragments written yet. Prefer small, composable subsection fragments.

## Inputs

Per `ai/IDENTITY.md` read order, plus `ai/_config/{conventions,scope,done}.md`,
the relevant validated outputs from stages 02/03/04, and only the exact thesis
sections being drafted. Use
`ai/03_investigation/references/results-tables-methodology.md` for the active
result-table/status contract. The exact supervisor/task prompt controls the
bounded thesis work. `ai/thesis-finalization-plan.md` is a historical planning
snapshot and is read only when the task explicitly names it.

For a supervisor-style audit, bounded refactor, or final thesis gate, also read
`ai/05_thesis/references/thesis-review-checklist.md`. Do not load that checklist
for ordinary fragment drafting.

## Next steps

- Write one `.tex` fragment per task under `ai/05_thesis/output/` (e.g.
  `father_results.tex`), thesis-ready but reviewable, fact-based, and aligned
  with the outputs it cites.
- When Claude is the executor, give it a short stage-05 prompt with an exact
  file allowlist and stop gate; it starts at `ai/INDEX.md`.
