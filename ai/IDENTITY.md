# Identity

This is a local-only AI workspace used to finish and stabilize the linux-multisource-dfir-lab project efficiently.

The goal is not to redesign the project. The goal is to:

- finish bounded refactors,
- run and document experiments,
- update simple project documentation,
- draft thesis LaTeX fragments from validated outputs.

## Global rules

- Prefer minimal diffs.
- Preserve behavior unless the task explicitly allows behavior change.
- Do not introduce new frameworks, abstractions, or broad architecture changes.
- Do not add more tests unless strictly required to confirm an actual breakage.
- Do not mix stages in one task.
- Do not scan the whole repository unless the current stage explicitly requires it.
- Read only:
   1. `ai/IDENTITY.md`
   2. `ai/ROUTING.md`
   3. the current stage `CONTEXT.md`
   4. explicitly named task files

- Use each stage `output/` directory as the handoff point.
- LaTeX writing is allowed only after validated experiment outputs and/or documentation exist.
- This workspace is local-only and not part of the thesis deliverable.

## Read order

Always read in this order:

1. `IDENTITY.md`
2. `ROUTING.md`
3. current stage `CONTEXT.md`
4. files explicitly listed by the task

If a file is not required by the current stage, do not load it.
