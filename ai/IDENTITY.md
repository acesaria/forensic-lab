# Identity

This is the repository's internal AI coordination workspace for finishing and
stabilizing the linux-multisource-dfir-lab project efficiently. It is tracked
for agent handoffs, but it is not forensic evidence or a thesis deliverable.

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
- Enter through `ai/INDEX.md`; then read only the files in the order below.

- Use each stage `output/` directory as the handoff point.
- LaTeX writing is allowed only after validated experiment outputs and/or documentation exist.
- This workspace is not an authority for run-specific findings.

## Read order

Always read in this order:

1. `ai/INDEX.md`
2. `ai/IDENTITY.md`
3. `ai/ROUTING.md`
4. the current stage `CONTEXT.md`
5. files explicitly listed by the task

If a file is not required by the current stage, do not load it.
