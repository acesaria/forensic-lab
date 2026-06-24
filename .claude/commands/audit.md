Read PROJECT_CONTEXT.md and AGENTS.md first.

You are auditing the forensic-lab Python project. This command is an optional
task helper, not an independent source of project truth.

## Your task

Perform a focused review for the scope the user requested.

The audit output is a report/plan unless the user explicitly requests edits.

## Method

- Inspect only the files needed for the requested audit scope.
- Confirm current behavior from code, config, and tests before making claims.
- Preserve the VM power-state contract and GT-blindness boundaries.
- Treat YAML rules and DetectionClaim records as candidate evidence, not final verdicts.
- Do not run VM-facing commands unless the user explicitly approves it.
- Do not edit files unless the user explicitly asks for implementation changes.

## Report Format

Include:

- inspected files
- findings, ordered by severity
- proposed minimal changes
- intentionally unchanged areas
- open questions or human-review TODOs

For each bug or risk, use:

FILE: <path>
FUNCTION: <name>
SEVERITY: critical | warning | minor
DESCRIPTION: one clear sentence describing the bug
FIX: concrete minimal fix or next check

End by answering:

"This system may work, but is it too complex for the thesis deadline? Which part can be removed, flattened, or made explicit?"
