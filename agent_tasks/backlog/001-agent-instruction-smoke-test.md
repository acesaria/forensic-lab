# Task: Agent Instruction Smoke Test

Read `PROJECT_CONTEXT.md` and `AGENTS.md` first.

## Objective

Verify that repo-level and agent-specific instruction files no longer contain
divergent project truth.

## Scope

Instruction files only.

## Files to Inspect

- `PROJECT_CONTEXT.md`
- `AGENTS.md`
- `CLAUDE.md`
- `.codex/CONTEXT.md`
- `.codex/RULES.md`
- `.codex/agent-cleaner.md`
- `.github/copilot-instructions.md`
- `.github/instructions/*.instructions.md`
- `.claude/commands/audit.md`

## Forbidden Changes

- Do not modify implementation code.
- Do not modify README.
- Do not rewrite optional Claude skills.

## Expected Output

A short report listing any remaining duplicate, stale, or conflicting project
truth and the smallest proposed fixes.

## Done Criteria

- Every agent-specific file either points to `PROJECT_CONTEXT.md` / `AGENTS.md`
  or contains only path-scoped guidance.
- No file repeats a conflicting VM mutation, scenario status, or detection
  terminology claim.
