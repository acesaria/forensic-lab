# CLAUDE.md

Read `AGENTS.md` and `PROJECT_CONTEXT.md` first. Keep changes small and
inspect the relevant files before editing. Do not duplicate their content here.

## Orchestration

The main agent (Fable) orchestrates: plan, decompose, synthesize, keep own
context lean.

- Reasoning-heavy phase (architecture, hard debugging, algorithm design) →
  `deep-reasoner` subagent (Opus).
- Mechanical, well-specified work → `fast-worker` subagent (Sonnet).
- Fresh perspective / second opinion → Codex (`/codex:*` commands or
  `codex exec` via Bash). Treat as a peer engineer, not a reviewer.
- High-stakes decision → task deep-reasoner and Codex on the same problem in
  parallel, independently (don't show either the other's answer); synthesize.
- Delegation has a cold-start cost (subagents re-derive context): if a task
  is smaller than its handoff, do it inline.
