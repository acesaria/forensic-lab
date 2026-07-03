# AGENTS.md

Behavior contract for coding agents in forensic-lab. Read
PROJECT_CONTEXT.md first, then only the files the task needs.

## Hard invariants (never violate, regardless of task wording)

1. GT-blindness: detectors, adapters, and YAML rules never read ground
   truth, artifact expectations, or scenario internals.
2. VM power-state contract: memory = VM ON, disk = VM OFF; transitions
   stay in the orchestrator.
3. DetectionClaim is candidate/supporting evidence, not a verdict.
4. Headline metrics score matched reconstruction, not raw findings.

## Change rules

- Make the smallest diff that satisfies the request. Prefer deleting code
  over adding it; prefer editing an existing module over creating one.
- No new top-level modules, abstractions, dependencies, frameworks, or
  config keys without an explicit request in the task.
- Per-run behavior toggles are CLI flags, not edits to scenarios.yaml or
  config files.
- Scenarios use classic, well-documented techniques; do not add
  evasion-style plumbing or expand scenario scope.
- Never put a scenario instance value (planted path, filename, hash, IP,
  timestamp) into a detector rule or matcher alias. That is circularity,
  and the leakage test will fail you.
- Legacy code (see PROJECT_CONTEXT.md map) is frozen: no fixes, no tests,
  no extensions - deletion only, when a task asks for it.
- VM-facing changes are validated with `python cli.py run` on the live
  lab, not with mocked unit tests.

## Test policy

- At most one focused test per behavior change, in an existing test file
  when one fits. No new fixtures, suites, or parametrized matrices unless
  the task asks.
- Never add tests to legacy code.

## Git

- Commit as the repository's configured identity. No AI attribution:
  no Co-Authored-By trailers, no AI mentions in commit messages.

## Definition of done

Every task response ends with these two lines:
- `Intentionally unchanged:` what you deliberately left alone and why.
- `Deletion candidates:` anything you noticed that could be removed
  (or `none`).

## Audits

When asked for an audit, produce a report (no edits) listing: inspected
files; findings ordered by severity; proposed minimal changes;
intentionally unchanged areas; open questions.
