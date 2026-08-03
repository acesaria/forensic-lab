# Agent instructions

This is the single entry point for repository agents working on **Linux
Multi-Source DFIR Lab**.

## Read in this order

1. Read this file.
2. Read `README.md` for stable scope and the current public repository surface.
3. Read `TODO.md` only when the task concerns status, priorities, or planning.
4. Read `METHODOLOGY.md` only for thesis, evidence, investigation, or reporting
   work.
5. Inspect the relevant source, tests, Git history, and task-specific documents.

Verify mutable implementation facts from source. Archived documents and
generated material under `shared/` are not standing instructions.

## Roles and authority

- Repository agents inspect, implement, review, validate, and report bounded
  work.
- The human approves decisions and commits, authorizes privileged or VM-facing
  actions, understands investigative commands, and owns forensic conclusions.
- Do not commit, push, run a scenario, invoke forensic tools, or perform a
  privileged action unless the task explicitly authorizes it.
- ChatGPT may supervise and frame tasks, but external context is not a source of
  current repository facts. Claude and other agents are optional support, not a
  workflow dependency.

## Invariants

- Controlled scenarios run only in isolated laboratory VMs.
- Keep scenario execution deterministic and retain the run manifest and
  append-only command log.
- Acquire memory while the VM is on and disk after the VM is off; lifecycle
  transitions remain in the orchestrator.
- Accepted evidence and raw exports are immutable. New examination output is a
  separate derived artifact with its own provenance.
- Scenario execution validation proves only that the treatment occurred. It is
  distinct from forensic discovery, observation, interpretation, and conclusion.
- Investigation and cross-source interpretation remain manual. Do not restore
  automatic detection, matching, scoring, or reconstruction as the current
  architecture.
- Never turn planted scenario paths, names, hashes, addresses, or timestamps into
  reusable detection logic or an undisclosed investigation shortcut.
- Record tool failures and valid negative observations explicitly and
  separately.

## Working rules

- Inspect `git status`, HEAD, and the relevant history before editing. If a task
  requires a clean worktree and tracked changes exist, stop and report them.
- Make the smallest coherent change. Prefer deletion and existing structures;
  do not add speculative abstractions, dependencies, configuration, tests, or
  documentation.
- Preserve unrelated work. Do not rewrite history or normalize operational
  identifiers merely because they still contain `forensic-lab`.
- Treat current source as authoritative for commands, paths, schemas, scenario
  keys, and supported platforms. Correct documentation drift instead of coding
  toward stale documentation.
- Use `.venv/bin/python` for repository Python and pytest commands.
- Add or change tests only when requested or when active behavior changes and a
  focused regression check is necessary.

## Evidence and investigation tasks

- Identify the exact run and verify its manifest, acquisition record, raw-tool
  status, and hashes before analysis.
- Size large artifacts before reading. Filter and aggregate first; never load a
  large raw export wholesale when a bounded query can answer the question.
- Start discovery from the technique, operating-system structures, and source
  semantics. Use disclosed scenario facts only for clearly labelled validation
  after candidate selection.
- Keep filesystem, timeline, and memory observations distinguishable. Cite exact
  immutable-run locators and record the command, rationale, and stopping
  condition for each examination step.
- Do not modify accepted evidence, raw exports, worklogs, reports, or comparative
  results unless the task explicitly places that artifact in scope.

## Validation and handoff

Validate in proportion to the change. Documentation-only work normally needs
`git diff --check`, path/link checks, bounded stale-reference searches, and a
scope review; it does not need implementation tests.

Report the changed files, checks and real results, limitations or unresolved
questions, intentionally unchanged areas, and any genuine deletion candidates.
