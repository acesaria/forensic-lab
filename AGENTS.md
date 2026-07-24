# AGENTS.md

Behavior contract for coding agents in forensic-lab. Read
PROJECT_CONTEXT.md first, then only the files the task needs.

## Hard invariants (never violate, regardless of task wording)

1. Deterministic scenario execution is required. Each run keeps a minimal
   manifest, append-only command log, and enough provenance to reproduce the
   controlled compromise.
2. VM power-state contract: memory = VM ON, disk = VM OFF; transitions stay in
   the orchestrator.
3. Acquired raw evidence is immutable. Disk images, memory images, raw TSK,
   Plaso, and Volatility exports keep hashes and provenance.
4. Tool failures and negative findings are explicit investigation results, not
   silent omissions.
5. Investigation is manual. Automatic detection, canonical matching, precision,
   recall, and reconstruction scoring are not current thesis deliverables.
6. Legacy detector/matcher code remains GT-blind until deleted: it must not read
   ground truth, artifact expectations, scenario internals, or instance values.

## Evidence reading discipline (token budget)

Raw evidence (timelines, bodyfiles, findings/*.jsonl, exported logs under
shared/) is large. Never load it whole into context.

1. Size before reading: `wc -l` / `ls -lh` first. Never `cat`, `less`, or
   open any file over 200 lines.
2. Filter, then read: use `rg`, `jq`, `awk`, or a short Python one-liner to
   reduce the file to the relevant slice (time window, source, event class,
   path pattern). Reason only over the filtered output.
3. Cap every command's output at 100 lines (`| head -n 100`). If the slice
   is bigger, narrow the filter instead of reading more.
4. Aggregate before inspecting: start from counts and histograms
   (events per source, per hour, per path prefix), then drill into the one
   or two buckets that matter.
5. Do not re-read a file already summarized in this session; reuse the
   summary.
6. Persist findings: append conclusions and the exact filter commands used
   to shared/results/<scenario>/investigation_notes.md so later sessions
   start from the notes, not from raw evidence.
7. Filters are scoped by time window and technique-level patterns
   (e.g. ld.so.preload, module load events), never by planted instance
   values from ground truth (see circularity rule above).

## Change rules

- Make the smallest diff that satisfies the request. Prefer deleting code
  over adding it; prefer editing an existing module over creating one.
- No new top-level modules, abstractions, dependencies, frameworks, or config
  keys without an explicit request in the task.
- Per-run behavior toggles are CLI flags, not edits to scenario source or
  config files.
- Scenarios use classic, well-documented techniques; do not add
  evasion-style plumbing or expand scenario scope.
- Never put a scenario instance value (planted path, filename, hash, IP,
  timestamp) into a detector rule, matcher alias, investigation checklist, or
  profile comparison shortcut. That is circularity.
- Do not reintroduce ToolFinding, DetectionClaim, canonical matching,
  automatic reconstruction, precision/recall metrics, or ruleset hashes as
  normative thesis requirements.
- Legacy code (see PROJECT_CONTEXT.md map) is frozen: no fixes, no tests,
  no extensions - deletion only, when a task asks for it.
- VM-facing changes are validated with `python cli.py run` on the live
  lab, not with mocked unit tests.

## Test policy

- Do not add or modify tests by default. Scenario changes are validated with
  syntax checks, existing relevant tests, and controlled VM smoke runs.
- Add one focused regression test only when explicitly requested or when
  fixing a concrete shared-runtime defect.
- Never add tests to legacy code.

## Python commands

Always use the repository virtual environment for Python and pytest commands:

`.venv/bin/python -m pytest`

Do not try the system `python` or `python3` first.

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
