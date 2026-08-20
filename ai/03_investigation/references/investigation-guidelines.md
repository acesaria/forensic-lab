# Investigation guidelines

> ICM reference — migrated 2026-08-20 from the repo-root `GUIDELINES.md` during
> the public-surface cleanup. Authoring guidance for producing the
> `docs/investigations/<scenario>/<run_id>/runme_*.md` notebooks. Stable;
> update carefully. Reporting rules and status vocabulary remain in the
> repo-root `../../archive/METHODOLOGY.md` (public, cited by the accepted case reports).

Read this file before performing an investigation or creating or editing a
Runme investigation notebook.

## Scope and method

- Produce a concise educational investigation, not an exhaustive examination.
- Select the most useful observations and stop when the investigation question
  is answered.
- Prefer source-aware DFIR tools over generic byte or text processing. For
  filesystem work, use TSK commands such as `mmls`, `fsstat`, `ifind`, `ffind`,
  `fls`, `istat`, `icat`, `blkls`, `blkcalc`, and `blkcat` when they directly
  answer the question.
- Use `grep`, `sed`, `awk`, `xxd`, regular expressions, and shell pipelines only
  for small display or validation tasks that a forensic tool cannot answer
  directly.
- Apply KISS: use short sequential steps and do not add speculative analysis,
  helpers, abstractions, or automation.

## Identifying a run

`shared/experiments/<run_id>/` holds every started run, including verify,
failed, and `--no-acquire` validation runs, not only investigable ones.
Before investigating, confirm what `run_id` actually is:

- **Verify** (`{distro}_verify_{ts}`): a disposable `setup`-time pipeline
  self-test, not an experiment record. It has no `manifest.json` at all and
  is deleted automatically after a successful probe; one still on disk means
  a prior probe failed and it is kept only for debugging. Never investigate
  it.
- **Validation-only** (`--no-acquire`): `manifest.json` has
  `"acquisition_requested": false` and no `dumps/` directory. Proves the
  scenario executed; not a forensic experiment.
- **Failed**: `manifest.json` has `"status": "failed"` with `failed_phase`
  set to `"scenario"` or `"acquisition"`.
- **Real acquired run** (the only kind eligible for investigation):
  `manifest.json` has `"status": "completed"` and
  `manifest.json.artifacts.acquisition_manifest` set, alongside
  `dumps/acquisition.json`.

Older `shared/investigations/<run_id>/` trees predating the `derived/
<source>/` convention above (`*-worklog.md`, `commands.txt`, `SHA256SUMS`)
are superseded, gitignored, and carry no provenance; leave or prune them
freely.

## Shell history and Linux log examination

- Every disk investigation performs a bounded lookup for command-history
  files belonging to the relevant user accounts and root. Examine metadata
  and content when present. Untimestamped history preserves command
  text/order only; it does not establish per-command time, successful
  execution, or completeness.
- Every disk investigation inventories the principal Linux logs available
  under `/var/log` and the persistent systemd journal. Examine only logs
  relevant to the technique, users, services, and bounded case window.
  Typical candidates include `auth.log`, `syslog`, `kern.log`, and
  `audit.log` when present; names and availability vary by distribution.
- Prefer the timeline investigation for broad temporal correlation and
  structured journal parsing. Do not duplicate large log output in the disk
  notebook.
- Keep run-root `command_log.jsonl` and `terminal_transcript.txt` classified
  as scenario provenance/validation, not disk-image forensic evidence.

## Runme style

- Use ordinary, readable Bash. Avoid functions, arrays, complex loops, and
  dense pipelines when a direct command is sufficient.
- Use descriptive uppercase `SNAKE_CASE` variable names. Reuse `RUN_ID`,
  `RUN_DIR`, and `INV_DIR` for the same common paths across notebooks; use
  source-specific names for different concepts.
- Follow each command block with the heading `**Output**`, then a brief
  interpretation or limitation. Do not qualify the heading as selected,
  reviewed, complete, or similar.
- Save broad output in derived files and show only the bounded portion useful
  to the educational point in the notebook.
- Keep observations, interpretations, and scenario-fact validation distinct.

## Cross-cell variable propagation

If a Bash variable assigned in one Runme cell is needed by a later cell, export
it from the producer cell with an explicit self-assignment:

```bash
PRELOAD_INODE="..."
export PRELOAD_INODE="$PRELOAD_INODE"
```

Use one explicit `export NAME="$NAME"` statement per cross-cell variable. Keep
cell-local variables as ordinary assignments.
