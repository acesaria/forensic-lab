# Father investigation workflow

Reusable, `RUN_ID`-parameterized investigation for the `father`
(`userland_father_ldpreload`) scenario.

**Disk phase (current, canonical):** a Python-orchestrated Jupyter notebook.
**Memory and timeline phases (unchanged):** plain Bash phase scripts with
documentation-only Markdown notebooks. These two phases were out of scope
for the 2026-08-19 disk-focused refactor and are unmodified — see
`investigation_notebook.md`.

## Files

- `disk_investigation.ipynb` — **the disk phase's single canonical
  workflow.** A linear, restartable Python notebook: invokes TSK/ext4
  tools (`mmls`, `fsstat`, `ifind`, `icat`, `istat`, `fls`, `jls`, `jcat`,
  ...) via `subprocess` (list-args, never `shell=True`), captures raw
  output, builds one findings dict, computes metrics from it, and renders
  the final report from it. Includes a real ext4 journal investigation
  (Section 10) and an explicit, reasoned decision on `extundelete`/
  `ext4magic` (Section 11) — not just a `not-met` precondition stop.
- `investigation_utils.py` — small, reusable helpers imported by the
  notebook (`resolve_run_paths`, `run_command`, `save_raw_output`,
  `write_json`, `write_report`, `safe_sha256`, and a handful of parsers for
  known `mmls`/`fsstat`/`istat`/`fls` text formats). Orchestration glue
  only — it never reimplements a forensic tool.
- `disk_notebook.md` — **superseded**, documentation-only reference for the
  deprecated `runme_disk.sh` shell implementation. Kept for its TSK command
  explanations; see the banner at the top of the file.
- `runme_disk.sh.deprecated`, `metrics/disk_metrics.py.deprecated` — the
  prior disk-phase implementation (shell script + Python metrics helper).
  Renamed (non-executable, not importable by their old names) rather than
  deleted, so the history is inspectable. Do not run or import them.
- `investigation_notebook.md` — documentation for the memory and timeline
  phases (combined; unchanged by this refactor — see the notebook itself
  for why memory/timeline stay combined).
- `runme_memory.sh`, `runme_timeline.sh` — the memory and timeline phase
  scripts (unchanged). Each is a normal linear Bash script
  (`set -euo pipefail`), not executable Markdown.
- `metrics/{memory,timeline}_metrics.py` — small helpers that turn the
  memory/timeline phases' raw tool output into `metrics.json` (unchanged).
  They only parse existing output; they never invoke a forensic tool
  themselves.
- `history_seed_notebook.md` — the original executable-Markdown notebook,
  superseded 2026-08-18. Kept as reference only; its code fences are no
  longer runnable.

## Running a phase

Disk (current, canonical):

```bash
RUN_ID=father-u22-20260818-02 jupyter nbconvert --to notebook --execute \
    investigations/father/disk_investigation.ipynb
```

`RUN_ID` may also be passed by editing the first configuration cell if
running interactively in Jupyter; the notebook reads the `RUN_ID`
environment variable with the same accepted-run default either way. There
is no shell `export` propagation between cells — `RUN_ID` is a plain Python
variable set once in the first code cell and used by every cell after it.
Re-running the whole notebook (Kernel → Restart & Run All, or the
`nbconvert --execute` form above) is the supported way to re-run the disk
investigation for a different run.

Memory and timeline (unchanged):

```bash
./investigations/father/runme_memory.sh RUN_ID
./investigations/father/runme_timeline.sh RUN_ID
# or
RUN_ID=father-u22-20260818-02 ./investigations/father/runme_memory.sh
```

Run order: disk, then memory, then timeline (the timeline phase optionally
reads the disk phase's `findings.json` for inode-ordering queries, and
skips that one query cleanly if it isn't there yet — this still works
against the notebook-produced `findings.json`, which lives at the same
path the old shell script wrote to).

## Contract

- Input: `RUN_ID`, naming one completed run under
  `shared/experiments/<RUN_ID>/` (read-only; the disk notebook never writes
  there — see `resolve_run_paths`/`ensure_output_dirs` in
  `investigation_utils.py`).
- Disk phase output: `shared/investigations/<RUN_ID>/derived/disk/`
  (`raw/` for tool output, `findings.json`, `metrics.json`) and
  `shared/investigations/<RUN_ID>/report/disk.md`. Same paths the prior
  shell implementation used, so memory/timeline's existing
  `derived/disk/findings.json` read (in `runme_timeline.sh`) is unaffected.
- Memory/timeline phase output (unchanged):
  `shared/investigations/<RUN_ID>/derived/{memory,timeline}/`, each with
  `raw/`, `investigation-summary.md`, `findings.json`, and `metrics.json`;
  plus a command log under `shared/investigations/<RUN_ID>/logs/`.
- Every offset, inode, PID, socket, ISF file, and time window is
  rediscovered from that run's own evidence — nothing is a literal constant
  copied from a prior run.
- Deleted-object *content* recovery (residual/unallocated-block carving via
  `extundelete`/`ext4magic`) is only attempted when the run's own
  `command_log.jsonl` shows an explicit `sync` before the relevant `rm`; a
  `sleep` in the scenario's own pacing does not satisfy this. The disk
  notebook records the precondition status honestly either way, and —
  unlike the deprecated shell script — still investigates the ext4 journal
  for *metadata/directory-entry* corroboration even when that content
  recovery precondition is not met (ext4's `jbd2` journal commits on its
  own timer, independent of an explicit `sync`). See
  `disk_investigation.ipynb` Section 10 and its "Deleted-file recovery and
  journal evidence" discussion for the full reasoning and the distinction
  between the two.

## Reference material

The accepted historical runs under `docs/investigations/` (old long-form
run IDs) remain in place as reference/starting-point material only. They
are not the current investigation and are not migrated.
