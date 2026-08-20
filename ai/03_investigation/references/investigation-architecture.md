# Investigation-layer architecture (decision of record)

Stable reference. Moved here from `ai/03_investigation/CONTEXT.md` during the
2026-08-20 ICM cleanup so CONTEXT stays short; the decisions below are still
authoritative. No run-specific findings belong here.

## Base architecture (2026-08-18 refactor)

As of 2026-08-18, `investigations/<scenario>/` no longer uses executable
Markdown (mixed prose + runnable shell blocks with `export`-based variable
propagation). That pattern was hard to execute reliably, reuse across
`RUN_ID` values, and explain in a thesis. It was replaced with:

- **Documentation-only Markdown notebooks** (`disk_notebook.md`, and either
  separate `memory_notebook.md`/`timeline_notebook.md` or one combined
  notebook when that avoids unnecessary duplication). Notebooks explain
  purpose, tool choice, the `RUN_ID` contract, output locations, what is
  rediscovered per run, what requires human interpretation, and limitations.
  They are never executed.
- **Plain Bash phase scripts** (`runme_disk.sh`, `runme_memory.sh`,
  `runme_timeline.sh`), one per phase, each a normal linear script
  (`set -euo pipefail`) accepting `RUN_ID` as `$1` or the `RUN_ID`
  environment variable:
  ```bash
  RUN_ID="${1:-${RUN_ID:-}}"
  : "${RUN_ID:?Usage: $0 RUN_ID}"
  ```
- **Small, focused metric helpers** (`investigations/<scenario>/metrics/*.py`)
  that consume a phase's own raw output/`findings.json` and write
  `metrics.json`. They never rerun a forensic tool.
- **Per-run derived outputs** under
  `shared/investigations/<RUN_ID>/derived/{disk,memory,timeline}/`, each with
  `raw/` (tool output), `findings.json`, `metrics.json`, and
  `investigation-summary.md`. This output-path convention (not
  `shared/derived/<RUN_ID>/`) is the repository's actual established
  convention.
- **Explicit limitations and human interpretation**, stated in both the
  notebook and each phase's generated `investigation-summary.md`.

Reference implementation: `investigations/father/`. Investigation workflows
for `ptrace_fa`, `kernel_diamorphine`, and `kernel_ebpf_badbpf` are not yet
present in this checkout. When added, reuse the understandable phase shape and
adapt scenario-specific questions/tool commands without building a generic
framework.

## Disk-phase architecture update (2026-08-19, Father only)

The Father scenario's **disk phase only** was further refactored from the
Bash `runme_disk.sh` + `metrics/disk_metrics.py` pair into a Python-orchestrated
Jupyter notebook. Father's memory and timeline phases still use the
Bash-phase-script architecture above; the other scenario workflows are not yet
implemented.

- `investigations/father/disk_investigation.ipynb` is now the disk phase's
  single canonical workflow: a linear, restartable notebook that invokes
  TSK/ext4 tools via `subprocess` (list-args, never `shell=True`), captures raw
  output, builds one findings dict, computes metrics from it, and renders
  `report/disk.md` from it.
- `investigations/father/investigation_utils.py` holds only small, reusable
  orchestration helpers (`resolve_run_paths`, `run_command`, parsers for known
  TSK text output, `write_report`); it is not a generic framework and does not
  reimplement any forensic tool.
- Output paths are unchanged from the Bash-phase convention:
  `shared/investigations/<RUN_ID>/derived/disk/{raw/,findings.json,metrics.json}`
  and `shared/investigations/<RUN_ID>/report/disk.md` — chosen so the timeline
  phase's existing read of the disk phase's `findings.json` keeps working.
- The prior `runme_disk.sh` and `metrics/disk_metrics.py` are kept, renamed to
  `.deprecated`, as historical reference only.
- This disk notebook added a real ext4 journal investigation the prior
  implementation never had: rather than stopping at "deleted-object recovery
  precondition: not-met", it independently checks the run's own ext4 journal
  (which commits on its own timer, not only on an explicit `sync`) for
  directory-entry/metadata corroboration, and explicitly distinguishes that
  (weaker) finding from full file-content recovery. See
  `investigations/father/disk_investigation.ipynb` Section 10 and
  `ai/03_investigation/output/disk-notebook-refactor.md`.

## Notebook tool-methodology convention (2026-08-19, Father disk notebook)

`investigations/father/disk_investigation.ipynb` cells must invoke standard
digital forensics CLI tools and methodologies (TSK/ext4 commands such as `fls`,
`ifind`, `icat`, `istat`, `jls`, `jcat`, ...) directly, rather than
reimplementing an equivalent check as custom Python or complex bash. When a cell
performs a specific, named DF technique, mark it with a short explicit comment
naming that technique (e.g. `# File Listing`, `# Path Resolution`,
`# Metadata Extraction`, `# Keyword Search`, `# File Recovery`), so the
technique stays visible next to the command performing it.

## Stage boundaries

- `ai/02_experiments` — runs/executes scenarios and acquires evidence
  (`shared/experiments/<RUN_ID>/`). Never re-runs acquisition; only reads it.
- `ai/03_investigation` (this stage) — forensic investigation phase scripts,
  notebooks, and metrics. Writes only under `shared/investigations/<RUN_ID>/`
  and `investigations/<scenario>/`.
- `ai/04_docs` — general README/project documentation, from this stage's
  validated `output/` handoffs. Does not re-derive forensic facts.
- `ai/05_thesis` — LaTeX fragments from validated `02`/`03`/`04` outputs. Never
  edits investigation code or scripts.
