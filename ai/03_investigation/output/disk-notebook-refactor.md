# Father disk-phase refactor — Python-orchestrated notebook

Task: replace the fragmented `runme_disk.sh` + `metrics/disk_metrics.py` +
generated `investigation-summary.md` disk-phase implementation with one
Python-orchestrated Jupyter notebook, and actually investigate deleted-file
recovery / journal evidence instead of stopping at "precondition not met".
Disk phase only; memory and timeline phases and all other scenarios are
unmodified.

## 1. Files created, renamed, or modified

Created:

- `investigations/father/disk_investigation.ipynb` — the canonical disk
  workflow (15 sections per the task's required structure).
- `investigations/father/investigation_utils.py` — reusable helpers
  (`resolve_run_paths`, `run_command`, `save_raw_output`, `write_json`,
  `write_report`, `safe_sha256`, small TSK-output parsers,
  `check_command_log_precondition`).

Renamed (deprecated, not deleted — kept for history, no longer executable
or importable by their old names):

- `investigations/father/runme_disk.sh` → `runme_disk.sh.deprecated`
  (execute bit removed, deprecation banner added).
- `investigations/father/metrics/disk_metrics.py` →
  `metrics/disk_metrics.py.deprecated` (banner added).

Modified:

- `investigations/father/disk_notebook.md` — deprecation banner added at
  the top; content kept as historical TSK-command reference.
- `investigations/father/README.md` — rewritten to describe the disk
  notebook as canonical, memory/timeline as unchanged.
- `ai/03_investigation/CONTEXT.md` — added a "Disk-phase architecture
  update (2026-08-19, Father only)" section.

Regenerated (per-run derived output, not source code):

- `shared/investigations/father-u22-20260818-02/derived/disk/{raw/,findings.json,metrics.json}`
- `shared/investigations/father-u22-20260818-02/report/disk.md`
- `shared/investigations/father-u22-20260818-02/logs/disk-commands.log`

Not touched: `runme_memory.sh`, `runme_timeline.sh`,
`metrics/memory_metrics.py`, `metrics/timeline_metrics.py`,
`investigation_notebook.md`, `history_seed_notebook.md`, root README,
thesis files, experiment execution infrastructure.

## 2. Canonical workflow for future investigation

```bash
RUN_ID=<run_id> jupyter nbconvert --to notebook --execute \
    investigations/father/disk_investigation.ipynb
```

Or open the notebook in Jupyter and Kernel → Restart & Run All, editing the
`RUN_ID` line in the first code cell if not using the environment variable.
`RUN_ID` is a plain Python variable, read once in cell 2
(`RUN_ID = os.environ.get("RUN_ID", "father-u22-20260818-02")`); there is
no shell `export` propagation anywhere in this workflow.

Every path is derived from `RUN_ID` via `resolve_run_paths()`:
`shared/experiments/<RUN_ID>/{manifest.json,dumps/acquisition.json,dumps/disk/evidence_disk.E01,command_log.jsonl}`
(read-only input) →
`shared/investigations/<RUN_ID>/derived/disk/{raw/,findings.json,metrics.json}`
and `shared/investigations/<RUN_ID>/report/disk.md` (output). This matches
the pre-existing, already-established convention (verified from the prior
`runme_disk.sh`, `investigation.json`, and the accepted `report/disk.md`
before implementing) — not the task prompt's illustrative
`shared/derived/<RUN_ID>/metrics/disk.json` path, which does not match how
this repository's investigation outputs are actually organized.

## 3. Environment note

`nbformat`/`nbclient`/`ipykernel` were `pip install`ed into the existing
`.venv` to execute the notebook headlessly for validation (not added to
`requirements.txt` — out of scope for this task; a supervisor running the
notebook interactively only needs a Jupyter install with these).

## 4. Recovery/journal investigation actually executed (Section 9–11)

This is the substantive addition over the prior implementation, which
stopped at recording `recovery precondition: not-met`.

- **Precondition check** (`check_command_log_precondition`): this run's
  `command_log.jsonl` shows `rm -f -- /tmp/rk.so` with no `sync` in the
  preceding commands — status **not-met**. The scenario's `time.sleep(...)`
  calls (used for general pacing, confirmed by reading
  `scenarios/userland_father_ldpreload/runner.py`) are explicitly not
  treated as equivalent to a `sync`.
- **Live/deleted directory entry**: `fls -o <offset> -rd -p <image> <tmp_inode>`
  — empty. No live or deleted `rk.so` entry.
- **Journal investigation (executed, not skipped):**
  - `jls -o <offset> <image>` — 16,391 journal blocks enumerated, saved in
    full (`raw/15-jls.txt`).
  - Journal inode discovered from `fsstat` (`Journal Inode: 8`), sized via
    `istat` (67,108,864 bytes — 64 MiB), read in one bounded `icat` pass
    (not persisted as a 64 MB raw file; held in memory only for the search,
    then freed).
  - Searched for 5 known marker strings (`rk.so`, `__malicious_recon`,
    `__malicious_harvest`, `selinux.so.3`, `ld.so.preload`) by byte offset,
    mapped to 13 unique journal blocks.
  - Each hit block re-extracted individually via
    `jcat -o <offset> <image> 8 <block>` (TSK's own verified journal-block
    interface — checked against `jcat`'s usage output before use, not
    invented) and saved (`raw/17-jcat-block-*.txt`).
  - **Result: `rk.so` found** as a directory-entry filename string in
    journal block 862 (and others), alongside `__malicious_recon` and other
    genuine `/tmp` directory-entry names in the same block — this is ext4's
    automatic periodic journal commit (`jbd2`, independent of any
    application-level `sync`) having captured a `/tmp` directory data block
    from during the scenario window.
  - Checked for ELF magic bytes (`\x7fELF`) anywhere in the 64 MiB journal:
    **zero occurrences**. Interpreted (not just asserted) as consistent
    with ext4's default `data=ordered` journal mode, which journals
    metadata but not file *data* blocks — explained in the notebook, not
    invented as a generic claim.
  - **Conclusion recorded**: directory-entry/metadata corroboration =
    `confirmed`; file-content recovery = `not_observed`. These are reported
    as two distinct, differently-strong claims, not conflated.
- **extundelete/ext4magic**: both confirmed present on the host
  (`--version` checked, saved). **Not invoked** — reasoned explicitly in
  the notebook (Section 11): would need a raw (non-EWF) image conversion
  not performed in this pass, and the journal step above already
  establishes no recoverable file content exists to guide a targeted
  carve, so an unguided unallocated-space search was judged likely to
  produce an unreliable result. Recorded as
  `recovery_status: "available_but_not_run"` with the reason — not a
  negative recovery claim, and not silently omitted.

## 5. What was or was not recovered (for the accepted run,
`father-u22-20260818-02`)

- Recovered/confirmed: preload persistence chain, installed-library hash
  identity (exact match to manifest input), a timestomp signal on the
  library, both concealed `/tmp` artifacts (visible offline, hidden live),
  journal directory-entry corroboration of `rk.so`'s prior existence in
  `/tmp`.
- Not recovered: `rk.so`'s file content (neither from a live/deleted
  directory entry, nor from the journal, nor from an unallocated-block
  carve attempt — the last one not attempted, per above).

## 6. Validations performed

- `python3 -m py_compile investigations/father/investigation_utils.py` —
  pass.
- Notebook executed top-to-bottom with `nbclient.NotebookClient.execute()`
  against `RUN_ID=father-u22-20260818-02`; scanned all cell outputs for
  `output_type == "error"` afterward — none found.
- Confirmed `git status --short` before/after shows no changes under
  `shared/experiments/` (read-only input untouched) and no new files at
  the repository root.
- Confirmed `findings.json`, `metrics.json`, and `report/disk.md` are
  mutually consistent (spot-checked hash, precondition status, journal
  corroboration status, and the findings table against the underlying
  `findings.json` values).
- Re-derived the whole-disk `fls -r -p` `/tmp`-non-descent check per-run
  rather than assuming the historical limitation still holds: for this
  run's image, the recursive `fls` **does** list `tmp/__malicious_recon`
  and `tmp/__malicious_harvest` directly — the notebook detects and
  reports this per run instead of hardcoding the old assumption.
- Confirmed the journal/recovery section (Sections 9–11) executed for
  real, not stubbed: raw jcat/jls output files exist under
  `derived/disk/raw/`, and `findings.json`'s `journal` and
  `recovery_tooling` keys are populated from that real execution.

## 7. Known limitations (also recorded in the notebook/report itself)

- Hash identity proves byte-for-byte object identity, not that any hook
  executed (memory phase's contribution).
- A timestomp flag is a signal, not a verdict.
- Journal directory-entry corroboration is metadata evidence, materially
  weaker than file-content recovery — kept explicitly distinct in
  `findings.json` and the report.
- `extundelete`/`ext4magic` were not run against a raw image conversion in
  this pass — an explicit, reasoned TODO, not a negative result.
- ext4/`jbd2`-specific throughout; a different filesystem would need
  different tooling.
- No `auth.log`/systemd-journal log reading — that remains the timeline
  phase's contribution, out of scope here.

## 8. Blockers

None.

## 9. Next recommended step

Human review of this disk-phase result, then (if approved) the same
Python-notebook pattern could be considered for the memory/timeline phases
or the other three scenarios in a separate, explicitly-scoped task — not
undertaken here, per this task's disk-only boundary.
