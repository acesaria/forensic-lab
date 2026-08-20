# Notebook implementation — father, disk phase

## Task

Implement the reusable `RUN_ID`-parameterized Runme investigation notebook
for the Father scenario and execute its disk phase against
`father-u22-20260818-02`.

## Files changed

- `investigations/father/runme_investigate.md` — replaced the seed copy
  (hardcoded to the old reference run) with a generalized notebook: case
  setup (require `RUN_ID`, derive all paths, validate manifest/acquisition,
  create output dirs, write/update `investigation.json`, record tool
  versions) plus a fully implemented disk-examination phase. Memory and
  timeline sections are present as headers only, explicitly marked pending.
- `investigations/father/README.md` — updated to describe the current
  (generalized, partially implemented) state instead of the seed-file note.
- `shared/investigations/father-u22-20260818-02/investigation.json` —
  created/updated with run metadata and `phases.disk: "complete"`.

## Notebook structure

1. **Case setup** — validates `RUN_DIR`, `MANIFEST`, `ACQUISITION`, `DISK`,
   `MEM` all resolve before creating any output directory; records tool
   versions to `logs/tool-versions.txt`; writes `investigation.json`.
2. **Disk examination** (implemented, executed) — offset discovery via
   `mmls`, filesystem identity via `fsstat`, preload entry via
   `ifind`/`icat`/`istat`, installed-library hash comparison against the
   manifest, `/tmp` enumeration and per-inode metadata, and a precondition
   check before any deleted-object recovery attempt.
3. **Memory / Timeline / Findings** — stubbed, not yet implemented; each
   waits for review of the prior phase per the task's phase-gate
   requirement.

## Deviations from the initial plan, made while running

- `mmls`'s offset-selection `awk` needed a column-index fix (start sector is
  field 3 of a matching row, not field 2) — caught by seeing `fsstat`
  fail on the malformed first attempt.
- The `run()` command-logger originally piped its own announce line into
  the same pipe as the tool's output (`run cmd | tee out.txt`), which
  leaked "+ cmd" text into `d-00-fsstat.txt`. Fixed by writing the announce
  line straight to the log file instead of `tee`ing it to stdout.
- Whole-disk recursive `fls -r -p` did not descend into `/tmp` on this
  image build (confirmed: zero `/tmp/*` matches even though the bare `tmp`
  directory entry exists at the root). Switched to resolving `/tmp`'s own
  inode via `ifind -n /tmp` and listing that inode directly, which is more
  targeted and turned out to be necessary, not just a preference.
- `${LIB_PATH/#\/lib\//\/usr\/lib\/}` bash parameter-expansion syntax
  produced literal backslashes in this shell; replaced with `sed
  's#^/lib/#/usr/lib/#'`.

## Result — disk phase, `father-u22-20260818-02`

- Root partition offset: sector `227328` (Ext4, `cloudimg-rootfs`,
  unmounted properly) — independently rediscovered, not copied from the
  reference run (which happens to share the same offset structurally, but
  every value here comes from this run's own `mmls`/`fsstat`).
- `/etc/ld.so.preload` inode `74210`, content `/lib/selinux.so.3`.
- Installed library inode `74251`, SHA-256
  `87fece49fc15a48372a1ba76cf424755f9cfab6cce7e8073002757f7db2f0711`, exact
  match to the manifest's `rk.so` input hash. `istat` shows a timestomped
  `File Modified` (2026-01-30) against a true `Created`/`Inode Modified`
  (2026-08-18 20:55:2x CEST).
- `/tmp` (inode `1581`) holds `__malicious_recon` (74168) and
  `__malicious_harvest` (74171), both fully visible offline though hidden
  live; `/tmp/rk.so` absent, live or deleted.
- Deleted-object content recovery: **not run**. This run's
  `command_log.jsonl` has no `sync` before `rm -f -- /tmp/rk.so` (unlike the
  accepted reference run), so the documented precondition for
  journal/residual-block recovery is not met; recorded explicitly in
  `derived/disk/d-06-recovery-result.txt` and `report/disk.md`, not silently
  skipped or fabricated.

## Validations performed

- Read-only: no command wrote to `shared/experiments/father-u22-20260818-02/`.
- No repository-root artifacts created; every write landed under
  `shared/investigations/father-u22-20260818-02/`.
- Tool availability confirmed before use (`mmls`, `fsstat`, `ifind`, `icat`,
  `istat`, `fls`, `extundelete`, `ext4magic`, `vol3`, `log2timeline`/`pinfo`/
  `psort` all resolve on this host).
- Hash comparison (`d-03-installed-lib.sha256` vs `d-03-manifest-input.sha256`)
  performed and matched.

## Blockers

None. Stopping here per the task's phase-gate requirement — human review of
the disk phase before the memory phase begins.

## Next recommended step

On approval: implement and run the memory phase (Volatility 3 2.28.0 against
`shared/isf/ubuntu_5.15.0-179-generic.json`), starting from
`linux.proc.Maps` to find the library mapping technique-led (not from
scenario ground truth), following the same rediscovery discipline as the
disk phase.
