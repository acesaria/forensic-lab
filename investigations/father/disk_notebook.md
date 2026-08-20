> **Superseded 2026-08-19.** This file documented the now-deprecated
> `runme_disk.sh` + `metrics/disk_metrics.py` shell/Python-script pair. The
> disk phase's canonical implementation is now
> `investigations/father/disk_investigation.ipynb` (a Python-orchestrated
> Jupyter notebook, using `investigation_utils.py` for small reusable
> helpers), which also adds a real ext4 journal investigation this
> generation of the disk phase never had. This file is kept only as
> reference for the underlying TSK command explanations, most of which
> still apply; do not treat the `runme_disk.sh` invocation examples below as
> runnable — see `investigations/father/README.md` for the current
> workflow.

# Father — disk phase notebook (historical, see banner above)

This is documentation only. It explains what the now-deprecated
`runme_disk.sh` did and why; it was never executed itself. The commands and
reasoning below carried over into `disk_investigation.ipynb`.

```text
./investigations/father/runme_disk.sh RUN_ID   # deprecated -- historical example only
# or
RUN_ID=father-u22-20260818-02 ./investigations/father/runme_disk.sh   # deprecated
```

## Purpose

Follow the `LD_PRELOAD` persistence path outward from `/etc/ld.so.preload` on
the read-only EWF disk image, confirm the installed library's identity by
hash, characterize concealment behavior visible offline, and check — without
assuming — whether the precondition for recovering the deleted staging
object (`/tmp/rk.so`) is met for this run.

## RUN_ID contract

- Input: `shared/experiments/<RUN_ID>/` — read-only. The script never writes
  there.
- Required files: `manifest.json`, `dumps/acquisition.json`,
  `dumps/disk/evidence_disk.E01`. Missing any of these stops the script
  before any output directory is created.
- Output: `shared/investigations/<RUN_ID>/derived/disk/`
  (`raw/` for tool output, `investigation-summary.md`, `findings.json`,
  `metrics.json`) and a command log at
  `shared/investigations/<RUN_ID>/logs/disk-commands.log`.

## What is rediscovered per run (never hardcoded)

- The root-partition sector offset, from `mmls` output (largest real
  partition slot).
- The `/etc/ld.so.preload` inode, from `ifind`.
- The installed library's path (read from the preload file's own content,
  not assumed) and inode, from `ifind`.
- Every `/tmp` entry and its inode, from `fls`/`ifind` addressed at `/tmp`'s
  own inode.
- The deleted-object recovery precondition, from this run's own
  `command_log.jsonl` — never copied from a prior run.

## Steps and why

1. **`mmls -i ewf`** — partition table. The largest real slot is the
   candidate root volume; `mmls` alone cannot prove this (GPT partition
   names are often blank on cloud images), only `fsstat` can.
2. **`fsstat -o <offset>`** — filesystem identity and clean-unmount status.
   A clean unmount matters for the recovery precondition below: cached
   writes had a normal chance to reach stable storage.
3. **`ifind`/`icat`/`istat` on `/etc/ld.so.preload`** — the technique-led
   entry point for an `LD_PRELOAD` case. Its content names the installed
   library.
4. **`ifind`/`icat`/`istat` on the installed library** — SHA-256 hash
   compared against the manifest's known input hash (identity), and MAC
   times compared against each other (timestomp detection: a modified time
   inconsistent with the created/inode-modified times).
5. **`/tmp` enumeration** — addressed by the directory's own inode
   (`ifind -n /tmp`), not by a whole-disk recursive `fls -r -p`. See
   Limitations below for why.
6. **Deleted `/tmp/rk.so` — precondition check, not recovery.** The script
   checks this run's own `command_log.jsonl` for an explicit `sync`
   immediately before the `rm -f -- /tmp/rk.so` entry. If absent, recovery
   is recorded as `not-met` with the reason stated. **This script does not
   implement the journal/residual-block recovery technique itself** — that
   is a deliberate scope boundary of this refactor (see Limitations).

## Where outputs land

- Raw command output: `shared/investigations/<RUN_ID>/derived/disk/raw/`
  (numbered files, e.g. `00-mmls.txt`, `03-installed-lib.sha256`).
- Structured facts: `derived/disk/findings.json` (machine-readable; the
  metrics helper consumes this, not the raw text).
- Metrics: `derived/disk/metrics.json` — see schema in
  `metrics/disk_metrics.py`.
- Human summary: `derived/disk/investigation-summary.md`.

## What requires human interpretation

- Hash identity proves the installed object is byte-for-byte the known
  input; it does not by itself prove any hook executed. That is the memory
  phase's contribution — cross-reference `metrics/memory_metrics.py`'s
  `library_mapping` observation.
- A timestomp flag (`mtime != crtime`) is a signal, not a verdict — confirm
  against the scenario's own disclosed steps (e.g. a `touch -r` call) when
  available, rather than treating the flag alone as proof of anti-forensic
  intent.
- Recovery precondition `not-met` means recovery was correctly *not
  attempted* for this run; it is not evidence the file never existed. Prior
  presence is established indirectly (e.g. an `install` command reading the
  source path recorded in `command_log.jsonl`), not by disk content
  recovery.

## Limitations (explicit)

- **`fls -r -p` `/tmp` non-descent.** A whole-disk recursive `fls -r -p` did
  not descend into `/tmp` on the originally inspected image (zero matches
  for any `/tmp/*` path, though the bare `tmp` entry was listed at the
  root). This script works around it by addressing `/tmp` through its own
  inode (`ifind -n /tmp`) directly. This is recorded as an observed
  tool/image behavior, not root-caused further here.
- **Recovery technique not implemented.** Even when the precondition is
  `met`, this script stops at recording that fact — it does not run
  `extundelete`/`ext4magic`/manual journal-carving. Implementing that
  technique (directory-entry journal history → journal inode recovery →
  residual-block hashing, as demonstrated for the historical reference run
  in `docs/investigations/userland_father_ldpreload/…/runme_disk_investigation.md`)
  is an intentionally manual next step, not automated by this refactor.
- **ext4/jbd2-specific.** The precondition check and any future recovery
  step assume ext4 with a journal (jbd2). A different filesystem would need
  different tooling entirely.
- **No log reading here.** `auth.log`/journal reading is deliberately out of
  scope for the disk phase; see the timeline notebook.
