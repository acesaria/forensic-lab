# Investigation layer refactor — Father scenario

Task: replace the executable-Markdown investigation notebook
(`investigations/father/runme_investigate.md`) with plain Bash phase
scripts, documentation-only notebooks, and small metric helpers, re-runnable
per `RUN_ID` without hardcoded offsets/inodes/PIDs.

## 1. Final investigation file structure

```
investigations/father/
├── README.md                     (updated: describes current structure)
├── disk_notebook.md               (new: doc-only, disk phase)
├── investigation_notebook.md      (new: doc-only, memory + timeline phases, combined — see "why combined" below)
├── history_seed_notebook.md       (renamed from runme_investigate.md; deprecation header added, code fences neutralized to plain text)
├── runme_disk.sh                  (new: executable, disk phase)
├── runme_memory.sh                (new: executable, memory phase)
├── runme_timeline.sh              (new: executable, timeline phase)
└── metrics/
    ├── disk_metrics.py            (new)
    ├── memory_metrics.py          (new)
    └── timeline_metrics.py        (new)
```

**Why one combined notebook for memory + timeline, not two separate
files.** Both phases share the same `RUN_ID`/output-location contract
already stated in `disk_notebook.md`; splitting them into two more files
would mostly duplicate that contract text. Disk stayed its own file because
it has proportionally more distinct content (six sub-steps, a recovery
precondition rule, and the largest tool-behavior limitation) and is what
the historical accepted report quotes most directly. This reasoning is also
recorded at the top of `investigation_notebook.md` itself.

## 2. How to run each phase

```bash
./investigations/father/runme_disk.sh RUN_ID
./investigations/father/runme_memory.sh RUN_ID
./investigations/father/runme_timeline.sh RUN_ID
# or
RUN_ID=father-u22-20260818-02 ./investigations/father/runme_disk.sh
```

Run order: disk, then memory, then timeline. The timeline script's
persistence-inode-ordering query is the only cross-phase dependency: it
reads `derived/disk/findings.json` if present and skips that one query
(recorded explicitly, not silently) if the disk phase hasn't run yet for
that `RUN_ID`.

## 3. RUN_ID contract

Every script uses the same pattern (per the task's suggested form):

```bash
RUN_ID="${1:-${RUN_ID:-}}"
: "${RUN_ID:?Usage: $0 RUN_ID}"
```

Verified: all three scripts exit 1 with a usage message when `RUN_ID` is
unset, both with no argument and (spot-checked) via the environment-variable
form.

## 4. Output directory contract

**Deviation from the task's suggested path, made deliberately per the
task's own instruction to verify real conventions first.** The task's
example used `shared/derived/${RUN_ID}/`. The repository's actual,
already-established convention — confirmed from
`investigations/father/README.md` (pre-refactor), the existing
`shared/investigations/<RUN_ID>/investigation.json`, and the accepted
`shared/investigations/father-u22-20260818-02/report/disk.md` — is:

```
shared/investigations/<RUN_ID>/
├── derived/
│   ├── disk/{raw/, findings.json, metrics.json, investigation-summary.md}
│   ├── memory/{raw/, findings.json, metrics.json, investigation-summary.md}
│   └── timeline/{raw/, findings.json, metrics.json, investigation-summary.md, timeline.plaso}
├── logs/{disk,memory,timeline}-commands.log
├── investigation.json      (pre-existing, not modified by this refactor)
└── report/                 (pre-existing report/disk.md, not modified by this refactor)
```

This is the path convention actually implemented and validated. Inputs are
read only from `shared/experiments/<RUN_ID>/`; nothing is written there, and
nothing is written to the repository root (verified — see §Validation).

## 5. What was implemented

- Three linear Bash phase scripts (`runme_disk.sh`, `runme_memory.sh`,
  `runme_timeline.sh`), all `set -euo pipefail`, no metaprogramming, no
  executable Markdown.
- **Disk phase**: partition/filesystem discovery (`mmls`/`fsstat`),
  `/etc/ld.so.preload` + installed-library identity (`ifind`/`icat`/`istat`,
  SHA-256 vs. manifest input hash), `/tmp` enumeration addressed by inode
  (works around the known `fls -r -p` non-descent limitation), and a
  deleted-`/tmp/rk.so` recovery **precondition check** (reads this run's own
  `command_log.jsonl` for a `sync` immediately before the `rm`) — the
  recovery *technique itself* is intentionally not implemented (see §7).
- **Memory phase**: Volatility 3 offline, ISF resolved per-run from
  `manifest.json`'s `platform.distro_id`/`platform.kernel` against
  `shared/isf/<family>_<kernel>.json` (falls back to newest
  `<family>_*.json` with a recorded warning if no exact match), running
  `linux.proc.Maps`, `linux.pslist`, `linux.pstree`, `linux.psaux`,
  `linux.sockstat`, `linux.bash` — exact command form verified against
  `orchestrator/forensics/vol_runner.py`'s own wrapper. A failed plugin is
  recorded as `"status": "failed"`, never silently treated as a negative
  result.
- **Timeline phase**: uses the project's own
  `orchestrator/forensics/plaso_runner.py` (`run_log2timeline` +
  `default_linux_filter()`) rather than a hand-typed `log2timeline` line.
  Runs one bounded `psort` query per run — the scenario window taken from
  that run's own `manifest.json` timestamps, generalized from the pattern
  the historical reference notebook used with a literal timestamp — plus an
  optional inode-ordering query that consumes the disk phase's
  `findings.json`.
- Three metric helpers (`metrics/*_metrics.py`), each with a
  `--write-findings` mode (raw output → `findings.json`) and a default mode
  (`findings.json` → `metrics.json`). Neither mode invokes a forensic tool.
- `disk_notebook.md` and `investigation_notebook.md`: documentation-only,
  explain purpose/tooling/RUN_ID contract/output locations/rediscovered
  values/human-interpretation points/limitations for each phase.
- `history_seed_notebook.md`: the old `runme_investigate.md`, renamed, with
  a deprecation header and its executable code fences converted to plain
  `text` fences so it can no longer be run.
- `investigations/father/README.md`: rewritten to describe the current
  structure.
- `ai/03_investigation/CONTEXT.md`: updated with the architecture section
  and the four-stage boundary description (`02_experiments` /
  `03_investigation` / `04_docs` / `05_thesis`).

## 6. Validation performed — end-to-end, against `father-u22-20260818-02`

All three phases were actually executed against the real, already-accepted
run (data already existed on disk; this only added new derived output —
nothing in `shared/experiments/father-u22-20260818-02/` was modified,
confirmed with `git status --short` before and after, empty both times).

- `bash -n` on all three `.sh` files: pass.
- Missing-`RUN_ID` rejection: verified for all three scripts (exit 1, usage
  message to stderr, no output directory created).
- `python3 -m py_compile` on all three metric helpers: pass.
- `./runme_disk.sh father-u22-20260818-02`: completed; `findings.json`
  reproduces the accepted report's facts exactly — preload inode `74210`,
  library inode `74251`, SHA-256
  `87fece49fc15a48372a1ba76cf424755f9cfab6cce7e8073002757f7db2f0711`
  matching the manifest input, `__malicious_recon`/`__malicious_harvest`
  found in `/tmp`, deleted-`rk.so` recovery precondition `not-met` (matches
  the accepted `report/disk.md` finding for this run, which has no `sync`
  before its `rm`).
- `./runme_memory.sh father-u22-20260818-02`: completed; all six plugins
  returned `"ok"` (`linux.proc.Maps` 3909 rows incl. 10 referencing
  `selinux.so.3`, `linux.pslist`/`linux.psaux` 129 rows, `linux.pstree` 2
  rows, `linux.sockstat` 296 rows, `linux.bash` 0 rows — recorded honestly
  as 0, not omitted).
- `./runme_timeline.sh father-u22-20260818-02`: completed; extraction via
  the project's `plaso_runner`, bounded scenario-window query
  (`2026-08-18T18:54:59Z`..`2026-08-18T18:56:31Z`, derived from this run's
  own manifest) returned 582 events across `fs:stat`/`syslog:line`/
  `systemd:journal`; the optional inode-ordering query ran (disk phase's
  `findings.json` was already present) and returned 8 events.
- Confirmed no repository-root artifacts were created by any phase
  (`git status --short .` before/after limited to the pre-existing
  unrelated modified files already on this branch, plus the new files under
  `investigations/`, `ai/03_investigation/output/`, and
  `shared/investigations/father-u22-20260818-02/`).
- Grepped the three `.sh` scripts and three metric helpers for the old
  reference run's inode/offset/timestamp literals (`74210`, `74251`,
  `227328`, `20260813`, `ubuntu-22.04_userland_father_ldpreload_20260813`)
  — none present; every value in the scripts is derived from `$RUN_ID`,
  `mmls`/`ifind` output, `manifest.json`, or `command_log.jsonl` at runtime.

## 7. What remains TODO

- **Deleted-object content recovery technique** (journal directory-entry
  history → journal inode recovery → residual-block hashing) is
  **intentionally not implemented** in `runme_disk.sh`; the script stops at
  recording `met`/`not-met`/`unknown`. Implementing it is a manual step for
  a future run whose `command_log.jsonl` discloses a `sync` immediately
  before the relevant `rm` — see `disk_notebook.md`'s Limitations.
- **Unfiltered Plaso control extraction** (the historical reference
  notebook's `father.plaso`, used to prove the curated filter dropped
  nothing material in-window) is not reproduced by `runme_timeline.sh` —
  left as a manual, run-when-needed check (`investigation_notebook.md`
  Limitations).
- Vol3 memory metrics currently record row counts and raw-observation
  strings for `library_mapping` and `socket_backdoor_observation` rather
  than a computed pass/fail — deliberately, per the task's instruction not
  to claim a plugin "proves a finding by itself." Turning these into a
  scored verdict is future work, not part of this refactor.

## 8. What is intentionally manual

- Correlating a `linux.proc.Maps` mapping row with a specific PID and with
  the disk phase's install event.
- Confirming a `linux.sockstat` row is the backdoor rather than the
  legitimate service on the same port.
- Interpreting timestomp flags and MAC-time ordering against the
  scenario's own disclosed steps rather than accepting the flag at face
  value.
- Any deleted-object recovery attempt when the precondition is `met`.

## 9. Known limitations

- `/tmp` on this image build is not descended into by whole-disk recursive
  `fls -r -p`; `runme_disk.sh` works around it by addressing `/tmp`'s own
  inode directly (`ifind -n /tmp`) — recorded as an observed tool/image
  behavior, not root-caused further.
- ext4/jbd2-specific: the recovery precondition logic assumes an ext4
  filesystem with a journal.
- Memory phase depends on an exact-kernel ISF match; a fallback to the
  newest same-family ISF is used (and recorded) if no exact match exists,
  which is a source of potential misattribution for a kernel it wasn't
  built against.
- Timeline phase's parser set and journal reading assume systemd-journald +
  rsyslog on Ubuntu; not portable to a different distro's logging stack
  without changing the parser list.

## 10. Reuse for the other three scenarios

The phase-script shape (`runme_disk.sh`/`runme_memory.sh`/
`runme_timeline.sh` + `metrics/*.py` + notebooks) is scenario-agnostic in
structure; only the scenario-specific parts need adapting per scenario:

- **`kernel_diamorphine`**: disk phase's artifact list changes (kernel
  module presence/hash rather than a userland `.so`); memory phase would
  add kernel-module-listing plugins (e.g. `linux.check_modules` /
  `linux.hidden_modules` style detection) alongside the same
  `pslist`/`pstree`/`sockstat`/`bash` core; timeline phase's bounded-window
  pattern (manifest-derived start/end) is directly reusable unchanged.
- **`ptrace_fa`**: memory phase becomes the primary evidence source
  (ptrace-based injection is less disk-visible); disk phase may reduce to
  confirming what persists, if anything.
- **The second Father variant / other distros**: the RUN_ID contract, ISF
  resolution pattern, and Plaso wrapper usage are unchanged; only the ISF
  filename and parser-set adequacy need re-checking per distro (see §9).

In each case, copy `investigations/father/` as a starting layout, keep the
`metrics/` helpers scenario-specific (do not generalize into a shared
framework — the task explicitly excludes that), and write a new pair of
notebooks rather than parameterizing one notebook across scenarios.
