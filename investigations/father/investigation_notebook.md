# Father — memory and timeline phase notebook

This is documentation only; it explains `runme_memory.sh` and
`runme_timeline.sh` and is not executed itself.

**Why one notebook, not two.** The task structure allows either a separate
`memory_notebook.md`/`timeline_notebook.md` pair or one combined notebook
when the split would just duplicate the RUN_ID contract and output-location
explanation. Here it would: both phases share the same run against the same
image/memory pair, the same "read-only on `shared/experiments/`, write-only
under `shared/investigations/<RUN_ID>/derived/`" contract already spelled
out once in `disk_notebook.md`, and both are short enough that a shared
"Case setup" section followed by two clearly separated phase sections is
more legible than two near-identical files. Disk stayed a separate file
because it is proportionally larger (six distinct sub-steps, a recovery
precondition rule, its own significant tool-behavior limitation) and is
the phase most directly reused/quoted by the historical reference report.

## Shared RUN_ID contract

```bash
./investigations/father/runme_memory.sh RUN_ID
./investigations/father/runme_timeline.sh RUN_ID
# or
RUN_ID=father-u22-20260818-02 ./investigations/father/runme_memory.sh
```

- Input: `shared/experiments/<RUN_ID>/` — read-only.
- Output: `shared/investigations/<RUN_ID>/derived/{memory,timeline}/`
  (`raw/`, `investigation-summary.md`, `findings.json`, `metrics.json` each),
  plus `shared/investigations/<RUN_ID>/logs/memory-commands.log`.
- Run order: disk, then memory, then timeline. The timeline phase's
  persistence-inode-ordering query is optional and reads the disk phase's
  `findings.json` if present; it skips cleanly (recorded, not silently
  dropped) if the disk phase has not been run for this `RUN_ID` yet.

---

## Memory phase (`runme_memory.sh`)

### Purpose

Independently check, from the memory image, what the disk phase can only
establish statically: whether the malicious library was actually mapped
into a process, what process tree and command lines were live at
acquisition, whether a socket consistent with the backdoor existed, and
whether any bash history was recoverable from process memory.

### Tooling

Volatility 3, offline, against the project's own ISF layout convention
(`orchestrator/forensics/vol_runner.py`):
`<isf_dir>/<distro_family>_<kernel_release>.json`. The script derives
`distro_family` and `kernel_release` from this run's own `manifest.json`
(`platform.distro_id`, `platform.kernel`) and looks for an exact filename
match under `shared/isf/`; if none exists it falls back to the newest
`<family>_*.json` and prints a warning (recorded as a limitation in the
summary, not silently substituted).

Command form (matches `vol_runner.py`'s own wrapper, so this is a verified,
not invented, invocation):

```bash
vol3 -f "$MEM_RAW" -s "$ISF_DIR" -r json <plugin>
```

### Plugin scope (fixed, per the task's intended scope)

| Plugin | What it shows | What it does NOT prove alone |
|---|---|---|
| `linux.proc.Maps` | Per-process memory mappings — whether `selinux.so.3` is mapped into some process's address space | Which process, or that any hook fired |
| `linux.pslist` | The visible process list | That a process is not hidden by a DKOM-style rootkit (Father is userland/`LD_PRELOAD`, so this is a weaker concern here than for `kernel_diamorphine`, but still not a completeness proof) |
| `linux.pstree` | Parent/child relationships | Causation — a child under `sshd` is consistent with, not proof of, the backconnect chain |
| `linux.psaux` | Command lines | Full argv is only as complete as what the kernel retained: truncation is possible |
| `linux.sockstat` | Open sockets | A matching port alone does not prove a *backdoor* socket rather than the legitimate service on the same port (Father's design point) |
| `linux.bash` | Recovered bash history from process memory | History atoms can be partial/absent if the shell already exited or the region was reclaimed |

Each plugin's raw JSON lands at `derived/memory/raw/<plugin-slug>.json`; a
failed plugin still writes an empty/stderr file and is recorded as
`"status": "failed"` in `findings.json` — never silently dropped, and never
reported the same as a genuine negative result.

### Where outputs land

- `derived/memory/raw/{proc-maps,pslist,pstree,psaux,sockstat,bash}.json`
  (+ matching `.stderr.txt` per plugin)
- `derived/memory/findings.json` — plugin status, row counts, and
  observation strings (see `metrics/memory_metrics.py`)
- `derived/memory/metrics.json` — see schema below
- `derived/memory/investigation-summary.md`

### Metrics schema (`metrics/memory_metrics.py`)

- `process_visibility` — row count from `linux.pslist`, or `"unknown ..."`
  if the plugin failed.
- `process_tree_available` — whether `linux.pstree` produced rows.
- `library_mapping` — plugin status plus a pointer to the observation in
  `findings.json`; deliberately **not** a boolean "library was loaded"
  claim — see What requires human interpretation, below.
- `socket_backdoor_observation` — `linux.sockstat` row count plus this run's
  manifest `scenario_facts.backdoor_connection.server_port` for manual
  cross-reference; never asserts the match itself.
- `bash_evidence` — `linux.bash` row count.
- `negative_or_unknown` — list of plugins that did not return `"ok"`.

### What requires human interpretation

- A `selinux.so.3` mapping row is *candidate* evidence the library loaded
  into a process; confirming *which* process, and correlating that PID with
  the disk phase's install event and the timeline phase's activation order,
  is a manual cross-phase step this script does not automate.
- A `linux.sockstat` row matching the manifest's backdoor port is not by
  itself proof of the backdoor: the same port may carry the legitimate
  service. Manual inspection of the raw row (owning process, local/remote
  address) is required.

### Limitations

- Offline analysis only.
- ISF-kernel mismatch causes `vol3` plugin failures with no partial output;
  a `"failed"` status must be read as `unknown`, not `absent`.
- `linux.bash` frequently returns 0 rows even when interactive commands ran
  — it depends on the shell process still existing in memory at
  acquisition; a 0-row result is recorded as a fact, not treated as a
  negative finding about interactive activity.

---

## Timeline phase (`runme_timeline.sh`)

### Purpose

Reconstruct event *order* across the disk image using Plaso, bounded to
this run's own scenario window, and check whether the persistence chain
(library install → preload configured → activation) is consistent with the
disk phase's static findings.

### Tooling

The project's own Plaso wrapper, **not** a hand-typed `log2timeline`/`psort`
invocation:

```python
from orchestrator.forensics.plaso_runner import run_log2timeline, default_linux_filter
run_log2timeline(disk_path=..., storage_path=..., file_filter=default_linux_filter())
```

`default_linux_filter()` resolves to
`orchestrator/forensics/filters/linux_common.yaml` — an include list
(`/etc`, `/var/log`, `/tmp`, `/var/tmp`, per-user `.bash_history`/`.ssh`,
`systemd`/`cron` units, shared objects under `/usr/lib`, `/lib`) and an
exclude list for bulky low-value trees. This is the project's declared
targeted-collection bound, applied identically for every run.

### Bounded queries

1. **Scenario window** — `psort` bounded to `[scenario_started_at,
   scenario_ended_at]` from this run's own `manifest.json`, rounded outward
   to whole seconds. This is the same pattern used in the historical
   reference timeline notebook (there called T-01), generalized so the
   bound comes from the current run's manifest rather than a literal
   timestamp.
2. **Persistence-inode ordering** (optional) — if
   `derived/disk/findings.json` exists for this `RUN_ID` (i.e. the disk
   phase already ran), query `psort` for events tied to the preload and
   library inodes it recorded. If the disk phase has not run yet, this step
   is skipped and the skip is recorded explicitly in
   `raw/persistence-inode-events.SKIPPED.txt` and in `findings.json`
   (`inode_query_skip_reason`) — never silently omitted.

### Where outputs land

- `derived/timeline/timeline.plaso` — the Plaso storage file itself.
- `derived/timeline/raw/window-events.jsonl`,
  `raw/event-family-counts.txt`, `raw/persistence-inode-events.jsonl`
  (when run).
- `derived/timeline/findings.json`, `metrics.json`,
  `investigation-summary.md`.

### Metrics schema (`metrics/timeline_metrics.py`)

- `bounded_window` — start/end/event count.
- `event_family_counts` — `data_type` histogram inside the window.
- `auth_or_execution_events` — count of window events whose `syslog:line`
  or `systemd:journal` message mentions `sudo`/`sshd`/`session`; `"unknown
  (no events in window)"` when the window is empty.
- `persistence_inode_ordering` — availability, event count, and the skip
  reason when unavailable.

### What requires human interpretation

- A surviving file's own MAC time does not necessarily date the activity
  that produced its *current* content — the historical reference run
  documented a case (`/etc/ld.so.preload`) where the surviving inode's MAC
  time postdated the journal-recorded configuration command by several
  seconds, consistent with a self-heal/rewrite at shutdown. This script
  reports the raw event set; it does not attempt that interpretation
  automatically.
- Event-family counts and the auth/execution count are descriptive, not a
  verdict — confirm any specific claim (e.g. "SSH was restarted during
  activation") by reading the actual message text in
  `raw/window-events.jsonl`.

### Limitations

- **Unfiltered control extraction not implemented.** The historical
  reference notebook also produced an unfiltered `father.plaso` control to
  prove the curated filter dropped no evidence in-window. This script does
  not reproduce that control — it would roughly double runtime for a check
  that, in the reference run, found nothing dropped. **TODO**, intentionally
  manual: re-run `run_log2timeline(..., file_filter=None)` by hand if a
  specific run's filter-sensitivity needs verifying.
- **Distro/journal-format specific.** The parser set
  (`plaso_runner.py`'s default:
  `text/bash_history, text/syslog, text/syslog_traditional,
  systemd_journal, filestat`) assumes a systemd-journald + rsyslog Ubuntu
  image. A distro with a different logging stack would need a different
  parser list — not covered here; adapting this script for another
  scenario/distro should treat the parser list as a variable to check, not
  assume.
- **ext4/jbd2 dependence carries over from the disk phase** wherever this
  phase's inode-ordering query depends on inode numbers the disk phase
  discovered.
