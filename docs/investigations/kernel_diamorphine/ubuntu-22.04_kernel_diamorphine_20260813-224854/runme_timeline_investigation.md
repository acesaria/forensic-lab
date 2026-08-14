---
cwd: ../../../..
shell: bash
---

# Diamorphine timeline investigation — Runme notebook

__Run:__ `ubuntu-22.04_kernel_diamorphine_20260813-224854`

**Scope:** bounded Plaso examination of the accepted **disk** image, answering
the concealment-versus-cold-timeline question — the Diamorphine LKM hides a
directory and a note from live directory listings (its `getdents` interposition),
but the powered-off disk image records their creation regardless. This notebook
states what the cold timeline establishes about **when** the concealed artifacts
and the module appeared, and what it **cannot** establish about the hiding
mechanism.

The case (`runme_case_summary.md`) is memory-dominant and fixed Filesystem and
Timeline as **out of scope**: "offline disk would expose the hidden files, as in
the Father case, but was not examined here." This notebook is exactly that
deferred disk examination. The kernel-memory targets are **D01–D04** as fixed in
the case summary; the timeline is applicable only to the disk-observable facets
of D01/D02, and the hooking targets D03/D04 remain memory bounded negatives that
the cold disk cannot change. Because this re-opens a scope the case summary
closed, T-05 marks its statuses **proposed** and lists the reconciliation for a
human.

No `vol3_timeliner.txt` was produced for this case (memory-dominant kernel run),
so there is no memory-timeline cross-acquisition comparison section; the memory
findings are compared against the existing memory notebook instead.

## T-00 - Case boundary and two Plaso extractions

Two stores exist under `derived/timeline/`:

- **`timeline_curated.plaso`** — the **primary, documented method**: a targeted
  collection produced by the project runner
  (`orchestrator/forensics/plaso_runner.py`) with `default_linux_filter()`,
  created by this notebook.
- **`timeline.plaso`** — a pre-existing **unfiltered control**: the `linux`
  parser preset, `--partitions all`, no path filter. (For this run the broad
  store was pre-produced under the name `timeline.plaso`; it is the unfiltered
  control here, the role `father.plaso` plays in the Father case. See the
  recommended edits in T-05 about the cross-notebook naming.)

```bash {"name":"T-00-Case-Boundary","promptEnv":"never"}
set -euo pipefail

RUN_ID='ubuntu-22.04_kernel_diamorphine_20260813-224854'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
ACQUISITION="$RUN_DIR/dumps/acquisition.json"
DISK="$RUN_DIR/dumps/disk/evidence_disk.E01"
TIMELINE_DIR="$INV_DIR/derived/timeline"
PLASO="$TIMELINE_DIR/timeline_curated.plaso"
CONTROL="$TIMELINE_DIR/timeline.plaso"
export RUN_ID RUN_DIR INV_DIR ACQUISITION DISK TIMELINE_DIR PLASO CONTROL

jq -r '{disk_sha256: .disk_image.sha256,
        disk_verify: .disk_image.verification.status,
        disk_prep: .disk_preparation,
        mem_sha256: .memory_image.sha256}' "$ACQUISITION"
log2timeline --version
```

**Output**

```text {"ignore":"true"}
{
  "disk_sha256": "52370debcb9bc15ef812eec2db154912cd9ea32c4f91896362d3a4b8eaaca04c",
  "disk_verify": "completed",
  "disk_prep": "powered_off",
  "mem_sha256": "75edc2d3970f22445181e76ace1c93f49837a39f5fad5ee1d0087e19d66b0446"
}
plaso - log2timeline version 20260512
```

The disk image verified at acquisition and was acquired powered-off. Examination
is read-only; all writes land under `derived/timeline/`.

### T-00a - Primary extraction via the project runner (curated)

```bash {"name":"T-00a-Curated-Extraction","promptEnv":"never"}
set -euo pipefail

[[ -s "$PLASO" ]] || python3 - <<'PY'
from pathlib import Path
from orchestrator.forensics.plaso_runner import run_log2timeline, default_linux_filter

RUN_ID = "ubuntu-22.04_kernel_diamorphine_20260813-224854"
disk = Path(f"shared/experiments/{RUN_ID}/dumps/disk/evidence_disk.E01")
storage = Path(f"shared/investigations/{RUN_ID}/derived/timeline/timeline_curated.plaso")
run_log2timeline(
    disk_path=disk,
    storage_path=storage,
    # runner default extended with `utmp` for the session-bracketing query (T-03c);
    # default_linux_filter() is the project include/exclude path filter.
    parsers="text/bash_history, text/syslog, text/syslog_traditional, systemd_journal, filestat, utmp",
    file_filter=default_linux_filter(),
)
PY

pinfo -v "$PLASO" 2>/dev/null | sed -n '/Command line arguments/,/Preferred encoding/p'
echo '--- events per parser ---'
pinfo "$PLASO" 2>/dev/null | sed -n '/Events generated per parser/,/Total/p' | grep -E ':[[:space:]]+[0-9]+|Total'
echo '--- warnings ---'
pinfo "$PLASO" 2>/dev/null | grep -iE 'No warnings stored|warnings' | head -1
sha256sum "$PLASO"
```

**Output**

```text {"ignore":"true"}
    Command line arguments : /home/anto/.local/bin/log2timeline --logfile
                             /tmp/plaso-log-lz37ve2z/log2timeline.log --parsers
                             text/bash_history, text/syslog,
                             text/syslog_traditional, systemd_journal,
                             filestat, utmp --hashers none --partitions all
                             --file-filter
                             /home/anto/linux-multisource-dfir-lab/orchestrator/forensics/filters/linux_common.yaml
                             --storage-file
                             shared/investigations/ubuntu-22.04_kernel_diamorphine_20260813-224854/derived/timeline/timeline_curated.plaso
                             shared/experiments/ubuntu-22.04_kernel_diamorphine_20260813-224854/dumps/disk/evidence_disk.E01
  Parser filter expression : text/bash_history, text/syslog,
                             text/syslog_traditional, systemd_journal,
                             filestat, utmp
Enabled parser and plugins : filestat, systemd_journal, text/bash_history,
                             text/syslog, text/syslog_traditional, utmp
        Preferred encoding : UTF-8
--- events per parser ---
            filestat : 9189
  syslog_traditional : 4125
     systemd_journal : 3131
                utmp : 22
               Total : 16467
--- warnings ---
No warnings stored.
07723a044bbd5b3896250aa2a500cf76bcf952f9eb30157c0f5aedbb8443fc9c  timeline_curated.plaso
```

**Why this parser set and this filter.** The parsers target the artifact classes
a loadable-kernel-module rootkit case turns on: `filestat` MAC times to date the
staged `.ko` and the concealed directory and note; the two syslog formats and the
systemd journal for the `insmod` invocation and the kernel taint messages; `utmp`
for the operator session. The path filter is `linux_common.yaml`
(`orchestrator/forensics/filters/linux_common.yaml`): it **includes** `/tmp`
(where this scenario stages everything), `/var/log`, `/etc`, and shared objects;
it **excludes** bulky low-value trees. The concealed artifacts and the module
file all live under `/tmp`, so the filter is a bound on noise, not on this case's
evidence — tested in T-04. This is a **declared targeted-collection bound**,
repeated in T-05 beside every negative that depends on it. The runner's tempdir
`--logfile /tmp/plaso-log-lz37ve2z/…` is fixed inside this store but differs on a
fresh regeneration.

### T-00b - Unfiltered control extraction (timeline.plaso)

```bash {"name":"T-00b-Unfiltered-Control","promptEnv":"never"}
set -euo pipefail

pinfo -v "$CONTROL" 2>/dev/null | sed -n '/Command line arguments/,/Enabled parser/p' | head -5
echo '--- event sources | total events ---'
pinfo "$CONTROL" 2>/dev/null | grep -E 'Total : [0-9]+'
echo '--- events per parser (control) ---'
pinfo "$CONTROL" 2>/dev/null | sed -n '/Events generated per parser/,/Total/p' | grep -E ':[[:space:]]+[0-9]+' | grep -v 'Total'
echo '--- extraction warnings (log2timeline.out) ---'
grep -i 'Number of warnings' "$TIMELINE_DIR/log2timeline.out"
```

**Output**

```text {"ignore":"true"}
    Command line arguments : /home/anto/.local/bin/log2timeline --status-view
                             none --partitions all --storage-file
                             shared/investigations/ubuntu-22.04_kernel_diamorphine_20260813-224854/derived/timeline/timeline.plaso
                             shared/experiments/ubuntu-22.04_kernel_diamorphine_20260813-224854/dumps/disk/evidence_disk.E01
  Parser filter expression : linux
--- event sources | total events ---
Total : 79430
               Total : 310300
--- events per parser (control) ---
         apt_history : 2
                dpkg : 81
            filestat : 302939
  syslog_traditional : 4125
     systemd_journal : 3131
                utmp : 22
--- extraction warnings (log2timeline.out) ---
Number of warnings generated while extracting events: 2.
```

The control was deliberately unfiltered so that a later curated negative cannot
be dismissed as "not collected". Its two warnings are `<No parser>`
`cannot convert NaN to integer` on two gzip console-font files
(`/usr/share/consolefonts/*.psf.gz`), unrelated to the scenario. The three log
parsers (`syslog_traditional` 4,125, `systemd_journal` 3,131, `utmp` 22) return
identical counts in both stores; the filter only reduced `filestat`
(302,939 → 9,189).

## T-01 - Bounded scenario window

```bash {"name":"T-01-Window","promptEnv":"never"}
set -euo pipefail

WINDOW="$TIMELINE_DIR/d-t01-scenario-window.jsonl"
export WINDOW
jq -r '{scenario_started_at: .timestamps.scenario_started_at,
        scenario_ended_at: .timestamps.scenario_ended_at}' "$RUN_DIR/manifest.json"

[[ -s "$WINDOW" ]] || psort -q --status_view none --output_time_zone UTC \
  -o json_line -w "$WINDOW" "$PLASO" \
  "timestamp >= DATETIME('2026-08-13T20:48:54+00:00') and timestamp < DATETIME('2026-08-13T20:48:56+00:00')"
printf 'window_events=%s\n' "$(wc -l <"$WINDOW")"
```

**Output**

```text {"ignore":"true"}
{
  "scenario_started_at": "2026-08-13T20:48:54.090Z",
  "scenario_ended_at": "2026-08-13T20:48:55.249Z"
}
window_events=59
```

The treatment spans ~1.16 s (`20:48:54.090`–`20:48:55.249`). The query window is
the two whole seconds `20:48:54`–`20:48:56` UTC as an ISO-8601 `DATETIME()`
half-open interval on `timestamp` (syntax from `psort -h`, version 20260512).

## T-02 - Event-family inventory in the window

```bash {"name":"T-02-Event-Families","promptEnv":"never"}
set -euo pipefail
jq -r '.data_type' "$WINDOW" | sort | uniq -c | sort -rn
```

**Output**

```text {"ignore":"true"}
     32 fs:stat
     14 syslog:line
     12 systemd:journal
      1 linux:utmp:event
```

Filesystem MAC times dominate; the syslog and journal lines carry the `insmod`
and kernel taint records; one utmp record falls in the window. `syslog:line`
here is the `syslog_traditional` output (`text/syslog` produced 0 events).

## T-03 - Concealment versus the cold timeline

### T-03a - Technique-led discovery of the concealed artifacts

Question: does the cold disk record files that a live `getdents`-hooking rootkit
would hide, and when were they created? Discovery is **location-first** — files
with a Creation Time inside the scenario window under `/tmp` — not by any known
name. What would count as an answer: one or more window-created files under
`/tmp` that are candidates for concealment.

```bash {"name":"T-03a-Concealed-Discovery","promptEnv":"never"}
set -euo pipefail
# Location-only: Creation Time in the window, under /tmp. No name, no keyword.
jq -r 'select(.data_type=="fs:stat" and .timestamp_desc=="Creation Time" and (.filename|startswith("/tmp/")))
       | [(.timestamp/1000000|floor|strftime("%H:%M:%S"))+"."+((.timestamp%1000000|tostring)), .filename, .inode] | @tsv' \
  "$WINDOW" | sort -u
```

**Output**

```text {"ignore":"true"}
20:48:54.176000	/tmp/diamorphine.ko	74173
20:48:54.180000	/tmp/diamorphine_secret_dir	258128
20:48:54.204000	/tmp/diamorphine_secret_dir/diamorphine_secret_file.txt	258129
```

Location-first discovery returns exactly three window-created `/tmp` objects: a
kernel module `diamorphine.ko` (inode 74173), a directory
`diamorphine_secret_dir` (258128), and a note
`diamorphine_secret_file.txt` (258129) inside it. **Posterior validation:** the
directory and note names match the disclosed scenario facts
(`/tmp/diamorphine_secret_dir`, the hidden note) — a name confirmation *after*
technique-led discovery, not a locator. The cold disk records all three plainly,
though the loaded rootkit's `getdents` interposition would hide the directory and
note from a live `ls`.

### T-03b - When they appeared, and the ordering (concealed inodes)

```bash {"name":"T-03b-Concealed-Ordering","promptEnv":"never"}
set -euo pipefail

INODES="$TIMELINE_DIR/d-t03-concealed-inodes.jsonl"
export INODES
[[ -s "$INODES" ]] || psort -q --status_view none --output_time_zone UTC \
  -o json_line -w "$INODES" "$PLASO" \
  "inode == 74173 or inode == 258128 or inode == 258129"
jq -r '[(.timestamp/1000000|floor|strftime("%H:%M:%S"))+"."+((.timestamp%1000000|tostring)),
        .timestamp_desc, .filename, .inode] | @tsv' "$INODES" | sort
```

**Output**

```text {"ignore":"true"}
20:48:54.176000	Content Modification Time	/tmp/diamorphine.ko	74173
20:48:54.176000	Creation Time	/tmp/diamorphine.ko	74173
20:48:54.176000	Metadata Modification Time	/tmp/diamorphine.ko	74173
20:48:54.180000	Creation Time	/tmp/diamorphine_secret_dir	258128
20:48:54.204000	Content Modification Time	/tmp/diamorphine_secret_dir	258128
20:48:54.204000	Creation Time	/tmp/diamorphine_secret_dir/diamorphine_secret_file.txt	258129
20:48:54.204000	Metadata Modification Time	/tmp/diamorphine_secret_dir	258128
20:48:54.208000	Content Modification Time	/tmp/diamorphine_secret_dir/diamorphine_secret_file.txt	258129
20:48:54.208000	Metadata Modification Time	/tmp/diamorphine_secret_dir/diamorphine_secret_file.txt	258129
20:48:54.240000	Last Access Time	/tmp/diamorphine_secret_dir	258128
20:48:54.272000	Last Access Time	/tmp/diamorphine.ko	74173
20:48:54.364000	Last Access Time	/tmp/diamorphine_secret_dir/diamorphine_secret_file.txt	258129
```

**What the timeline establishes:** the `.ko` is written first (`54.176`), then
the secret directory (`54.180`), then the note (`54.204`) with the directory's
`mtime` updated as the note is linked in — a coherent `stage → mkdir → write`
sequence spanning ~30 ms. As T-03c shows, the module is only `insmod`-ed at
`54.274`, so the concealed files are **created before the concealment mechanism
is loaded** (staged, then hidden). **What the timeline cannot establish:** that
the directory or note was ever hidden, or by what mechanism — MAC times record
existence and time, not `readdir`/`getdents` interposition. That hiding is a
runtime property the memory examination addressed (and recorded the active hook
as a bounded negative, D03/D04); the cold timeline does not change it.

### T-03c - Module load, taints, and the operator session

Question: does the disk record the module load and its kernel taints, and when?
This dates D01 (loading) and carries D02's taints from an independent source.
Discovery is by kernel/module log content, not the module name.

```bash {"name":"T-03c-Module-Load","promptEnv":"never"}
set -euo pipefail

LOAD="$TIMELINE_DIR/d-t03-module-load-syslog-journal.jsonl"
export LOAD
[[ -s "$LOAD" ]] || psort -q --status_view none --output_time_zone UTC \
  -o json_line -w "$LOAD" "$PLASO" \
  "(data_type is 'syslog:line' or data_type is 'systemd:journal') and timestamp >= DATETIME('2026-08-13T20:48:54+00:00') and timestamp < DATETIME('2026-08-13T20:48:56+00:00')"
# Sub-second from the journal: the insmod invocation and the two kernel taints.
jq -r 'select(.data_type=="systemd:journal")
       | select((.message)|test("insmod /tmp|out-of-tree module taints|module verification failed"))
       | [(.timestamp/1000000|floor|strftime("%H:%M:%S"))+"."+((.timestamp%1000000|tostring)),
          (.message|gsub("lab-ubuntu-22 ";"")|.[0:120])] | @tsv' "$LOAD" | sort

UTMP="$TIMELINE_DIR/d-t03-utmp-sessions.jsonl"
export UTMP
[[ -s "$UTMP" ]] || psort -q --status_view none --output_time_zone UTC \
  -o json_line -w "$UTMP" "$PLASO" "data_type is 'linux:utmp:event'"
echo '--- operator session bracket (scenario-boot cluster; type 7 USER / 8 DEAD) ---'
jq -r 'select(.timestamp >= 1786654120000000)
       | [(.timestamp/1000000|floor|strftime("%H:%M:%S"))+"."+((.timestamp%1000000|tostring)),
          (.type|tostring), (.username//"-"), (.terminal//"-")] | @tsv' "$UTMP" | sort
```

**Output**

```text {"ignore":"true"}
20:48:54.273979	[sudo, pid: 1046]  labuser : TTY=pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/sbin/insmod /tmp/diamorphine.ko
20:48:54.279631	[kernel] diamorphine: loading out-of-tree module taints kernel.
20:48:54.279687	[kernel] diamorphine: module verification failed: signature and/or required key missing - tainting kernel
--- operator session bracket (scenario-boot cluster; type 7 USER / 8 DEAD) ---
20:48:44.633035	2	reboot	system boot
20:48:51.994207	1	runlevel	system boot
20:48:52.380187	5	-	hvc0
20:48:52.380187	6	LOGIN	hvc0
20:48:52.380861	5	-	tty1
20:48:52.380861	6	LOGIN	tty1
20:48:53.647971	7	labuser	pts/0
20:48:54.461198	8	-	pts/0
20:49:24.097278	1	shutdown	system boot
```

The journal dates the load sub-second: `sudo insmod /tmp/diamorphine.ko`
(PID 1046) at `20:48:54.273979`, then the kernel taints `~5.7 ms` later —
`loading out-of-tree module taints kernel` (`54.279631`) and
`module verification failed: signature … missing - tainting kernel`
(`54.279687`). These two messages are the disk-side record of the exact taints
memory reported (`OOT_MODULE, UNSIGNED_MODULE` via `modxview`). The `utmp`
`labuser`/`pts/0` session (`USER 20:48:53.648` → `DEAD 20:48:54.461`) brackets
the `.ko` staging (`54.176`), the concealed-file creation (`54.180`–`54.204`) and
the `insmod` (`54.274`): all of it happened inside one interactive operator
session on `pts/0`. (The `syslog_traditional` copy of the taint lines is
1-second-granular and preserves the kernel monotonic stamp `[13.550839]`; the
journal supplies the wall-clock sub-second time.)

## T-04 - Comparison and controls

### What the timeline adds over the memory-only case

The case summary examined memory only and marked Filesystem/Timeline out of
scope. Against the memory notebook, the disk timeline **adds**:

- **the dating and provenance of the module load** — `sudo insmod
  /tmp/diamorphine.ko` and the kernel taints at `20:48:54.27–.28`, which the
  memory image (a later, single snapshot) cannot time;
- **the concealed artifacts themselves, dated** — the secret directory and note
  the live rootkit hides, created `20:48:54.180`–`.204`, plainly visible in the
  cold image; and
- **an independent record of the taints** (next paragraph).

It does **not** add anything about the hooking mechanism: the cold disk has no
view of the syscall table or `ftrace`, so D03/D04 remain exactly the memory
bounded negatives.

**Taints — corroboration across independent acquisitions.** The
`OOT_MODULE, UNSIGNED_MODULE` taint is recorded in two separately acquired
images: the disk `kern.log`/journal (`out-of-tree module taints kernel`;
`module verification failed … tainting kernel`) and memory `modxview`
(`taints OOT_MODULE,UNSIGNED_MODULE`). Two acquisitions of one kernel event
agree — corroboration that excludes single-source error. They are **not**
flattened: the disk log is a persisted write dated to the load instant
(`54.279`), memory is the live taint flags at acquisition; each carries what the
other cannot (load time versus in-RAM residency and the `lsmod` hiding).

### T-04a - Filter-sensitivity control

Question: did the curated filter drop anything relevant inside the window?

```bash {"name":"T-04a-Filter-Sensitivity","promptEnv":"never"}
set -euo pipefail

CTRLWIN="$TIMELINE_DIR/d-t04-window-unfiltered-control.jsonl"
export CTRLWIN
[[ -s "$CTRLWIN" ]] || psort -q --status_view none --output_time_zone UTC \
  -o json_line -w "$CTRLWIN" "$CONTROL" \
  "timestamp >= DATETIME('2026-08-13T20:48:54+00:00') and timestamp < DATETIME('2026-08-13T20:48:56+00:00')"

echo '--- events by family: curated | control ---'
paste <(jq -r '.data_type' "$WINDOW"   | sort | uniq -c) \
      <(jq -r '.data_type' "$CTRLWIN"  | sort | uniq -c)
echo '--- concealed artifacts among files the filter dropped ---'
comm -23 <(jq -r 'select(.data_type=="fs:stat")|.filename' "$CTRLWIN" | sort -u) \
         <(jq -r 'select(.data_type=="fs:stat")|.filename' "$WINDOW"   | sort -u) \
  | grep -Ei 'diamorphine|secret|\.ko$' || echo 'NONE dropped'
echo '--- dropped-file count + a representative sample ---'
comm -23 <(jq -r 'select(.data_type=="fs:stat")|.filename' "$CTRLWIN" | sort -u) \
         <(jq -r 'select(.data_type=="fs:stat")|.filename' "$WINDOW"   | sort -u) | wc -l
comm -23 <(jq -r 'select(.data_type=="fs:stat")|.filename' "$CTRLWIN" | sort -u) \
         <(jq -r 'select(.data_type=="fs:stat")|.filename' "$WINDOW"   | sort -u) \
  | grep -E '\.bash_logout|/usr/bin/sudo$|sudoers\.so' | head
```

**Output**

```text {"ignore":"true"}
--- events by family: curated | control ---
     32 fs:stat            64 fs:stat
      1 linux:utmp:event     1 linux:utmp:event
     14 syslog:line         14 syslog:line
     12 systemd:journal     12 systemd:journal
--- concealed artifacts among files the filter dropped ---
NONE dropped
--- dropped-file count + a representative sample ---
23
/home/labuser/.bash_logout
/usr/bin/sudo
/usr/libexec/sudo/sudoers.so
```

The filter dropped **23** in-window `fs:stat` files and **zero**
`syslog`/`journal`/`utmp` events. Every dropped item is read-access noise on
stock binaries (`/usr/bin/sudo`, the sudo helper objects, python bytecode) or a
user dotfile. **No concealed artifact was omitted** — `diamorphine.ko` and both
`diamorphine_secret_*` objects are retained. The targeted collection narrowed
noise, not evidence.

### T-04b - A bounded negative worth asking

Question: does the cold disk carry the module's runtime `procfs`/`sysfs`
presence — the "In sysfs `True`" that memory `modxview` reported? What would count
as an answer: any `filestat` row under `/sys/module` or `/proc/modules`.

```bash {"name":"T-04b-Sysfs-Negative","promptEnv":"never"}
set -euo pipefail

SYSNEG="$TIMELINE_DIR/d-t04-sysfs-procfs-negative.jsonl"
export SYSNEG
psort -q --status_view none --output_time_zone UTC \
  -o json_line -w "$SYSNEG" "$PLASO" \
  "filename contains '/sys/module' or filename contains '/proc/modules'"
printf 'sysfs_procfs_rows=%s\n' "$(wc -l <"$SYSNEG")"
```

**Output**

```text {"ignore":"true"}
sysfs_procfs_rows=0
```

**Bounded negative.** `/sys` and `/proc` are runtime pseudo-filesystems not
present on the ext4 disk image, so the module's sysfs presence — one half of the
memory `modxview` discrepancy — has **no** cold-disk counterpart. This is why the
timeline observes D02's *taints* but not its *view discrepancy* (T-05). It is a
source-scope bound, not a claim the module was absent.

## T-05 - Synthesis, proposed statuses, limitations, stopping condition

The cold timeline answers the concealment question cleanly: it dates the
concealed directory and note (`20:48:54.180`–`.204`) and the module load
(`insmod` `54.274`, kernel taints `54.279`), and it shows the concealed files
were **staged before** the module that hides them was loaded. It cannot see the
hiding itself — no `readdir`/`getdents` interposition, no syscall-table or
`ftrace` state is on a powered-off disk — so the hooking targets D03/D04 stay
exactly the memory bounded negatives, unchanged. The single new cross-source fact
is corroboration of the module **taints** across two independent acquisitions
(disk log + memory `modxview`).

### Proposed timeline statuses for D01–D04

The case summary fixed Timeline as **out of scope** for this memory-dominant
case (all `--`). Following the concealment angle, this notebook examined the disk
timeline and finds it contributes. The statuses below are therefore **proposed**,
for a human to reconcile with the fixed matrix (see recommended edits).

| Target | Memory (fixed) | Proposed Timeline | Durable locator / explicit bound |
|---|---|---|---|
| **D01** — module loaded but hidden from `lsmod` | O | **P** | Journal `sudo … COMMAND=/usr/sbin/insmod /tmp/diamorphine.ko` (PID 1046) `20:48:54.273979` + kernel `loading out-of-tree module taints kernel` `20:48:54.279631`; `filestat` `.ko` inode `74173` Creation Time `20:48:54.176000` (`d-t03-concealed-inodes.jsonl`). **Missing element:** the runtime hiding from `lsmod` (a memory fact; memory D01 O). |
| **D02** — view discrepancy and taints | O | **P** | Journal/`kern.log` `out-of-tree module taints kernel` (`OOT_MODULE`) + `module verification failed: signature … missing - tainting kernel` (`UNSIGNED_MODULE`), `20:48:54.279` (`d-t03-module-load-syslog-journal.jsonl`); corroborates memory `modxview` taints across independent acquisitions. **Missing element:** the `procfs`/`sysfs` view discrepancy — `/sys/module`,`/proc/modules` absent from the cold disk (`d-t04-sysfs-procfs-negative.jsonl`, 0 rows). |
| **D03** — active syscall-table hook | N | **--** | Not applicable: a powered-off disk has no syscall table to examine. The memory bounded negative (`check_syscall`) stands unchanged. |
| **D04** — active ftrace hook | N | **--** | Not applicable: no `ftrace` state on a cold disk. The memory bounded negative (`CheckFtrace`) stands unchanged. |

Beyond D01–D04, the timeline dates the **concealed directory and note** — the
objects of Diamorphine's `getdents` hiding — at `20:48:54.180`/`.204`. These are
not a separately enumerated target; they are the concrete "concealment versus the
cold timeline" evidence: present and dated on disk, hidden on the live host.

### Declared bounds

- **Curated collection bound (T-00a):** parser set + `linux_common.yaml`. Tested
  in T-04a — no material omission in-window; the concealed artifacts are all
  under the included `/tmp`.
- **Source-scope bound (T-04b):** `/sys` and `/proc` are runtime-only; their
  absence from the disk is why D02 is `P` (taints) not `O` (no view discrepancy).
- **Hooking is memory-only (T-03b, D03/D04):** MAC times and logs record
  existence, load time and taints, not interception. The cold disk cannot promote
  or refute the memory hook negatives.
- **Same-acquisition replication:** `filestat`, syslog and journal all read the
  one disk image; their agreement is parser-level replication. The only
  independent acquisition compared here is memory (the taint corroboration).
- **No `vol3_timeliner.txt`** was produced for this run, so there is no
  memory-timeline event comparison; the memory comparison is against the memory
  notebook's plugin findings.

### Stopping condition

Met: five bounded, individually justified `psort` queries (window; concealed
inodes; module-load syslog+journal; utmp; the `/sys`+`/proc` negative) plus the
filter-sensitivity control answered the concealment-and-dating question and fixed
proposed timeline statuses for D01–D04. No wholesale export was made. **TTF: not
measured** — no `TTF-START`/`TTF-FIRST` lines were recorded prospectively for
this examination.

### Recommended human edits (do not edit these files automatically)

This notebook does not modify `runme_case_summary.md`, `COMPARATIVE_RESULTS.md`,
or any LaTeX file.

1. **`runme_case_summary.md`, "Metric contract".** It states Filesystem/Timeline
   are "out of scope … offline disk … was not examined here." The timeline **has
   now been examined** (this notebook). Decide whether to re-open Timeline
   applicability for D01/D02. If yes, apply edits 2–4; if the case is to remain
   memory-only by design, cite this notebook as a supplementary disk examination
   and leave the matrix, noting the timeline results here.
2. **Matrix D01 / D02, Timeline column.** From `--` to **P** with the locators in
   the T-05 table (D01: `insmod`+taint+`.ko` crtime; D02: kernel taints, with the
   sysfs/procfs negative as the missing element). D03/D04 stay `--`.
3. **`U/C/S` and the independence caveat.** Under the fixed target-level
   contract, re-scoping Timeline makes both D01 and D02 mechanically **C**:
   Timeline finds a proper subset (`P`) and Memory finds the full compound
   target (`O`). Recompute the source and union partitions as `U/C/S: 0/2/0`
   (Timeline O 0 / P 2 / N 0 / TF 0, Found 2/2; Memory counts unchanged);
   `X` stays 0. This mechanical classification is not itself an independence
   claim. Only D02's **taint** attribute is the same attribute corroborated by
   disk `kern.log` and memory `modxview` across independent acquisitions. D01's
   Timeline result dates loading but does not establish the compound target's
   runtime hiding facet.
4. **Concealed-artifact note.** Record in the matrix or conclusion that the disk
   timeline dates `/tmp/diamorphine_secret_dir` (inode 258128) and its note
   (258129) at `20:48:54.18–.20`, the artifacts the live `getdents` hook hides —
   the concrete concealment-versus-cold-timeline result — while the hook itself
   remains the D03/D04 memory negative.
5. **`COMPARATIVE_RESULTS.md`.** The Diamorphine row currently shows Timeline out
   of scope. If edits 2–3 are applied, update its Timeline cell to `0/2/0/0;
   2/2 (100%)` and reflect the taint corroboration in the cross-source cell; TTF
   remains `not measured`.
6. **Cross-notebook naming.** For this run the unfiltered broad store is named
   `timeline.plaso` while the curated store this notebook created is
   `timeline_curated.plaso` — inverted from the Father run, where `timeline.plaso`
   is the curated store and `father.plaso` the control. Consider renaming for a
   uniform convention (e.g. control `diamorphine.plaso`, curated `timeline.plaso`)
   so the two cases read the same; purely cosmetic, no result depends on it.
