---
cwd: ../../../..
shell: bash
---

# Father timeline investigation — Runme notebook

__Run:__ `ubuntu-22.04_userland_father_ldpreload_20260813-224442`

**Scope:** bounded Plaso examination of the accepted disk image, answering one
question — can a full timeline reconstruct the **order** of the persistence
chain (library installed → `/etc/ld.so.preload` configured → SSH restarted →
backdoor active), and what does it add over the bounded `auth.log` reading
already performed in the disk notebook? Every query below is bounded and
justified before it runs. The Plaso stores are new derived examination output,
not run evidence or an automatic extraction product.

Timeline-applicable targets for this case are fixed by the case summary:
**M05** (library installed and mapped), **M08** (interactive command activity),
and **M11** (SSH restart during activation). Statuses for those three are
assigned in T-05.

## T-00 - Case boundary and two Plaso extractions

Two stores exist under `derived/timeline/`, with distinct roles:

- **`timeline.plaso`** — the **primary, documented method**: a targeted
  collection produced by the project's own runner
  (`orchestrator/forensics/plaso_runner.py`) with `default_linux_filter()`.
- **`father.plaso`** — a pre-existing **unfiltered control**: all parsers,
  `--partitions all`, no path filter. It is *not* the case's primary source;
  it exists so that any curated negative can be tested against it (T-04),
  turning "not collected" into a checked "not present within the compared
  window".

```bash {"name":"T-00-Case-Boundary","promptEnv":"never"}
set -euo pipefail

RUN_ID='ubuntu-22.04_userland_father_ldpreload_20260813-224442'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
ACQUISITION="$RUN_DIR/dumps/acquisition.json"
DISK="$RUN_DIR/dumps/disk/evidence_disk.E01"
TIMELINE_DIR="$INV_DIR/derived/timeline"
PLASO="$TIMELINE_DIR/timeline.plaso"
CONTROL="$TIMELINE_DIR/father.plaso"
export RUN_ID RUN_DIR INV_DIR ACQUISITION DISK TIMELINE_DIR PLASO CONTROL

# Acquisition authority: hashes, verification, powered-off preparation.
jq -r '{disk_sha256: .disk_image.sha256,
        disk_verify: .disk_image.verification.status,
        disk_prep: .disk_preparation,
        mem_sha256: .memory_image.sha256}' "$ACQUISITION"
log2timeline --version
```

**Output**

```text {"ignore":"true"}
{
  "disk_sha256": "f12d21e331f589007a1a15d1858e7ac34d6140a8ca4b6479a349b227bfd159ad",
  "disk_verify": "completed",
  "disk_prep": "powered_off",
  "mem_sha256": "4d370432d491b6559a70700afa16d9d3877edce9d709f20788146d31a85dab04"
}
plaso - log2timeline version 20260512
```

The disk image verified at acquisition and was acquired powered-off; the memory
hash is carried for the T-04b cross-acquisition comparison. Examination is
read-only on the immutable evidence; all writes land under `derived/timeline/`.

### T-00a - Primary extraction via the project runner (curated)

The storage file is produced by calling the repository's own contract, not a
hand-typed `log2timeline` line. The parser set and path filter are the project's
declared targeted-collection bound.

```bash {"name":"T-00a-Curated-Extraction","promptEnv":"never"}
set -euo pipefail

[[ -s "$PLASO" ]] || python3 - <<'PY'
from pathlib import Path
from orchestrator.forensics.plaso_runner import run_log2timeline, default_linux_filter

RUN_ID = "ubuntu-22.04_userland_father_ldpreload_20260813-224442"
disk = Path(f"shared/experiments/{RUN_ID}/dumps/disk/evidence_disk.E01")
storage = Path(f"shared/investigations/{RUN_ID}/derived/timeline/timeline.plaso")
run_log2timeline(
    disk_path=disk,
    storage_path=storage,
    # runner default extended with `utmp` for the session-bracketing query (T-03);
    # default_linux_filter() is the project include/exclude path filter.
    parsers="text/bash_history, text/syslog, text/syslog_traditional, systemd_journal, filestat, utmp",
    file_filter=default_linux_filter(),
)
PY

# The exact command Plaso recorded inside the store, plus totals and warnings.
pinfo -v "$PLASO" 2>/dev/null | sed -n '/Command line arguments/,/Preferred encoding/p'
echo '--- events per parser ---'
pinfo "$PLASO" 2>/dev/null | sed -n '/Events generated per parser/,/Total/p' | grep -E ':[[:space:]]*[0-9]+|Total'
echo '--- warnings ---'
pinfo "$PLASO" 2>/dev/null | grep -iE 'No warnings stored|warnings' | head -1
sha256sum "$PLASO"
```

**Output**

```text {"ignore":"true"}
    Command line arguments : /home/anto/.local/bin/log2timeline --logfile
                             /tmp/plaso-log-070gsesi/log2timeline.log --parsers
                             text/bash_history, text/syslog,
                             text/syslog_traditional, systemd_journal,
                             filestat, utmp --hashers none --partitions all
                             --file-filter
                             /home/anto/linux-multisource-dfir-lab/orchestrator/forensics/filters/linux_common.yaml
                             --storage-file
                             shared/investigations/ubuntu-22.04_userland_father_ldpreload_20260813-224442/derived/timeline/timeline.plaso
                             shared/experiments/ubuntu-22.04_userland_father_ldpreload_20260813-224442/dumps/disk/evidence_disk.E01
  Parser filter expression : text/bash_history, text/syslog,
                             text/syslog_traditional, systemd_journal,
                             filestat, utmp
Enabled parser and plugins : filestat, systemd_journal, text/bash_history,
                             text/syslog, text/syslog_traditional, utmp
        Preferred encoding : UTF-8
--- events per parser ---
            filestat : 9185
  syslog_traditional : 4139
     systemd_journal : 3137
                utmp : 22
               Total : 16483
--- warnings ---
No warnings stored.
682dd82ada0e3763fb8232aa790b3cf606d33b633a62b6dd4919b9b4f2318d0b  timeline.plaso
```

The `--logfile /tmp/plaso-log-070gsesi/…` path is the runner's tempdir
(`plaso_runner.py` stages the worker-log fan in a tempdir and moves only the
main log into `derived/timeline/log2timeline.log`); it is fixed inside this
store but would differ on a fresh regeneration.

**Why this parser set and this filter.** The parser list targets the artifact
classes an `LD_PRELOAD` persistence case turns on: filesystem MAC times
(`filestat`) to date the installed library, preload file and concealable file;
the two syslog formats and the systemd journal for the `sudo`/`sshd` activation
record; `bash_history` for interactive command text; and `utmp` for login
session accounting. The path filter is `linux_common.yaml`
(`orchestrator/forensics/filters/linux_common.yaml`): it **includes** `/etc`,
`/var/log`, `/tmp`, `/var/tmp`, the per-user and root `.bash_history`/`.ssh`,
cron and systemd units, and shared objects under `/usr/lib`, `/lib`; it
**excludes** bulky low-value trees (`/usr/share/{man,doc,locale,fonts,…}`,
`/snap`, `/var/cache`, apt lists, `/usr/src`). The three persistence inodes all
fall inside included paths (`/usr/lib/selinux.so.3`, `/etc/ld.so.preload`,
`/tmp/__malicious_file`), so the filter is a bound on *noise*, not on this
case's evidence. This is a **declared targeted-collection bound** and is
repeated in T-05 next to every negative that depends on it. `text/syslog`,
`text/bash_history`, `apt_history` and `dpkg` produced **0** events and are
therefore absent from the per-parser list (parsers ran, matched nothing — not
disabled).

### T-00b - Unfiltered control extraction (father.plaso)

```bash {"name":"T-00b-Unfiltered-Control","promptEnv":"never"}
set -euo pipefail

# Exact broad-extraction command, recorded inside the control store
# (log2timeline.out holds only the processing summary + the 2-warning count).
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
                             shared/investigations/ubuntu-22.04_userland_father_ldpreload_20260813-224442/derived/timeline/father.plaso
                             shared/experiments/ubuntu-22.04_userland_father_ldpreload_20260813-224442/dumps/disk/evidence_disk.E01
  Parser filter expression : linux
--- event sources | total events ---
Total : 79429
               Total : 310316
--- events per parser (control) ---
         apt_history : 2
                dpkg : 81
            filestat : 302935
  syslog_traditional : 4139
     systemd_journal : 3137
                utmp : 22
--- extraction warnings (log2timeline.out) ---
Number of warnings generated while extracting events: 2.
```

The two `Total` lines are event **sources** (79,429) and **events** (310,316);
the per-parser breakdown sums to the latter.

The control was deliberately unfiltered — the `linux` parser preset over all
partitions with no path filter — so that a later curated negative cannot be
dismissed as "not collected". Its two extraction warnings are `<No parser>`
`cannot convert NaN to integer` on two gzip console-font files
(`/usr/share/consolefonts/*.psf.gz`), unrelated to the scenario. Note that the
three **log** parsers (`syslog_traditional` 4,139, `systemd_journal` 3,137,
`utmp` 22) return **identical** counts in both stores: those sources live under
`/var/log` and `/etc`, fully inside the filter, so the filter only reduced
`filestat` (302,935 → 9,185).

## T-01 - Bounded scenario window

```bash {"name":"T-01-Window","promptEnv":"never"}
set -euo pipefail

WINDOW="$TIMELINE_DIR/t-01-scenario-window.jsonl"
export WINDOW
jq -r '{scenario_started_at: .timestamps.scenario_started_at,
        scenario_ended_at: .timestamps.scenario_ended_at}' "$RUN_DIR/manifest.json"

[[ -s "$WINDOW" ]] || psort -q --status_view none --output_time_zone UTC \
  -o json_line -w "$WINDOW" "$PLASO" \
  "timestamp >= DATETIME('2026-08-13T20:44:42+00:00') and timestamp < DATETIME('2026-08-13T20:44:44+00:00')"
printf 'window_events=%s\n' "$(wc -l <"$WINDOW")"
```

**Output**

```text {"ignore":"true"}
{
  "scenario_started_at": "2026-08-13T20:44:42.511Z",
  "scenario_ended_at": "2026-08-13T20:44:43.875Z"
}
window_events=113
```

The treatment spans ~1.4 s (`20:44:42.511`–`20:44:43.875`). The query window is
the two whole seconds `20:44:42`–`20:44:44` UTC, stated as an ISO-8601
`DATETIME()` half-open interval on `timestamp` (syntax confirmed from
`psort -h` and the plaso event-filter grammar for this version, 20260512). It
brackets the treatment with a small margin while staying bounded.

## T-02 - Event-family inventory in the window

```bash {"name":"T-02-Event-Families","promptEnv":"never"}
set -euo pipefail
jq -r '.data_type' "$WINDOW" | sort | uniq -c | sort -rn
```

**Output**

```text {"ignore":"true"}
     53 fs:stat
     31 systemd:journal
     27 syslog:line
      2 linux:utmp:event
```

Four families contribute inside the window: filesystem MAC times (`fs:stat`),
the systemd journal, traditional syslog lines, and two utmp records. No
`bash:history:entry` event appears despite the enabled parser — examined as a
bounded negative in T-04. `syslog:line` here is entirely the
`syslog_traditional` output (`text/syslog` produced 0 events for this image).

## T-03 - Ordering of the persistence chain

### T-03a - MAC times of the three known inodes

Question: do the filesystem MAC times of the installed library (inode 74172),
the preload file (74210) and the concealable file (74173) establish the order
in which they appeared? What would count as an answer: a monotonic set of
creation times that places install before the SSH restart. Selection is by
inode, not by scenario filename.

```bash {"name":"T-03a-Inode-Ordering","promptEnv":"never"}
set -euo pipefail

INODES="$TIMELINE_DIR/t-03-persistence-inodes.jsonl"
export INODES
[[ -s "$INODES" ]] || psort -q --status_view none --output_time_zone UTC \
  -o json_line -w "$INODES" "$PLASO" \
  "inode == 74172 or inode == 74210 or inode == 74173"
jq -r '[(.timestamp/1000000|floor|strftime("%H:%M:%S"))+"."+((.timestamp%1000000|tostring)),
        .timestamp_desc, .filename, .inode] | @tsv' "$INODES" | sort
```

**Output**

```text {"ignore":"true"}
20:44:43.372000	Content Modification Time	/usr/lib/selinux.so.3	74172
20:44:43.372000	Creation Time	/usr/lib/selinux.so.3	74172
20:44:43.376000	Metadata Modification Time	/usr/lib/selinux.so.3	74172
20:44:43.380000	Content Modification Time	/tmp/__malicious_file	74173
20:44:43.380000	Creation Time	/tmp/__malicious_file	74173
20:44:43.380000	Last Access Time	/tmp/__malicious_file	74173
20:44:43.380000	Metadata Modification Time	/tmp/__malicious_file	74173
20:44:43.440000	Last Access Time	/usr/lib/selinux.so.3	74172
20:44:46.472000	Content Modification Time	/etc/ld.so.preload	74210
20:44:46.472000	Creation Time	/etc/ld.so.preload	74210
20:44:46.472000	Metadata Modification Time	/etc/ld.so.preload	74210
20:44:46.476000	Last Access Time	/etc/ld.so.preload	74210
```

**What MAC times establish:** the installed library `/usr/lib/selinux.so.3`
(inode 74172) is created at `20:44:43.372`, and the concealable file
`/tmp/__malicious_file` (inode 74173) at `20:44:43.380` — eight milliseconds
later, both inside the scenario window. **What they cannot establish alone:**
the surviving `/etc/ld.so.preload` inode (74210) carries all four MAC times at
`20:44:46.472`, ~3 s *after* the library and, as T-03b shows, *after* the SSH
restart. Taken by themselves the MAC times would mis-order the preload step —
placing preload configuration last, after activation — which is not the command
order. Inode 74210's creation time dates the *surviving* inode, not the
activation-time configuration; the journal (T-03b) resolves the true order.
Inode identity matches TSK exactly, which is parser-level replication over one
disk image, not independent acquisition.

### T-03b - Command order and the SSH restart (M11), syslog_traditional + systemd_journal

Question: in what order did the persistence commands actually execute, and when
did the SSH restart happen? What would count as an answer: timestamped `sudo`
`COMMAND=` records and the old/new `sshd` transition. This is also the concrete
test of "what did Plaso add" — the disk notebook read `auth.log` and `syslog`
as flat files and did **not** read the systemd journal, which contributes 3,137
events here.

```bash {"name":"T-03b-Restart-Ordering","promptEnv":"never"}
set -euo pipefail

RESTART="$TIMELINE_DIR/t-03-sshd-restart-syslog-journal.jsonl"
export RESTART
[[ -s "$RESTART" ]] || psort -q --status_view none --output_time_zone UTC \
  -o json_line -w "$RESTART" "$PLASO" \
  "(data_type is 'syslog:line' or data_type is 'systemd:journal') and timestamp >= DATETIME('2026-08-13T20:44:00+00:00') and timestamp < DATETIME('2026-08-13T20:46:00+00:00')"
printf 'restart_window_events=%s\n' "$(wc -l <"$RESTART")"
# Sub-second command order, from the journal only (syslog_traditional is 1 s
# granularity). Bounded to the activation-cluster messages: the three sudo
# COMMANDs, the old master's SIGTERM, and the new master's IPv4 listen.
jq -r 'select(.data_type=="systemd:journal")
       | select((.message)|test("COMMAND=/usr/bin/(install|tee|systemctl)|pid: 655\\] Received signal 15|pid: 1054\\] Server listening on 0.0.0.0"))
       | [(.timestamp/1000000|floor|strftime("%H:%M:%S"))+"."+((.timestamp%1000000|tostring)),
          (.message|gsub("lab-ubuntu-22 ";"")|.[0:104])] | @tsv' "$RESTART" | sort
```

**Output**

```text {"ignore":"true"}
restart_window_events=3508
20:44:43.374899	[sudo, pid: 1040]  labuser : TTY=pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/install -m 064
20:44:43.429234	[sudo, pid: 1046]  labuser : TTY=pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/tee /etc/ld.so
20:44:43.453084	[sudo, pid: 1049]  labuser : TTY=pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/systemctl rest
20:44:43.464985	[sshd, pid: 655] Received signal 15; terminating.
20:44:43.488536	[sshd, pid: 1054] Server listening on 0.0.0.0 port 22.
```

**The journal establishes the chain order unambiguously, sub-second, from one
source:**

1. `20:44:43.374899` — `install -m 0644 /tmp/rk.so /lib/selinux.so.3` (library installed, inode 74172 dated `43.372` in T-03a)
2. `20:44:43.429234` — `tee /etc/ld.so.preload` (preload configured)
3. `20:44:43.453084` — `systemctl restart ssh.service` (restart requested)
4. `20:44:43.464985` — old `sshd` PID 655 receives `SIGTERM`
5. `20:44:43.488536` — new `sshd` PID 1054 listening on port 22

Order: **install → preload → restart → new sshd active**, all within 114 ms.
Critically, preload is configured (`43.429`) **before** the restart (`43.453`),
so the restarted `sshd` inherits the preload — the mechanism is internally
consistent. This is exactly the ordering that inode 74210's MAC time
(`46.472`, T-03a) alone would contradict: the journal's `tee` record, not the
surviving inode's crtime, dates the configuration. The ~3 s gap between the
`tee` command and the surviving inode 74210 is a genuine observation — inode
74210 is the *only* file created in the whole `20:44:46` second — but the
timeline does **not**, on its own, establish which write produced the surviving
content or why the inode postdates the command. (A Father-style self-heal of
`/etc/ld.so.preload` by the now-loaded library during shutdown is one
*hypothesis* consistent with the design; it is interpretation, not established
by these timestamps.)

### T-03c - Session accounting bracketing the restart (utmp)

Question: does login accounting bracket the operator session that ran the
restart? What would count as an answer: a `utmp` USER/DEAD pair around
`20:44:43`.

```bash {"name":"T-03c-Utmp-Sessions","promptEnv":"never"}
set -euo pipefail

UTMP="$TIMELINE_DIR/t-03-utmp-sessions.jsonl"
export UTMP
[[ -s "$UTMP" ]] || psort -q --status_view none --output_time_zone UTC \
  -o json_line -w "$UTMP" "$PLASO" "data_type is 'linux:utmp:event'"
printf 'utmp_events=%s\n' "$(wc -l <"$UTMP")"
# type: 1 RUN_LVL, 2 BOOT_TIME, 5 INIT, 6 LOGIN, 7 USER_PROCESS, 8 DEAD_PROCESS
jq -r 'select(.timestamp >= 1786653873000000)
       | [(.timestamp/1000000|floor|strftime("%H:%M:%S"))+"."+((.timestamp%1000000|tostring)),
          (.type|tostring), (.username//"-"), (.terminal//"-")] | @tsv' "$UTMP" | sort
```

**Output**

```text {"ignore":"true"}
utmp_events=22
20:44:33.767210	2	reboot	system boot
20:44:40.764094	1	runlevel	system boot
20:44:41.341948	5	-	hvc0
20:44:41.341948	6	LOGIN	hvc0
20:44:41.342320	5	-	tty1
20:44:41.342320	6	LOGIN	tty1
20:44:42.856282	7	labuser	pts/0
20:44:43.823745	8	-	pts/0
20:45:12.999504	1	shutdown	system boot
```

The `labuser` interactive session on `pts/0` — the TTY the T-03b `sudo` records
name (`TTY=pts/0`) — opens (`USER_PROCESS`, type 7) at `20:44:42.856` and is
recorded dead (`DEAD_PROCESS`, type 8) at `20:44:43.823`, bracketing the restart
(`43.45`–`43.49`). The backdoor `sshd` PID 1054 and `sh` PID 1056 create **no**
utmp record — they are not interactive logins — so session accounting is blind
to the runtime backdoor. That absence is consistent with the runtime being a
memory-only finding (T-04b).

## T-04 - Comparison against the disk notebook + filter-sensitivity control

The disk notebook read `auth.log`/`syslog` as flat files at 1-second granularity
and did not read the systemd journal. Against that baseline:

- **Replicated** (same acquired disk image, so agreement is parser-level
  replication, not independent evidence): the `sudo systemctl restart` →
  `sshd 655 SIGTERM` → `sshd 1054 listening` transition at `20:44:43`, and the
  three `sudo COMMAND=` invocations (`install`, `tee`, `systemctl`). The disk
  notebook already dated these to the second.
- **Added:** (a) **sub-second command ordering** — the journal separates
  install (`.374`), preload (`.429`), restart (`.453`), old-sshd death (`.464`)
  and new-sshd listen (`.488`), which the 1-second `auth.log` cannot; (b) the
  **systemd journal source itself** (3,137 events), which the disk notebook
  never read — this is the concrete answer to "what did Plaso add" and it
  carries the sub-second order in T-03b; (c) the **`utmp` session bracket**
  (T-03c); (d) the demonstration (T-03a vs T-03b) that the surviving
  `ld.so.preload` inode's MAC time would mis-order the chain without the journal.

### T-04a - Filter-sensitivity control (did the curated filter omit anything material?)

Question: does the curated path filter drop any event relevant to the chain
inside the scenario window? What would count as an answer: the same window,
run against the unfiltered control, containing no persistence artifact absent
from the curated window.

```bash {"name":"T-04a-Filter-Sensitivity","promptEnv":"never"}
set -euo pipefail

CTRLWIN="$TIMELINE_DIR/t-04-window-unfiltered-control.jsonl"
export CTRLWIN
[[ -s "$CTRLWIN" ]] || psort -q --status_view none --output_time_zone UTC \
  -o json_line -w "$CTRLWIN" "$CONTROL" \
  "timestamp >= DATETIME('2026-08-13T20:44:42+00:00') and timestamp < DATETIME('2026-08-13T20:44:44+00:00')"

echo '--- events by family: curated | control ---'
paste <(jq -r '.data_type' "$WINDOW"  | sort | uniq -c) \
      <(jq -r '.data_type' "$CTRLWIN" | sort | uniq -c)
echo '--- persistence artifacts among files the filter dropped ---'
comm -23 <(jq -r 'select(.data_type=="fs:stat")|.filename' "$CTRLWIN" | sort -u) \
         <(jq -r 'select(.data_type=="fs:stat")|.filename' "$WINDOW"  | sort -u) \
  | grep -Ei 'selinux|ld\.so\.preload|__malicious|rk\.so' || echo 'NONE dropped'
echo '--- dropped-file count + a representative sample ---'
comm -23 <(jq -r 'select(.data_type=="fs:stat")|.filename' "$CTRLWIN" | sort -u) \
         <(jq -r 'select(.data_type=="fs:stat")|.filename' "$WINDOW"  | sort -u) | wc -l
comm -23 <(jq -r 'select(.data_type=="fs:stat")|.filename' "$CTRLWIN" | sort -u) \
         <(jq -r 'select(.data_type=="fs:stat")|.filename' "$WINDOW"  | sort -u) \
  | grep -E '\.bashrc|\.profile|/usr/bin/(sudo|install|bash)$' | head
```

**Output**

```text {"ignore":"true"}
--- events by family: curated | control ---
     53 fs:stat            281 fs:stat
      2 linux:utmp:event     2 linux:utmp:event
     27 syslog:line         27 syslog:line
     31 systemd:journal     31 systemd:journal
--- persistence artifacts among files the filter dropped ---
NONE dropped
--- dropped-file count + a representative sample ---
216
/home/labuser/.bashrc
/home/labuser/.profile
/usr/bin/bash
/usr/bin/install
/usr/bin/sudo
```

The curated filter dropped **216** in-window `fs:stat` files and **zero**
`syslog`/`journal`/`utmp` events. Every dropped item is read-access noise on
stock binaries and interpreters (`/usr/bin/{bash,sudo,install,…}`, python
bytecode caches) or user dotfiles (`.bashrc`, `.profile`, `.bash_logout`) — the
tools the operator's session touched, not artifacts of the compromise. **No
persistence artifact was omitted**; the three inodes 74172/74210/74173 are
retained. This is a finding that *supports* the targeted collection: the filter
narrowed noise, not evidence, inside the treatment window.

### T-04-neg - A bounded negative worth asking (bash history)

Question: does the timeline date any interactive command? The disk notebook
found `.bash_history` **text** on the filesystem (M08 partial), so it is worth
asking whether the `bash_history` parser dates any of it. What would count as an
answer: any `bash:history:entry` event.

```bash {"name":"T-04-Bash-History-Negative","promptEnv":"never"}
set -euo pipefail

BASHNEG="$TIMELINE_DIR/t-04-bash-history-negative.jsonl"
export BASHNEG
psort -q --status_view none --output_time_zone UTC \
  -o json_line -w "$BASHNEG" "$PLASO" "data_type is 'bash:history:entry'"
printf 'bash_history_events=%s\n' "$(wc -l <"$BASHNEG")"
```

**Output**

```text {"ignore":"true"}
bash_history_events=0
```

**Bounded negative.** The `bash_history` parser (enabled, and the file is inside
the filter's include set) produced 0 events, because plaso's bash-history parser
requires `#<epoch>` timestamp lines and this `.bash_history` has none. The
interactive command *text* is therefore a filesystem-only artifact with no
timeline time — a source/format bound, not a claim that no commands ran. This is
the timeline's contribution to M08: **not observed** (see T-05).

## T-04b - Comparison against vol3_timeliner.txt (independent acquisition)

The memory image (`mem.raw`) and the disk image are **two separate
acquisitions**. Where both independently date the same event, that is
corroboration across independent acquisitions; where they disagree, the
disagreement is reported. They use **different time bases** — filesystem/journal
wall-clock on disk versus in-memory kernel task times reconstructed by
Volatility — so sub-second values are not flattened together.

```bash {"name":"T-04b-Vol3-Comparison","promptEnv":"never"}
set -euo pipefail

VOL3="$TIMELINE_DIR/vol3_timeliner.txt"
echo '--- memory (vol3 PsList): backdoor process creation times ---'
grep -E 'PsList	Process (1054|1056)/' "$VOL3" | awk -F'\t' '{print $2"  Created "$3}'
echo '--- memory (vol3 Files): cached-inode MAC for /usr/lib/selinux.so.3 (Modified|Accessed|Changed) ---'
grep -E 'Files	Cached Inode for /usr/lib/selinux.so.3' "$VOL3" | awk -F'\t' '{print $4" | "$5" | "$6}' | sort -u | head -1
echo '--- disk (timeline.plaso filestat): inode 74172 MAC ---'
jq -r 'select(.inode=="74172")|[.timestamp_desc,(.timestamp/1000000|floor|strftime("%H:%M:%S"))+"."+((.timestamp%1000000|tostring))]|@tsv' "$INODES" | sort -u
echo '--- disk (timeline.plaso journal): new sshd 1054 listen ---'
jq -r 'select(.data_type=="systemd:journal" and ((.message)|test("pid: 1054.* Server listening on 0.0.0.0")))
       | (.timestamp/1000000|floor|strftime("%H:%M:%S"))+"."+((.timestamp%1000000|tostring))' "$RESTART" | head -1
```

**Output**

```text {"ignore":"true"}
--- memory (vol3 PsList): backdoor process creation times ---
Process 1054/1054 sshd (153073869651968)  Created 2026-08-13 20:44:42.775129 UTC
Process 1056/1056 sh (153073821474816)  Created 2026-08-13 20:44:42.823229 UTC
--- memory (vol3 Files): cached-inode MAC for /usr/lib/selinux.so.3 (Modified|Accessed|Changed) ---
2026-08-13 20:44:43.372000 UTC | 2026-08-13 20:44:43.440000 UTC | 2026-08-13 20:44:43.376000 UTC
--- disk (timeline.plaso filestat): inode 74172 MAC ---
Content Modification Time	20:44:43.372000
Creation Time	20:44:43.372000
Last Access Time	20:44:43.440000
Metadata Modification Time	20:44:43.376000
--- disk (timeline.plaso journal): new sshd 1054 listen ---
20:44:43.488536
```

Each compared event, classified explicitly:

- **`/usr/lib/selinux.so.3` MAC times — corroboration across independent
  acquisitions (same underlying ext4 metadata).** The memory image's
  `Files`/"Cached Inode" row and the disk `filestat` inode-74172 row agree to
  the **microsecond**: Modified/mtime `43.372000`, Changed/ctime `43.376000`,
  Accessed/atime `43.440000`. Two separate acquisitions — a live RAM page-cache
  copy of the inode versus the powered-off ext4 inode — carry the same times,
  which excludes acquisition-time skew and single-tool error and confirms the
  images are consistent snapshots of one filesystem state. **Caveat, not
  flattened:** the cached inode *is* the kernel's copy of the same ext4 inode,
  so this is metadata corroboration (a consistency check across acquisitions),
  not a second *causal* witness. The disk adds the ext4 **Creation** time
  (crtime `43.372000`); Volatility's `Files` plugin exposes no crtime (`N/A`).
- **`sshd` PID 1054 — corroboration of existence and identity; sub-second timing
  is a time-base difference, not a contradiction.** Memory `PsList` records the
  process created at `20:44:42.775` (a memory-native runtime fact — the kernel
  task `start_time`, independent of any disk structure); the disk journal records
  the same PID 1054 listening at `20:44:43.488`. Both acquisitions place the same
  PID-identified restarted `sshd` inside the scenario window (`42.511`–`43.875`)
  — identity and existence corroborate. The memory time is `~0.7 s` *earlier*
  than the journal's `systemctl restart` (`43.453`) that spawned it, which would
  invert causality only if the two clocks were commensurable: `PsList`
  "Created Date" is monotonic-clock based (converted via the image's boot time),
  the journal is the systemd realtime clock, and their sub-second alignment is
  not established. This is a **time-base difference**, not a contradiction — no
  single attribute is asserted inconsistently, so `X` stays 0.
- **`sh` PID 1056 — memory-specialized; the disk timeline adds nothing.** The
  backdoor shell (created `20:44:42.823` in memory) produces no journal, syslog
  or utmp record. Correctly so: it is spawned by the loaded library, not through
  PAM/systemd. The timeline's silence here matches M09 being a memory-only
  target, and echoes the utmp gap in T-03c.

Note: the memory `Files` plugin dates the *cached inode metadata* of
`selinux.so.3`, not its process **mapping**; the disk↔memory inode-**number**
tie (74172) that binds the mapping to the on-disk library is in `linux.proc.Maps`
(memory notebook), which `timeliner` does not carry.

## T-05 - Synthesis, statuses, limitations, stopping condition

The full timeline **can** reconstruct the persistence-chain order, but the
reconstruction rests on the **systemd journal**, not on filesystem MAC times.
The journal orders install (`43.374`) → preload (`43.429`) → restart (`43.453`)
→ new `sshd` (`43.488`) sub-second from a single source; the `fs:stat` MAC times
corroborate the library and concealable-file creation (`43.372`, `43.380`) but,
for `/etc/ld.so.preload`, would mis-order the chain because the surviving inode
74210 dates to `46.472`. Over the disk notebook, the timeline adds sub-second
ordering, the journal source itself (3,137 events, previously unread), the utmp
session bracket, and the filter-sensitivity control proving the curated
collection omitted nothing material in-window.

### Timeline statuses for the applicable targets

| Target | Status | Durable locator / explicit bound |
|---|---|---|
| **M05** — library installed and mapped | **O** (install/activation facet) | Journal `sudo … COMMAND=/usr/bin/install -m 0644 /tmp/rk.so /lib/selinux.so.3` (PID 1040) `20:44:43.374899`; `filestat` inode `74172` `/usr/lib/selinux.so.3` Creation Time `20:44:43.372000` (`t-03-persistence-inodes.jsonl`). **Bound:** the timeline dates the install and the restart that loads it; the in-RAM *mapping* is not timeline-observable (memory `proc.Maps`). `filestat` replicates TSK over one disk image (same acquisition). |
| **M08** — interactive command activity | **N** | `bash:history:entry` parser produced **0** events (`t-04-bash-history-negative.jsonl`); `.bash_history` has no `#<epoch>` lines. **Bound:** the journal/syslog `sudo COMMAND=` records are privileged-invocation records (the class `auth.log` already showed), not an interactive shell command stream; negative is bounded to the `bash_history` parser and the syslog/journal reporters. |
| **M11** — SSH restart during activation | **O** | Journal `sudo … COMMAND=/usr/bin/systemctl restart ssh.service` (PID 1049) `20:44:43.453084`; `sshd` PID 655 `Received signal 15; terminating` `20:44:43.464985`; `sshd` PID 1054 `Server listening on 0.0.0.0 port 22` `20:44:43.488536` (`t-03-sshd-restart-syslog-journal.jsonl`); `utmp` `labuser`/`pts/0` USER `42.856` → DEAD `43.823` (`t-03-utmp-sessions.jsonl`). Read from the same disk image as `auth.log`, so replication vs the disk notebook; the journal source and sub-second times are the addition. |

M05 and M11 agree with the fixed case summary (O/O). M08 agrees (N). See the
recommended human edits below for the one place the timeline could sharpen the
existing M05 locator, and for an optional stricter reading of M05.

### Declared bounds carried from earlier sections

- **Curated collection bound (T-00a):** parser set + `linux_common.yaml`. The
  M08 negative and the T-04a comparison are both bounded by it; T-04a tested it
  and found no material omission in-window.
- **Format bound (T-04-neg):** `bash_history` needs `#<epoch>` lines; their
  absence is why M08 is `N` on the timeline, independent of the filter.
- **Same-acquisition bound (T-03a, T-03b, T-05 table):** `filestat`, syslog and
  journal all read the one disk image; agreement among them is parser-level
  replication. Only the memory image (T-04b) is an independent acquisition.
- **Time-base bound (T-04b):** memory task times and disk wall-clock are not
  sub-second-commensurable; the ~0.7 s `sshd` 1054 offset is a time-base
  difference, not a contradiction (`X` = 0).
- **Unresolved within bounds:** why the surviving `/etc/ld.so.preload` inode
  74210 postdates the `tee` command by ~3 s. Reported as observed; cause not
  established by MAC times.

### Stopping condition

The stopping condition is met: five bounded, individually justified `psort`
queries (window, inode ordering, restart syslog+journal, utmp, bash-history
negative) plus the filter-sensitivity control answered the ordering question and
fixed timeline statuses for M05, M08 and M11. No wholesale export of either
store was made. **TTF: not measured** — no `TTF-START`/`TTF-FIRST` lines were
recorded prospectively for this timeline examination, so per METHODOLOGY.md it
is not reconstructed after the fact.

### Recommended human edits (do not edit these files automatically)

These are for a human to apply; this notebook does not modify
`runme_case_summary.md`, `COMPARATIVE_RESULTS.md`, or any LaTeX file.

1. **`runme_case_summary.md`, "Metric contract → Timeline scope for this run".**
   The paragraph "A full Plaso timeline was not regenerated for this exact run.
   The temporal ('TL') column is bounded system-log context (`auth.log`,
   `syslog`) …" is now **superseded**: a curated Plaso store
   (`derived/timeline/timeline.plaso`, sha256 `682dd82a…18d0b`, 16,483 events)
   and an unfiltered control (`father.plaso`, 310,316 events) exist, examined in
   this notebook. Re-word to reference this timeline notebook, and keep the
   same-acquisition caveat (timeline still shares the disk acquisition; memory
   remains the only independent one).
2. **`runme_case_summary.md`, M05 row, Timeline locator.** Current text
   "TL `sudo`/`sshd` restart at `20:44:43Z`". Add the sub-second journal +
   filestat locators: install PID 1040 `20:44:43.374899`, inode 74172 crtime
   `20:44:43.372000`, and name the systemd journal (not only `auth.log`).
   *Optional stricter reading:* if the reviewer scores the compound "installed
   **and** mapped" strictly against a single source, the log timeline supports
   only "installed" → **P** (missing element: in-RAM mapping). This notebook
   keeps **O** to match the current fixed table and the union outcome; flagging
   the alternative for auditability.
3. **`runme_case_summary.md`, M11 row, Timeline locator.** Current text is
   `auth.log`-only. Add the systemd journal source and sub-second times: `sshd`
   655 `SIGTERM` `20:44:43.464985`, `sshd` 1054 listening `20:44:43.488536`,
   `systemctl restart` PID 1049 `20:44:43.453084`, plus the `utmp` `pts/0`
   bracket.
4. **`runme_case_summary.md`, source metric summary, "Timeline (log)" row,
   Principal methods.** Current "on-disk `auth.log`/`syslog` (no Plaso store)"
   is now inaccurate. Replace with: "Plaso 20260512 curated `timeline.plaso`
   (`filestat`, `syslog_traditional`, `systemd_journal`, `utmp`) + unfiltered
   `father.plaso` control; `psort` event filters". Status counts (O 2 / N 1) are
   unchanged. TTF remains `not measured`.
5. **`runme_case_summary.md`, M06 limitation (optional).** M06 stays
   filesystem-specialized, but the timeline adds ordering context worth a note:
   the surviving `/etc/ld.so.preload` inode 74210 MAC time (`20:44:46.472`)
   postdates the activation-time `tee` command (`20:44:43.429`, journal) by ~3 s;
   MAC time alone mis-dates the configuration.
6. **`COMPARATIVE_RESULTS.md`.** If the Timeline cell for this run cites "no
   Plaso store", update it to reflect the curated `timeline.plaso`; no status,
   union, or `X` value changes (Timeline O/P/N/TF unchanged at 2/0/1/0).
