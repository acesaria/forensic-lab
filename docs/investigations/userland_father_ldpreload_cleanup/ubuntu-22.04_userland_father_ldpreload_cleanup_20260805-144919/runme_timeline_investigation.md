---
cwd: ../../../..
shell: bash
---

# Father cleanup timeline investigation — Runme notebook

__Run:__ `ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919`

**Scope:** a small, source-scoped examination of the accepted Plaso storage.

Case-level per-artifact and aggregate metrics are recorded in
[runme_case_summary.md](./runme_case_summary.md); this notebook retains the
timeline observations and limitations that support them.

> [!IMPORTANT]
> Run cells in order from the repository root and in one Runme terminal. The
> accepted Plaso storage and its existing JSONL exports are immutable. This
> notebook never reads the large raw `timeline.jsonl` export. Its only new
> output is one bounded JSONL view beneath this run's `derived/timeline/`
> directory.

## Method and honesty statement

This is a **scenario-informed** investigation, not a genuinely blind one. Three
kinds of fact are kept separate throughout:

- **scenario metadata** (`manifest.json`, `command_log.jsonl`) used only to fix
  the case boundary and, later, to validate candidates already found;
- **generic Linux forensic categories** — authentication, SSH, sudo, service
  and filesystem timestamp evidence — used for the initial examination without
  starting from the malware name; and
- **exact `Father` IOC searches**, used only after a generic event exposes a
  candidate artifact.

Plaso practice is to query the storage file with a stated time slice and event
filter, retain that reduced result, and read only the few records relevant to
the question ([Plaso event filters](https://plaso.readthedocs.io/en/latest/sources/user/Event-filters.html)).
General Linux log-forensics background used to choose the categories below
comes from the DFRWS Linux forensic analysis workshop material
(https://dfrws.org/wp-content/uploads/2023/05/Learning_Linux_Forensic_Analysis-manual.pdf)
and a filesystem-timestamp walkthrough
(https://opensource.com/article/18/4/linux-filesystem-forensics). This
notebook does not otherwise summarize those references.

Plaso `filestat` events describe filesystem timestamp fields, not individual
shell-command executions. A `sudo` `COMMAND=` record supports that sudo logged
an invocation, not that the command completed successfully. A journal/syslog
line supports only what its parsed message records.

## T-00 - Case boundary, acquisition status, and Plaso scope disclosure

**Question:** Is this the completed cleanup run, does the Plaso storage used
below match the recorded raw-extraction authority, and what did that
extraction actually collect?

```bash {"name":"T-00-Case-Boundary-and-Integrity","promptEnv":"never"}
set -euo pipefail

RUN_ID='ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
MANIFEST="$RUN_DIR/manifest.json"
ACQUISITION="$RUN_DIR/dumps/acquisition.json"
RAW_STATUS="$RUN_DIR/analysis/raw_extraction_status.json"
PLASO="$RUN_DIR/analysis/timeline.plaso"
PLASO_ABS="$(readlink -f "$PLASO")"
TIMELINE_DIR="$INV_DIR/derived/timeline"

jq -e --arg run "$RUN_ID" '
  .run_id == $run
  and .scenario_id == "userland_father_ldpreload_cleanup"
  and .status == "completed"
' "$MANIFEST" >/dev/null
jq -e --arg run "$RUN_ID" '
  .run_id == $run
  and .memory_image.commands[0].status == "completed"
  and .disk_preparation == "powered_off"
  and .disk_image.verification.status == "completed"
  and .disk_image.verification.exit_status == 0
' "$ACQUISITION" >/dev/null
jq -e --arg storage "$PLASO_ABS" '
  .run_id == "ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919"
  and .plaso.status == "completed"
  and .plaso.event_count == 15063
  and .plaso.outputs.storage.path == $storage
' "$RAW_STATUS" >/dev/null

[[ "$(stat -c '%s' "$PLASO")" == "$(jq -er '.plaso.outputs.storage.size_bytes' "$RAW_STATUS")" ]]
[[ "$(sha256sum "$PLASO" | cut -d' ' -f1)" == "$(jq -er '.plaso.outputs.storage.sha256' "$RAW_STATUS")" ]]

mkdir -p "$TIMELINE_DIR"
export RUN_ID="$RUN_ID"
export RUN_DIR="$RUN_DIR"
export INV_DIR="$INV_DIR"
export MANIFEST="$MANIFEST"
export ACQUISITION="$ACQUISITION"
export RAW_STATUS="$RAW_STATUS"
export PLASO="$PLASO"
export TIMELINE_DIR="$TIMELINE_DIR"

printf 'run=%s\nplaso=%s\n' "$RUN_ID" "$PLASO"
printf 'plaso_size=%s\nplaso_sha256=%s\n' \
  "$(stat -c '%s' "$PLASO")" "$(sha256sum "$PLASO" | cut -d' ' -f1)"
printf 'plaso_status=completed; recorded_events=15063\n'
printf 'disk_ewfverify=completed exit=0; memory_acquisition=completed\n'
printf 'derived_directory=%s\n' "$TIMELINE_DIR"
```

**Output**

```text {"ignore":"true"}
run=ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919
plaso=shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/analysis/timeline.plaso
plaso_size=8085504
plaso_sha256=10ef253a33c1b6ab235edf9cdc4f41e28f4497d357af3b488e10aa54a09becb2
plaso_status=completed; recorded_events=15063
disk_ewfverify=completed exit=0; memory_acquisition=completed
derived_directory=shared/investigations/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/derived/timeline
```

The completed manifest, acquisition authority and raw-extraction authority
agree on this run. The stored Plaso size and SHA-256 match the raw-extraction
record. The recorded `ewfverify` success is acquisition-time evidence; this
cell does not rerun acquisition or verify the large disk image again.

### Plaso scope disclosure

The accepted `.plaso` store is already a **targeted** collection, not a full
disk parse:

- included paths come from `orchestrator/forensics/filters/linux_common.yaml`:
  `/etc`, `/var/log`, `/tmp`, `/var/tmp`, `/home/*/.bash_history`,
  `/root/.bash_history`, `/home/*/.ssh`, `/root/.ssh`, cron
  (`/var/spool/cron`, `/etc/crontab`, `/etc/cron.d`) and systemd
  (`/etc/systemd`, `/usr/lib/systemd`, `/lib/systemd`) locations,
  `/usr/local/{bin,sbin,lib,lib64}`, and a shallow `.so`-suffixed pattern
  under `/usr/lib`, `/lib`; bulky low-value trees (man pages, docs, locale,
  `/snap`, apt/package caches) are excluded;
- enabled parsers are the `run_log2timeline` default in
  `orchestrator/forensics/plaso_runner.py`.

Because source code can change after acquisition, the exact invocation used
**for this run** is read from `raw_extraction_status.json` rather than assumed
from current source:

```bash {"name":"T-00-Plaso-Invocation-Authority","promptEnv":"never"}
set -euo pipefail

jq -r '
  .plaso.invocations.log2timeline.command as $c
  | ($c | index("--parsers")) as $pi
  | ($c | index("--file-filter")) as $fi
  | "parsers=" + $c[$pi+1] + "\nfile_filter=" + $c[$fi+1] + "\nhashers=none\npartitions=all"
' "$RAW_STATUS"
```

**Output**

```text {"ignore":"true"}
parsers=text/bash_history, text/syslog, text/syslog_traditional, systemd_journal, filestat
file_filter=/home/anto/linux-multisource-dfir-lab/orchestrator/forensics/filters/linux_common.yaml
hashers=none
partitions=all
```

This confirms the run used the checked-in `linux_common.yaml` and the five
parsers named above. **`utmp` is not among them.** This investigation
therefore does not examine `wtmp`/`utmp` login records, and does not claim to,
unless a later query unexpectedly turns up a `linux:utmp:event` record (it did
not, see T-02). Enabling a `utmp`-capable parser is a candidate future change
to `plaso_runner.py`; it is not made here.

## T-01 - Define the bounded examination

**Question:** What narrow time window can answer the educational question
without reading the full timeline?

```bash {"name":"T-01-Bounded-Window","promptEnv":"never"}
set -euo pipefail

SCENARIO_START_UTC="$(jq -er '.timestamps.scenario_started_at' "$MANIFEST")"
SCENARIO_END_UTC="$(jq -er '.timestamps.scenario_ended_at' "$MANIFEST")"
GUEST_TIMEZONE="$(jq -er '.platform.timezone' "$MANIFEST")"
WINDOW_CENTER='2026-08-05T12:49:20+00:00'
SLICE_SIZE_MINUTES=1

export SCENARIO_START_UTC="$SCENARIO_START_UTC"
export SCENARIO_END_UTC="$SCENARIO_END_UTC"
export WINDOW_CENTER="$WINDOW_CENTER"
export SLICE_SIZE_MINUTES="$SLICE_SIZE_MINUTES"

printf 'scenario_start=%s\nscenario_end=%s\nguest_timezone=%s\n' \
  "$SCENARIO_START_UTC" "$SCENARIO_END_UTC" "$GUEST_TIMEZONE"
printf 'psort_slice_center=%s\npsort_slice_size=%s minute each side\n' \
  "$WINDOW_CENTER" "$SLICE_SIZE_MINUTES"
```

**Output**

```text {"ignore":"true"}
scenario_start=2026-08-05T12:49:19.071Z
scenario_end=2026-08-05T12:49:20.859Z
guest_timezone=Etc/UTC
psort_slice_center=2026-08-05T12:49:20+00:00
psort_slice_size=1 minute each side
```

The resulting `psort` time slice spans 12:48:20 through 12:50:20 UTC — wider
than the 1.788-second host-recorded scenario interval so that nearby
authentication, service and filesystem-timestamp context remains visible,
while staying small. All timestamps below are UTC.

## T-02 - Inventory the event families present in the window

**Question:** Which parsers actually produced events in this window, before
any content is interpreted? An enabled parser is not proof that it produced
events.

```bash {"name":"T-02-Event-Family-Inventory","promptEnv":"never"}
set -euo pipefail

WINDOW_SCRATCH="$(mktemp -u /tmp/father-window-inventory-XXXX.jsonl)"
psort -q --status_view none \
  --slice "$WINDOW_CENTER" --slice_size "$SLICE_SIZE_MINUTES" \
  --output_time_zone UTC -o json_line -w "$WINDOW_SCRATCH" \
  "$PLASO"

printf 'window_events=%s\n' "$(wc -l <"$WINDOW_SCRATCH")"
jq -r '.data_type' "$WINDOW_SCRATCH" | sort | uniq -c | sort -rn

STORE_SCRATCH="$(mktemp -u /tmp/father-store-inventory-XXXX.jsonl)"
psort -q --status_view none -o json_line -w "$STORE_SCRATCH" "$PLASO"
printf 'store_events=%s\n' "$(wc -l <"$STORE_SCRATCH")"
jq -r '.data_type' "$STORE_SCRATCH" | sort | uniq -c | sort -rn

rm -f "$WINDOW_SCRATCH" "$STORE_SCRATCH"
```

**Output**

```text {"ignore":"true"}
window_events=3681
   1580 syslog:line
   1324 systemd:journal
    777 fs:stat
store_events=15063
   9005 fs:stat
   3286 syslog:line
   2772 systemd:journal
```

Both the window and the entire accepted store contain exactly three
`data_type` values: `fs:stat`, `syslog:line`, and `systemd:journal`. The
store-wide count (15,063) matches the raw-extraction authority exactly. No
Bash-history event data type occurs even though `text/bash_history` was
enabled — a valid negative for this run, not a tool failure. These data-type
counts do not distinguish which enabled syslog parser produced a
`syslog:line` event. The scratch exports are not retained; only the
auth/ssh/service export below (T-04) becomes a new derived file.

## T-03 - Filesystem location observations

**Question:** What do ordinary staging, loader-configuration and
shared-library filesystem locations show in the window?

```bash {"name":"T-03-Export-Bounded-Location-Timeline","promptEnv":"never"}
set -euo pipefail

EVENT_EXPORT="$TIMELINE_DIR/t-01-window-location-events.jsonl"
EXPECTED_EVENT_EXPORT_SHA256='cb0bf08806fbca2a64daab1c19446be8229d0982b1c83274d24f6b3b86087529'
export EVENT_EXPORT="$EVENT_EXPORT"

if [[ -s "$EVENT_EXPORT" ]]; then
  printf 'reusing=%s\n' "$EVENT_EXPORT"
else
  psort -q --status_view none \
    --slice "$WINDOW_CENTER" --slice_size "$SLICE_SIZE_MINUTES" \
    --output_time_zone UTC -o json_line -w "$EVENT_EXPORT" \
    "$PLASO" \
    "filename contains '/tmp/' or filename contains '/etc/ld.so.preload' or filename contains '/usr/lib/'"
fi

[[ "$(sha256sum "$EVENT_EXPORT" | cut -d' ' -f1)" == "$EXPECTED_EVENT_EXPORT_SHA256" ]]
printf 'export=%s\nexport_events=%s\nexport_size=%s bytes\n' \
  "$EVENT_EXPORT" "$(wc -l <"$EVENT_EXPORT")" "$(stat -c '%s' "$EVENT_EXPORT")"
printf 'export_sha256=%s\n' "$(sha256sum "$EVENT_EXPORT" | cut -d' ' -f1)"
jq -r '.data_type' "$EVENT_EXPORT" | sort | uniq -c
```

**Output**

```text {"ignore":"true"}
reusing=shared/investigations/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/derived/timeline/t-01-window-location-events.jsonl
export=shared/investigations/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/derived/timeline/t-01-window-location-events.jsonl
export_events=139
export_size=140204 bytes
export_sha256=cb0bf08806fbca2a64daab1c19446be8229d0982b1c83274d24f6b3b86087529
    139 fs:stat
```

The 139-event view is entirely `fs:stat` (filesystem-timestamp) records; it
selects nothing from the auth/service families inventoried in T-02. The export
was selected through generic Linux locations. The exact rows displayed next
are scenario-guided validation within that already-bounded export, not blind
candidate discovery.

```bash {"name":"T-03-Show-Candidate-Events","promptEnv":"never"}
set -euo pipefail

jq -r '
  select(
    (.filename == "/tmp/forensic-lab" and .timestamp_desc == "Creation Time")
    or (.filename == "/tmp/forensic-lab/father_ldpreload" and .timestamp_desc == "Creation Time")
    or (.filename == "/tmp/forensic-lab/father_ldpreload/probe" and .timestamp_desc == "Creation Time")
    or (.filename == "/usr/lib/selinux.so.3" and .timestamp_desc == "Creation Time")
    or (.filename == "/tmp/forensic-lab/father_ldpreload/probe/__malicious_file" and .timestamp_desc == "Creation Time")
    or (.filename == "/tmp/forensic-lab/father_ldpreload" and .timestamp_desc == "Content Modification Time")
    or (.filename == "/etc/ld.so.preload" and .timestamp_desc == "Creation Time")
  )
  | [(.timestamp / 1000000 | floor | strftime("%Y-%m-%dT%H:%M:%SZ")), .timestamp_desc, .filename, .inode]
  | @tsv
' "$EVENT_EXPORT"
```

**Output**

```text {"ignore":"true"}
2026-08-05T12:49:19Z	Creation Time	/tmp/forensic-lab/father_ldpreload/probe	258156
2026-08-05T12:49:19Z	Creation Time	/tmp/forensic-lab/father_ldpreload	258155
2026-08-05T12:49:19Z	Creation Time	/tmp/forensic-lab	258154
2026-08-05T12:49:20Z	Creation Time	/usr/lib/selinux.so.3	62345
2026-08-05T12:49:20Z	Creation Time	/tmp/forensic-lab/father_ldpreload/probe/__malicious_file	260193
2026-08-05T12:49:20Z	Content Modification Time	/tmp/forensic-lab/father_ldpreload	258155
2026-08-05T12:49:22Z	Creation Time	/etc/ld.so.preload	61596
```

Relevant record locators (nanosecond precision from the export's nested
`date_time` field):

- staging hierarchy creation at `12:49:19.869540242 UTC` (inodes `258154`–`258156`);
- the allocated 32,784-byte `.so`-named regular file `/usr/lib/selinux.so.3`
  creation at `12:49:20.473540242 UTC` (inode `62345`);
- the retained zero-byte probe file's timestamps at `12:49:20.497540242 UTC`
  (inode `260193`);
- modification metadata on the surviving staging parent at
  `12:49:20.685540242 UTC`; and
- `/etc/ld.so.preload` creation at `12:49:22.745540242 UTC` (inode `61596`).

No `fs:stat` record for the extracted `Father-*` source directory appears in
this bounded `/tmp/` view. This is a valid negative for this query, not proof
that the directory never existed — a deleted object may have no surviving
allocated `filestat` record. The parent-directory modification is
directory-change context compatible with cleanup, not cleanup proof by
itself.

## T-04 - Generic authentication, SSH, sudo, and service examination

**Question:** What do ordinary Linux authentication logs show in the window,
selected by reporter and message content — not by the scenario or malware
name?

```bash {"name":"T-04-Export-Auth-SSH-Service-Timeline","promptEnv":"never"}
set -euo pipefail

AUTH_EXPORT="$TIMELINE_DIR/t-03-window-auth-ssh-service-events.jsonl"
EXPECTED_AUTH_EXPORT_SHA256='2e374121900114e68190eb9aa2e27dff23034a6b49e57ba8cc9391d931fc9620'
export AUTH_EXPORT="$AUTH_EXPORT"

if [[ -s "$AUTH_EXPORT" ]]; then
  printf 'reusing=%s\n' "$AUTH_EXPORT"
else
  psort -q --status_view none \
    --slice "$WINDOW_CENTER" --slice_size "$SLICE_SIZE_MINUTES" \
    --output_time_zone UTC -o json_line -w "$AUTH_EXPORT" \
    "$PLASO" \
    "(data_type is 'syslog:line' or data_type is 'systemd:journal') and (reporter is 'sshd' or reporter is 'sudo' or body contains 'ssh.service' or body contains 'Secure Shell')"
fi

[[ "$(sha256sum "$AUTH_EXPORT" | cut -d' ' -f1)" == "$EXPECTED_AUTH_EXPORT_SHA256" ]]
printf 'export=%s\nexport_events=%s\nexport_size=%s bytes\n' \
  "$AUTH_EXPORT" "$(wc -l <"$AUTH_EXPORT")" "$(stat -c '%s' "$AUTH_EXPORT")"
printf 'export_sha256=%s\n' "$(sha256sum "$AUTH_EXPORT" | cut -d' ' -f1)"
jq -r '.data_type' "$AUTH_EXPORT" | sort | uniq -c
jq -r '.reporter' "$AUTH_EXPORT" | sort | uniq -c
```

**Output**

```text {"ignore":"true"}
reusing=shared/investigations/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/derived/timeline/t-03-window-auth-ssh-service-events.jsonl
export=shared/investigations/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/derived/timeline/t-03-window-auth-ssh-service-events.jsonl
export_events=62
export_size=77144 bytes
export_sha256=2e374121900114e68190eb9aa2e27dff23034a6b49e57ba8cc9391d931fc9620
     27 syslog:line
     35 systemd:journal
     31 sshd
     14 sudo
     17 systemd
```

`body` (the parser's raw attribute) rather than `message` (a display-only
field) had to be used for the `contains` clauses; `psort` filters operate on
raw event attributes.

```bash {"name":"T-04-Show-Auth-SSH-Service-Records","promptEnv":"never"}
set -euo pipefail

echo "== SSH accepted-connection records =="
jq -r '
  select(.data_type == "systemd:journal" and .reporter == "sshd" and (.message | contains("Accepted publickey")))
  | [(.timestamp / 1000000 | strftime("%H:%M:%S")) + "." + (("000000" + ((.timestamp % 1000000) | tostring))[-6:]), .message]
  | @tsv
' "$AUTH_EXPORT"

echo "== sudo COMMAND= records =="
jq -r '
  select(.data_type == "systemd:journal" and .reporter == "sudo" and (.message | contains("COMMAND=")))
  | [(.timestamp / 1000000 | strftime("%H:%M:%S")) + "." + (("000000" + ((.timestamp % 1000000) | tostring))[-6:]), .message]
  | @tsv
' "$AUTH_EXPORT"

echo "== ssh.service restart lifecycle =="
jq -r '
  select(.data_type == "systemd:journal" and .reporter == "systemd" and (.message | contains("Secure Shell") or contains("ssh.service")) and .timestamp > 1785934160000000 and .timestamp < 1785934161000000)
  | [(.timestamp / 1000000 | strftime("%H:%M:%S")) + "." + (("000000" + ((.timestamp % 1000000) | tostring))[-6:]), .message]
  | @tsv
' "$AUTH_EXPORT"
```

**Output**

```text {"ignore":"true"}
== SSH accepted-connection records ==
12:49:17.925586	lab-ubuntu-22 [sshd, pid: 616] Accepted publickey for labuser from 192.168.100.1 port 48500 ssh2: ED25519 SHA256:b+sPbwXWklIm2oxWubk7bIEnom4awIHQPkaKP93zfGs
12:49:19.076860	lab-ubuntu-22 [sshd, pid: 708] Accepted publickey for labuser from 192.168.100.1 port 38354 ssh2: ED25519 SHA256:b+sPbwXWklIm2oxWubk7bIEnom4awIHQPkaKP93zfGs
12:49:19.189586	lab-ubuntu-22 [sshd, pid: 711] Accepted publickey for labuser from 192.168.100.1 port 38360 ssh2: ED25519 SHA256:b+sPbwXWklIm2oxWubk7bIEnom4awIHQPkaKP93zfGs
== sudo COMMAND= records ==
12:49:20.475866	lab-ubuntu-22 [sudo, pid: 863]  labuser : TTY=pts/0 ; PWD=/tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332 ; USER=root ; COMMAND=/usr/bin/install -m 0644 /tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/rk.so /lib/selinux.so.3
12:49:20.545552	lab-ubuntu-22 [sudo, pid: 869]  labuser : TTY=pts/0 ; PWD=/tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332 ; USER=root ; COMMAND=/usr/bin/tee /etc/ld.so.preload
12:49:20.565643	lab-ubuntu-22 [sudo, pid: 872]  labuser : TTY=pts/0 ; PWD=/tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332 ; USER=root ; COMMAND=/usr/bin/systemctl restart ssh.service
== ssh.service restart lifecycle ==
12:49:20.570606	lab-ubuntu-22 [systemd, pid: 1] Stopping OpenBSD Secure Shell server...
12:49:20.573744	lab-ubuntu-22 [systemd, pid: 1] ssh.service: Deactivated successfully.
12:49:20.573921	lab-ubuntu-22 [systemd, pid: 1] Stopped OpenBSD Secure Shell server.
12:49:20.574991	lab-ubuntu-22 [systemd, pid: 1] Starting OpenBSD Secure Shell server...
12:49:20.590870	lab-ubuntu-22 [systemd, pid: 1] Started OpenBSD Secure Shell server.
```

**Observations.** Three SSH sessions were accepted from `192.168.100.1` in
quick succession, all with the same ED25519 user public-key fingerprint,
opening and closing within the window (full open/close pairs are in
`AUTH_EXPORT`). Immediately afterward, three `sudo` `COMMAND=` records appear
for user `labuser` acting as `root`: an `install` of a file into
`/lib/selinux.so.3`, a `tee` into `/etc/ld.so.preload`, and a `systemctl
restart` of `ssh.service` — matching the `install`/`tee`/`restart` sequence
by name and by relative order, with each message represented in both the
journal and traditional-syslog sources. The `ssh.service` restart
lifecycle (`Stopping` → `Deactivated` → `Stopped` → `Starting` → `Started`)
brackets the `systemctl` `sudo` record. **A `sudo` `COMMAND=` line supports
that sudo logged this invocation; it does not by itself prove the command
completed.**

**Interpretation.** The three accepted SSH sessions share one source address
and one user public-key fingerprint, open and close quickly, and are not
distinguished from each other by this evidence alone; they are read here as
ordinary orchestration SSH activity carrying interactive terminal commands,
not as a demonstrated distinct "native" connection. No separate accepted-
connection record in this bounded export is attributable specifically to any
later backdoor-trigger step; see T-06 for why that must remain a scenario-
validation statement rather than a timeline finding.

## T-05 - Father IOC pivot

**Question:** The `sudo` `PWD=` field above names
`/tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332`
— a candidate exposed by a generic authentication record, not by searching
for "Father" first. Does an explicit, exact search for that string change
what is observed?

```bash {"name":"T-05-Father-Pivot-Field-Restriction-Check","promptEnv":"never"}
set -euo pipefail

TOTAL_RECORDS=$(wc -l < "$AUTH_EXPORT")
NAIVE_MATCHES=$(grep -ic father "$AUTH_EXPORT")
CONTENT_MATCHES=$(jq -r 'select((.message // "" | test("Father";"i")) or (.filename // "" | test("Father";"i")))' "$AUTH_EXPORT" | jq -s 'length')

printf 'total_records=%s\nnaive_whole_record_grep_matches=%s\ncontent_field_restricted_matches=%s\n' \
  "$TOTAL_RECORDS" "$NAIVE_MATCHES" "$CONTENT_MATCHES"

echo "why the naive whole-record grep over-matches:"
jq -r 'select(.reporter=="sshd" and (.message|contains("Server listening"))) | .pathspec.parent.parent.parent.location' "$AUTH_EXPORT" | head -1
```

**Output**

```text {"ignore":"true"}
total_records=62
naive_whole_record_grep_matches=62
content_field_restricted_matches=6
why the naive whole-record grep over-matches:
/home/anto/linux-multisource-dfir-lab/shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/dumps/disk/evidence_disk.E01
```

**Negative finding, methodological.** Grepping the raw exported JSON records
for "father" matches all 62/62 records, including SSH `Server listening`
lines that never mention Father — because every psort JSON record embeds the
evidence image's own `pathspec`, and this run's evidence path contains
`father_ldpreload` as part of the run identifier. That is a false positive
from the acquisition path, not a forensic hit. Restricting the search to the
parsed `.message`/`.filename` content fields gives 6 matches instead. This
distinction matters for any exact-string pivot against this evidence set.

```bash {"name":"T-05-Father-Pivot-Content-Matches","promptEnv":"never"}
set -euo pipefail

jq -r '
  select(.data_type == "systemd:journal" and (.message | contains("Father")))
  | [(.timestamp / 1000000 | strftime("%H:%M:%S")) + "." + (("000000" + ((.timestamp % 1000000) | tostring))[-6:]), .reporter, .message]
  | @tsv
' "$AUTH_EXPORT"

echo "-- extracted /tmp/ location export: any fs:stat for the Father-named source dir? --"
jq -r 'select(.filename // "" | test("Father-4eb2712")) | .filename' "$EVENT_EXPORT" | wc -l
```

**Output**

```text {"ignore":"true"}
12:49:20.475866	sudo	lab-ubuntu-22 [sudo, pid: 863]  labuser : TTY=pts/0 ; PWD=/tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332 ; USER=root ; COMMAND=/usr/bin/install -m 0644 /tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/rk.so /lib/selinux.so.3
12:49:20.545552	sudo	lab-ubuntu-22 [sudo, pid: 869]  labuser : TTY=pts/0 ; PWD=/tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332 ; USER=root ; COMMAND=/usr/bin/tee /etc/ld.so.preload
12:49:20.565643	sudo	lab-ubuntu-22 [sudo, pid: 872]  labuser : TTY=pts/0 ; PWD=/tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332 ; USER=root ; COMMAND=/usr/bin/systemctl restart ssh.service
-- extracted /tmp/ location export: any fs:stat for the Father-named source dir? --
0
```

**Observations.** Within this bounded evidence, the only source family that
names the extracted `Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332`
directory is the `sudo` audit trail (3 distinct commands, each independently
recorded by `text/syslog_traditional` and `systemd_journal`). The `/tmp/`
`fs:stat` export (T-03) has zero records for that exact directory name — the
sudo log preserved the working directory at command-invocation time even
though this bounded filesystem-timestamp view has no surviving allocated
`filestat` record for it, consistent with the T-03 valid negative. This does
not show the directory never existed on disk; it shows this bounded query
found no allocated `filestat` record for it.

## T-06 - Cross-source correlation

The next cell reads the scenario command log and acquisition record only
*after* the candidates above were already selected from Plaso. These are
**scenario-validation and acquisition facts**, not Plaso findings, and are
kept in a separate cell for that reason.

```bash {"name":"T-06-Scenario-Record-Correlation","promptEnv":"never"}
set -euo pipefail

jq -r '
  select(
    .operation == "upload_archive"
    or .operation == "validate_backdoor"
    or (.command? == "sudo -n install -m 0644 \"$source/rk.so\" /lib/selinux.so.3")
    or (.command? == "printf '\''%s\\n'\'' /lib/selinux.so.3 | sudo -n tee /etc/ld.so.preload")
    or (.command? == "sudo -n systemctl restart ssh.service")
  )
  | if .command then
      [.recorded_at, .operation, .status, .command]
    else
      [.recorded_at, .operation, .status]
    end
  | @tsv
' "$RUN_DIR/command_log.jsonl"

MEMORY_ACQUISITION_EPOCH="$(jq -er '.memory_image.timestamp' "$ACQUISITION")"
DISK_ACQUISITION_EPOCH="$(jq -er '.disk_image.timestamp' "$ACQUISITION")"

printf 'memory_acquisition_epoch=%s\ndisk_acquisition_epoch=%s\n' \
  "$MEMORY_ACQUISITION_EPOCH" "$DISK_ACQUISITION_EPOCH"
printf 'memory_acquisition_utc=%s\n' \
  "$(date -u -d "@$MEMORY_ACQUISITION_EPOCH" +%Y-%m-%dT%H:%M:%S.%3NZ)"
printf 'disk_acquisition_utc=%s\n' \
  "$(date -u -d "@$DISK_ACQUISITION_EPOCH" +%Y-%m-%dT%H:%M:%S.%3NZ)"
```

**Output**

```text {"ignore":"true"}
2026-08-05T12:49:19.407Z	upload_archive	success
2026-08-05T12:49:20.559Z	terminal	success	sudo -n install -m 0644 "$source/rk.so" /lib/selinux.so.3
2026-08-05T12:49:20.621Z	terminal	success	printf '%s\\n' /lib/selinux.so.3 | sudo -n tee /etc/ld.so.preload
2026-08-05T12:49:20.662Z	terminal	success	sudo -n systemctl restart ssh.service
2026-08-05T12:49:20.729Z	validate_backdoor	success
memory_acquisition_epoch=1785934164.9253495
disk_acquisition_epoch=1785934208.4018614
memory_acquisition_utc=2026-08-05T12:49:24.925Z
disk_acquisition_utc=2026-08-05T12:50:08.401Z
```

| Source and semantics | Event | Time (UTC) |
| --- | --- | --- |
| Auth log, `sshd` accepted-key session (orchestration SSH) | first of 3 sessions from `192.168.100.1` | `12:49:17.925586` |
| Auth log, `sudo` `COMMAND=` (invocation record) | `install ... /lib/selinux.so.3` (PWD names `Father-4eb27...`) | `12:49:20.475866` |
| Scenario command log (orchestrator-observed) | same `install` command, `success` | `12:49:20.559` |
| Auth log, `sudo` `COMMAND=` | `tee /etc/ld.so.preload` | `12:49:20.545552` |
| Scenario command log | same `tee` command, `success` | `12:49:20.621` |
| Auth log, `sudo` `COMMAND=` | `systemctl restart ssh.service` | `12:49:20.565643` |
| Scenario command log | same `systemctl` command, `success` | `12:49:20.662` |
| Filesystem timestamp (`fs:stat`) | `/usr/lib/selinux.so.3` Creation Time, inode `62345` | `12:49:20.473540242` |
| Filesystem timestamp (`fs:stat`) | `/etc/ld.so.preload` Creation Time, inode `61596` | `12:49:22.745540242` |
| Scenario command log | `validate_backdoor`, `success` | `12:49:20.729` |
| Acquisition authority | memory image captured (guest on) | `12:49:24.925` |
| Acquisition authority | disk image captured (guest off) | `12:50:08.401` |

The sudo destination `/lib/selinux.so.3` and the `fs:stat` path
`/usr/lib/selinux.so.3` identify the same allocated object because `/lib`
resolves to `/usr/lib` in this acquired Ubuntu filesystem (disk notebook
D-01.3).

**Correlation notes, kept separate from the raw observations above:**

- The auth-log `sudo` timestamps and the scenario command-log timestamps for
  the same three commands are within roughly 0.1–0.2 seconds of each other
  and in the same relative order. That gap is compatible with two different
  recording layers (guest journal time vs. orchestrator-observed completion
  time over SSH) and is not treated as a contradiction.
- The acquired `/etc/ld.so.preload` inode time is about 2.2 seconds after the
  sudo log recorded the explicit `tee` invocation. The inode timestamp cannot
  date that invocation; a later rewrite is plausible, but neither its mechanism
  nor its cause is demonstrated by this evidence.
- `validate_backdoor` is recorded as `success` in the scenario command log at
  `12:49:20.729`, but no distinct auth/SSH record in the bounded T-04 export
  is attributable specifically to that step. **The Father hook's native
  connection is therefore supported only by scenario validation here, not by
  a separate timeline finding**, and is reported as such.
- Both acquisition timestamps postdate every Plaso observation above by
  several seconds, consistent with capture occurring after the scenario
  actions; this is coarse ordering context from a different authority
  (`acquisition.json`), not a Plaso event.

## T-07 - Findings, negative observations, and conclusion

| Status | Timeline result and limit |
| --- | --- |
| Observed | The window and store-wide inventory (T-02) contain only `fs:stat`, `syslog:line`, and `systemd:journal`; no Bash-history event data type occurs despite `text/bash_history` being enabled. The data-type inventory cannot attribute `syslog:line` rows to one of the two enabled syslog parsers. |
| Observed | Three orchestration SSH sessions from `192.168.100.1` and three `sudo` `COMMAND=` records (`install`, `tee`, `systemctl restart`) appear in T-04, bracketed by an `ssh.service` stop/start lifecycle. |
| Observed | Three `sudo` `PWD=`/`COMMAND=` records name the `Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332` directory (T-04); this is the artifact that justified the exact `Father` pivot in T-05. |
| Scenario-guided validation | Within the generic bounded-location export, the exact rows displayed in T-03 record staging-hierarchy creation, an unusual `.so`-named regular file, a retained probe file, and a surviving `/etc/ld.so.preload`. |
| Valid negative | No `fs:stat` record for the `Father-*` extracted-source directory appears in the bounded `/tmp/` export (T-03, T-05); a deleted object may have no surviving allocated record — this does not show it never existed. |
| Valid negative | No auth/SSH record in the bounded T-04 export is separately attributable to the `validate_backdoor` step; that step is reported only as scenario validation (T-06), not a timeline finding. |
| Methodological negative | A naive whole-record `grep` for "Father" over exported psort JSON matches every record (62/62) because the evidence `pathspec` embeds the run identifier; restricting to parsed content fields is required for a real pivot (T-05). |
| Limitation | `utmp` is not among the enabled parsers for this run (T-00); no `wtmp`/`utmp` login claim is made. |
| Limitation | `fs:stat` supports a filesystem metadata event, not execution; `sudo` `COMMAND=` supports a logged invocation, not completion; a journal/syslog line supports only its parsed message. |
| Stopping condition | Stop after the bounded location export (139 events) and auth/ssh/service export (62 events) answer the staging, authentication, privileged-command and persistence questions; do not read or search the 16,369,789-byte raw `timeline.jsonl`. |

**Timeline conclusion:** The accepted Plaso storage supplies coherent parsed
evidence of ordinary SSH access and three sudo-logged
privileged-command invocations (installing a `.so`-named file, writing
`/etc/ld.so.preload`, and restarting `ssh.service`). Generic authentication
and service examination exposed these records before any `Father` name search;
the exact filesystem rows shown from the generic bounded-location export are
disclosed scenario-guided validation. A `Father`-named path first surfaced
through a `sudo` audit record,
not a targeted search, and the resulting exact pivot found no additional
artifact beyond what the generic examination had already exposed. Kept
separate, the scenario command log and acquisition record corroborate the
same three commands' relative order and show the native-backdoor validation
step is supported only by that scenario record. The timeline does not
independently establish execution of the installed file, actor identity
beyond the logged `labuser`/`root` pair, or the absence of removed artifacts.
Enabling a `utmp`-capable parser in `plaso_runner.py` is a candidate future
change, not performed in this task.
