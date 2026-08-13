---
cwd: ../../../..
shell: bash
---

# ptrace_fa timeline investigation — Runme notebook

__Run:__ `ubuntu-22.04_ptrace_fa_20260813-173337`

**Scope:** bounded Plaso examination of P01-P03 and nearby authentication
context. The Plaso store is new derived examination output, not run evidence or
an automatic extraction product.

## T-00 - Case boundary and bounded Plaso extraction

```bash {"name":"T-00-Bounded-Plaso","promptEnv":"never"}
set -euo pipefail

RUN_ID='ubuntu-22.04_ptrace_fa_20260813-173337'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
MANIFEST="$RUN_DIR/manifest.json"
ACQUISITION="$RUN_DIR/dumps/acquisition.json"
EWF="$RUN_DIR/dumps/disk/evidence_disk.E01"
TIMELINE_DIR="$INV_DIR/derived/timeline"
PLASO="$TIMELINE_DIR/timeline.plaso"

jq -e --arg run "$RUN_ID" '
  .run_id == $run and .scenario_id == "ptrace_fa"
  and .status == "completed"
  and .repository.commit == "aef7d0015bbcd1a87f051e16f4fe722f73507993-dirty"
' "$MANIFEST" >/dev/null
jq -e '
  .disk_preparation == "powered_off"
  and .disk_image.verification.status == "completed"
  and .disk_image.verification.exit_status == 0
' "$ACQUISITION" >/dev/null

mkdir -p "$TIMELINE_DIR"
[[ -s "$PLASO" ]] || log2timeline --unattended --status-view none \
  --storage-file "$PLASO" --partitions all \
  --parsers 'text/bash_history,text/syslog,text/syslog_traditional,systemd_journal,filestat' \
  --file-filter orchestrator/forensics/filters/linux_common.yaml "$EWF"

export RUN_ID RUN_DIR INV_DIR MANIFEST TIMELINE_DIR PLASO
printf 'plaso_size=%s\n' "$(stat -c '%s' "$PLASO")"
sha256sum "$PLASO"
log2timeline --version
```

**Output**

```text {"ignore":"true"}
plaso_size=8450048
377a2761b252677355eb869e125b0b6e4f61ed5bb1eefd6237d90089bbcf3f0e  timeline.plaso
plaso - log2timeline version 20260512
```

The successful extraction used the established Linux include/exclude filter
and five parser families. Two earlier attempts failed before extraction:
unattended mode first lacked partition selection, then rejected identifier
`3`; `--partitions all` resolved dfVFS selection while the file filter retained
the bounded collection. Both failures are preserved in the investigation log.

## T-01 - Bounded window

```bash {"name":"T-01-Window","promptEnv":"never"}
set -euo pipefail

SCENARIO_START="$(jq -er '.timestamps.scenario_started_at' "$MANIFEST")"
SCENARIO_END="$(jq -er '.timestamps.scenario_ended_at' "$MANIFEST")"
WINDOW_CENTER='2026-08-13T15:33:38+00:00'
SLICE_SIZE_MINUTES=1
export WINDOW_CENTER SLICE_SIZE_MINUTES
printf 'scenario_start=%s\nscenario_end=%s\ncenter=%s\nslice=%s minute each side\n' \
  "$SCENARIO_START" "$SCENARIO_END" "$WINDOW_CENTER" "$SLICE_SIZE_MINUTES"
```

**Output**

```text {"ignore":"true"}
scenario_start=2026-08-13T15:33:37.722Z
scenario_end=2026-08-13T15:33:38.790Z
center=2026-08-13T15:33:38+00:00
slice=1 minute each side
```

The treatment spans about one second; a two-minute window retains nearby
filesystem and session context while remaining bounded.

## T-02 - Event-family inventory

```bash {"name":"T-02-Event-Families","promptEnv":"never"}
set -euo pipefail

WINDOW="$TIMELINE_DIR/t-00-window-inventory.jsonl"
[[ -s "$WINDOW" ]] || psort -q --status_view none \
  --slice "$WINDOW_CENTER" --slice_size "$SLICE_SIZE_MINUTES" \
  --output_time_zone UTC -o json_line -w "$WINDOW" "$PLASO"
printf 'window_events=%s\n' "$(wc -l <"$WINDOW")"
jq -r '.data_type' "$WINDOW" | sort | uniq -c | sort -rn
```

**Output**

```text {"ignore":"true"}
window_events=4254
1984 syslog:line
1486 systemd:journal
784 fs:stat
```

No bash-history event occurs despite the enabled parser. The history file is
examined directly in D-05; Plaso's absence is a source/tool-bounded negative.

## T-03 - Location-first staging observations (P01-P03)

```bash {"name":"T-03-Staging-Timeline","promptEnv":"never"}
set -euo pipefail

LOCATION="$TIMELINE_DIR/t-01-window-location-events.jsonl"
[[ -s "$LOCATION" ]] || psort -q --status_view none \
  --slice "$WINDOW_CENTER" --slice_size "$SLICE_SIZE_MINUTES" \
  --output_time_zone UTC -o json_line -w "$LOCATION" "$PLASO" \
  "filename contains '/tmp/'"
printf 'location_events=%s\n' "$(wc -l <"$LOCATION")"
jq -r '
  select(.timestamp_desc == "Creation Time" and (.filename | test("/ptrace_fa")))
  | [(.timestamp / 1000000 | floor | strftime("%Y-%m-%dT%H:%M:%SZ")), .filename, .inode]
  | @tsv
' "$LOCATION" | sort
sha256sum "$LOCATION"
```

**Output**

```text {"ignore":"true"}
location_events=62
2026-08-13T15:33:37Z /tmp/ptrace_fa-shellcode_inject_fa                   74171
2026-08-13T15:33:37Z /tmp/ptrace_fa-victim                                74172
2026-08-13T15:33:38Z /tmp/forensic-lab/ptrace_fa                         258129
2026-08-13T15:33:38Z /tmp/forensic-lab/ptrace_fa/shellcode_inject_fa     258130
2026-08-13T15:33:38Z /tmp/forensic-lab/ptrace_fa/victim                  258131
2026-08-13T15:33:38Z /tmp/forensic-lab/ptrace_fa/victim.log              258132
89b0819526c3edd01e99a9cdca476058bd07fdca63049ba740326bbd7e7815e5  t-01-window-location-events.jsonl
```

The export is selected by generic `/tmp` location before filtering displayed
rows to the candidate tree. **P01-P03 observed.** The upload-stage files precede
the installed runtime directory by one second. Inodes match TSK exactly, which
is parser-level replication over one disk image, not independent acquisition.

## T-04 - Authentication/session context

```bash {"name":"T-04-Auth-Context","promptEnv":"never"}
set -euo pipefail

AUTH="$TIMELINE_DIR/t-02-window-auth-ssh-service-events.jsonl"
[[ -s "$AUTH" ]] || psort -q --status_view none \
  --slice "$WINDOW_CENTER" --slice_size "$SLICE_SIZE_MINUTES" \
  --output_time_zone UTC -o json_line -w "$AUTH" "$PLASO" \
  "(data_type is 'syslog:line' or data_type is 'systemd:journal') and (reporter is 'sshd' or reporter is 'sudo')"
printf 'auth_events=%s\n' "$(wc -l <"$AUTH")"
jq -r '.reporter' "$AUTH" | sort | uniq -c
jq -r '
  select(.data_type == "systemd:journal" and (.message | contains("Accepted publickey")))
  | [(.timestamp / 1000000 | strftime("%H:%M:%S")), .message] | @tsv
' "$AUTH"
sha256sum "$AUTH"
```

**Output**

```text {"ignore":"true"}
auth_events=23
23 sshd
15:33:36 lab-ubuntu-22 [sshd, pid: 714] Accepted publickey for labuser from 192.168.100.1 port 47298 ...
15:33:37 lab-ubuntu-22 [sshd, pid: 909] Accepted publickey for labuser from 192.168.100.1 port 47300 ...
15:33:37 lab-ubuntu-22 [sshd, pid: 926] Accepted publickey for labuser from 192.168.100.1 port 47306 ...
ef0d5f85d5673ec4b1b1a2da269e08448ee01e6ad260a72aab39b954dad92771  t-02-window-auth-ssh-service-events.jsonl
```

All bounded auth-family rows are ordinary `sshd` orchestration context; no
`sudo` record occurs. These rows do not prove injection.

## T-05 - Synthesis and limitations

Timeline observes P01-P03 through `fs:stat` rows. It does not establish that
either binary executed or that a child shell, injected mapping, or connection
existed; those are memory findings. The Plaso store is a derived, targeted
examination product, not immutable run evidence. Two recoverable setup failures
are disclosed, and the 122-second timeline TTF includes them.

The stopping condition was reached after the 62-row location export and 23-row
auth export answered staging and session-context questions; the full store was
not exported wholesale.
