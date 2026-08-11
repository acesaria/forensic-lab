---
cwd: ../../../..
shell: bash
---

# ptrace_fa timeline investigation — Runme notebook

__Run:__ `ubuntu-22.04_ptrace_fa_20260807-150736`

**Scope:** a small, source-scoped examination of the accepted Plaso storage,
intentionally small: P01–P03 only (staging/build). P05–P08 are memory-only
runtime targets and are not re-examined here.

Case-level per-artifact and aggregate metrics are recorded in
[runme_case_summary.md](./runme_case_summary.md); this notebook retains the
timeline observations and limitations that support them.

> [!IMPORTANT]
> Run cells in order from the repository root and in one Runme terminal. The
> accepted Plaso storage is immutable and is not rerun. This notebook never
> reads the full raw `timeline.jsonl` export; its only new output is small
> bounded JSONL views beneath this run's `derived/timeline/` directory.

## T-00 - Case boundary, acquisition status, and Plaso scope disclosure

**Question:** Is this the completed authoritative run, does the Plaso storage
used below match the recorded raw-extraction authority, and what did that
extraction actually collect?

```bash {"name":"T-00-Case-Boundary-and-Integrity","promptEnv":"never"}
set -euo pipefail

RUN_ID='ubuntu-22.04_ptrace_fa_20260807-150736'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
MANIFEST="$RUN_DIR/manifest.json"
ACQUISITION="$RUN_DIR/dumps/acquisition.json"
RAW_STATUS="$RUN_DIR/analysis/raw_extraction_status.json"
PLASO="$RUN_DIR/analysis/timeline.plaso"
TIMELINE_DIR="$INV_DIR/derived/timeline"

jq -e --arg run "$RUN_ID" '
  .run_id == $run and .scenario_id == "ptrace_fa" and .status == "completed"
  and .repository.commit == "29bbcfcc24509f84497eb5bf09e04cb358d97bbe"
' "$MANIFEST" >/dev/null
jq -e --arg run "$RUN_ID" '
  .run_id == $run
  and .memory_image.commands[0].status == "completed"
  and .disk_preparation == "powered_off"
  and .disk_image.verification.status == "completed"
  and .disk_image.verification.exit_status == 0
' "$ACQUISITION" >/dev/null
jq -e '.plaso.status == "completed" and .plaso.event_count == 14928' "$RAW_STATUS" >/dev/null

[[ "$(stat -c '%s' "$PLASO")" == "$(jq -er '.plaso.outputs.storage.size_bytes' "$RAW_STATUS")" ]]
[[ "$(sha256sum "$PLASO" | cut -d' ' -f1)" == "$(jq -er '.plaso.outputs.storage.sha256' "$RAW_STATUS")" ]]

mkdir -p "$TIMELINE_DIR"
export RUN_ID="$RUN_ID"
export RUN_DIR="$RUN_DIR"
export INV_DIR="$INV_DIR"
export MANIFEST="$MANIFEST"
export PLASO="$PLASO"
export TIMELINE_DIR="$TIMELINE_DIR"

printf 'run=%s\nplaso=%s\nplaso_size=%s\nplaso_sha256=%s\nplaso_events=14928\n' \
  "$RUN_ID" "$PLASO" "$(stat -c '%s' "$PLASO")" "$(sha256sum "$PLASO" | cut -d' ' -f1)"
printf 'disk_ewfverify=completed exit=0; memory_acquisition=completed\n'

jq -r '
  .plaso.invocations.log2timeline.command as $c
  | ($c | index("--parsers")) as $pi
  | ($c | index("--file-filter")) as $fi
  | "parsers=" + $c[$pi+1] + "\nfile_filter=" + $c[$fi+1]
' "$RAW_STATUS"
```

**Output**

```text {"ignore":"true"}
run=ubuntu-22.04_ptrace_fa_20260807-150736
plaso=shared/experiments/ubuntu-22.04_ptrace_fa_20260807-150736/analysis/timeline.plaso
plaso_size=7929856
plaso_sha256=81eda3f98b29369bd079a782424e25f4cbf84b0f358f35093acf5c17719ae504
plaso_events=14928
disk_ewfverify=completed exit=0; memory_acquisition=completed
parsers=text/bash_history, text/syslog, text/syslog_traditional, systemd_journal, filestat
file_filter=/home/anto/linux-multisource-dfir-lab/orchestrator/forensics/filters/linux_common.yaml
```

__Assessment.__ The manifest, acquisition sidecar and raw-extraction sidecar
agree on the run and the current committed revision; stored Plaso size and
SHA-256 match. The accepted store is the same __targeted__ collection used in
the Father cleanup case (`orchestrator/forensics/filters/linux_common.yaml`,
same five parsers). `/tmp` is one of the filtered paths, which is what makes
this scenario's staging tree visible to Plaso at all.

## T-01 - Define the bounded examination

**Question:** What narrow window answers the staging question without
reading the full timeline?

```bash {"name":"T-01-Bounded-Window","promptEnv":"never"}
set -euo pipefail

SCENARIO_START_UTC="$(jq -er '.timestamps.scenario_started_at' "$MANIFEST")"
SCENARIO_END_UTC="$(jq -er '.timestamps.scenario_ended_at' "$MANIFEST")"
GUEST_TIMEZONE="$(jq -er '.platform.timezone' "$MANIFEST")"
WINDOW_CENTER='2026-08-07T13:07:44+00:00'
SLICE_SIZE_MINUTES=1

export WINDOW_CENTER="$WINDOW_CENTER"
export SLICE_SIZE_MINUTES="$SLICE_SIZE_MINUTES"

printf 'scenario_start=%s\nscenario_end=%s\nguest_timezone=%s\n' \
  "$SCENARIO_START_UTC" "$SCENARIO_END_UTC" "$GUEST_TIMEZONE"
printf 'psort_slice_center=%s\npsort_slice_size=%s minute each side\n' \
  "$WINDOW_CENTER" "$SLICE_SIZE_MINUTES"
```

**Output**

```text {"ignore":"true"}
scenario_start=2026-08-07T13:07:36.773Z
scenario_end=2026-08-07T13:07:44.767Z
guest_timezone=Etc/UTC
psort_slice_center=2026-08-07T13:07:44+00:00
psort_slice_size=1 minute each side
```

The scenario itself spans under 8 seconds. The resulting `psort` slice,
`13:06:44`–`13:08:44 UTC`, is far wider than that so nearby filesystem and
service context stays visible while the query remains small.

## T-02 - Inventory the event families present in the window

**Question:** Which parsers actually produced events in this window?

```bash {"name":"T-02-Event-Family-Inventory","promptEnv":"never"}
set -euo pipefail

WINDOW_SCRATCH="$(mktemp -u /tmp/ptrace-fa-window-inventory-XXXX.jsonl)"
psort -q --status_view none \
  --slice "$WINDOW_CENTER" --slice_size "$SLICE_SIZE_MINUTES" \
  --output_time_zone UTC -o json_line -w "$WINDOW_SCRATCH" \
  "$PLASO"

printf 'window_events=%s\n' "$(wc -l <"$WINDOW_SCRATCH")"
jq -r '.data_type' "$WINDOW_SCRATCH" | sort | uniq -c | sort -rn
rm -f "$WINDOW_SCRATCH"
```

**Output**

```text {"ignore":"true"}
window_events=3195
   1484 syslog:line
   1261 systemd:journal
    450 fs:stat
```

Only three `data_type` values occur, matching the enabled parser set. No
`bash_history` event data type occurs even though `text/bash_history` was
enabled — a valid negative for this run, consistent with the scenario's
commands running over an interactive SSH terminal rather than a login shell
whose history file was captured by this filter.

## T-03 - Staging-tree filesystem observations (P01-P03)

**Question:** What does the generic `/tmp/` filesystem-timestamp view show,
selected by location alone, before any scenario-specific name is used?

```bash {"name":"T-03-Export-Bounded-Location-Timeline","promptEnv":"never"}
set -euo pipefail

EVENT_EXPORT="$TIMELINE_DIR/t-01-window-location-events.jsonl"
export EVENT_EXPORT="$EVENT_EXPORT"
EXPECTED_EVENT_EXPORT_SHA256='ee76f5fce76ac2e9875a28de8e8e2cb88304230cef3b874de82b2ed0883869e6'

if [[ -s "$EVENT_EXPORT" ]]; then
  printf 'reusing=%s\n' "$EVENT_EXPORT"
else
  psort -q --status_view none \
    --slice "$WINDOW_CENTER" --slice_size "$SLICE_SIZE_MINUTES" \
    --output_time_zone UTC -o json_line -w "$EVENT_EXPORT" \
    "$PLASO" \
    "filename contains '/tmp/'"
fi

[[ "$(sha256sum "$EVENT_EXPORT" | cut -d' ' -f1)" == "$EXPECTED_EVENT_EXPORT_SHA256" ]]
printf 'export=%s\nexport_events=%s\n' "$EVENT_EXPORT" "$(wc -l <"$EVENT_EXPORT")"
jq -r '.data_type' "$EVENT_EXPORT" | sort | uniq -c
```

**Output**

```text {"ignore":"true"}
export=shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/timeline/t-01-window-location-events.jsonl
export_events=78
     78 fs:stat
```

```bash {"name":"T-03-Show-Staging-Rows","promptEnv":"never"}
set -euo pipefail

jq -r '
  select(.timestamp_desc == "Creation Time" and (.filename | test("/ptrace_fa")))
  | [(.timestamp / 1000000 | floor | strftime("%Y-%m-%dT%H:%M:%SZ")), .filename, .inode]
  | @tsv
' "$EVENT_EXPORT" | sort
```

**Output**

```text {"ignore":"true"}
2026-08-07T13:07:38Z	/tmp/forensic-lab/ptrace_fa	258110
2026-08-07T13:07:38Z	/tmp/forensic-lab/ptrace_fa/common	258114
2026-08-07T13:07:38Z	/tmp/forensic-lab/ptrace_fa/src	258111
2026-08-07T13:07:39Z	/tmp/forensic-lab/ptrace_fa/common/ptrace_utils.c	258150
2026-08-07T13:07:39Z	/tmp/forensic-lab/ptrace_fa/common/ptrace_utils.h	258151
2026-08-07T13:07:39Z	/tmp/forensic-lab/ptrace_fa/common/utils.c	258154
2026-08-07T13:07:39Z	/tmp/forensic-lab/ptrace_fa/common/utils.h	258157
2026-08-07T13:07:39Z	/tmp/forensic-lab/ptrace_fa/src/shellcode_inject_fa.c	258158
2026-08-07T13:07:39Z	/tmp/forensic-lab/ptrace_fa/src/victim.c	258149
2026-08-07T13:07:42Z	/tmp/forensic-lab/ptrace_fa/shellcode_inject_fa	258148
2026-08-07T13:07:43Z	/tmp/forensic-lab/ptrace_fa/victim	258159
2026-08-07T13:07:43Z	/tmp/forensic-lab/ptrace_fa/victim.log	258160
```

__Observations (P01-P03).__ The generic `/tmp/` location export — selected
purely by path, matched against `filename` before any `ptrace_fa` string
search — already contains `fs:stat` "Creation Time" records for the complete
source tree (`P01`, inodes `258110`, `258111`, `258114`, `258149`–`258151`,
`258154`, `258157`–`258158`), the compiled injector (`P03`, inode `258148`,
`13:07:42Z`), and the compiled victim (`P02`, inode `258159`, `13:07:43Z`),
in build order. Every filename/inode pair matches the disk investigation's
independent TSK resolution (D-01–D-03) exactly, because both read the same
acquired ext4 inode structure through different tools: this is __parser-level
replication__ between filesystem and timeline for these three targets, not
two independently acquired sources. It rules out a TSK-specific or
Plaso-specific tool error, but not a forged or misread on-disk structure.

## T-04 - Bounded authentication/session context

**Question:** Does ordinary authentication/session activity in the window
show anything scenario-specific, or only expected orchestration access?

```bash {"name":"T-04-Auth-Context","promptEnv":"never"}
set -euo pipefail

AUTH_EXPORT="$TIMELINE_DIR/t-02-window-auth-ssh-service-events.jsonl"
export AUTH_EXPORT="$AUTH_EXPORT"
EXPECTED_AUTH_EXPORT_SHA256='c9725bb2797418da62bcc784ab619ea768adffaa8cf208dcc66a121bf5d461de'

if [[ -s "$AUTH_EXPORT" ]]; then
  printf 'reusing=%s\n' "$AUTH_EXPORT"
else
  psort -q --status_view none \
    --slice "$WINDOW_CENTER" --slice_size "$SLICE_SIZE_MINUTES" \
    --output_time_zone UTC -o json_line -w "$AUTH_EXPORT" \
    "$PLASO" \
    "(data_type is 'syslog:line' or data_type is 'systemd:journal') and (reporter is 'sshd' or reporter is 'sudo')"
fi

[[ "$(sha256sum "$AUTH_EXPORT" | cut -d' ' -f1)" == "$EXPECTED_AUTH_EXPORT_SHA256" ]]
printf 'export=%s\nexport_events=%s\n' "$AUTH_EXPORT" "$(wc -l <"$AUTH_EXPORT")"
jq -r '.reporter' "$AUTH_EXPORT" | sort | uniq -c

jq -r '
  select(.data_type == "systemd:journal" and (.message | contains("Accepted publickey")))
  | [(.timestamp / 1000000 | strftime("%H:%M:%S")), .message]
  | @tsv
' "$AUTH_EXPORT"
```

**Output**

```text {"ignore":"true"}
export=shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/timeline/t-02-window-auth-ssh-service-events.jsonl
export_events=22
     22 sshd
13:07:29	lab-ubuntu-22 [sshd, pid: 457] Accepted publickey for labuser from 192.168.100.1 port 53256 ssh2: ED25519 SHA256:b+sPbwXWklIm2oxWubk7bIEnom4awIHQPkaKP93zfGs
13:07:36	lab-ubuntu-22 [sshd, pid: 564] Accepted publickey for labuser from 192.168.100.1 port 49880 ssh2: ED25519 SHA256:b+sPbwXWklIm2oxWubk7bIEnom4awIHQPkaKP93zfGs
13:07:37	lab-ubuntu-22 [sshd, pid: 567] Accepted publickey for labuser from 192.168.100.1 port 49886 ssh2: ED25519 SHA256:b+sPbwXWklIm2oxWubk7bIEnom4awIHQPkaKP93zfGs
```

__Observation.__ All 22 auth-family records are `sshd`; there is no `sudo`
record in this window, consistent with `ptrace_fa` requiring no privilege
escalation (attach against a same-UID process). The three accepted-key
sessions are ordinary orchestration SSH access carrying the terminal commands
that staged, built, launched and injected the victim — not a separate
scenario-specific finding.

## T-05 - Methodological check: scenario-name search pitfall

__Question:__ Does searching for the literal scenario name `ptrace_fa`
change what is found, given that this run's own evidence path contains that
string?

```bash {"name":"T-05-Naive-Grep-Pitfall","promptEnv":"never"}
set -euo pipefail

TOTAL_RECORDS=$(wc -l <"$AUTH_EXPORT")
NAIVE_MATCHES=$(grep -ic ptrace_fa "$AUTH_EXPORT")
CONTENT_MATCHES=$(jq -r 'select((.message // "" | test("ptrace_fa";"i")) or (.filename // "" | test("ptrace_fa";"i")))' "$AUTH_EXPORT" | jq -s 'length')

printf 'total_records=%s\nnaive_whole_record_grep_matches=%s\ncontent_field_restricted_matches=%s\n' \
  "$TOTAL_RECORDS" "$NAIVE_MATCHES" "$CONTENT_MATCHES"

echo "why the naive whole-record grep over-matches:"
jq -r '.pathspec.parent.parent.parent.location' "$AUTH_EXPORT" | head -1
```

**Output**

```text {"ignore":"true"}
total_records=22
naive_whole_record_grep_matches=22
content_field_restricted_matches=0
why the naive whole-record grep over-matches:
/home/anto/linux-multisource-dfir-lab/shared/experiments/ubuntu-22.04_ptrace_fa_20260807-150736/dumps/disk/evidence_disk.E01
```

__Negative finding, methodological.__ Every exported psort JSON record embeds
the evidence image's own `pathspec`, and this run's evidence path contains
`ptrace_fa` because it is part of the run identifier — not because of
scenario content. A naive whole-record `grep` for the scenario name matches
all 22/22 `sshd` auth records, none of which mention `ptrace_fa` in their
parsed content. Restricting to the `.message`/`.filename` content fields
gives zero matches for this export, correctly reflecting that ordinary auth
records carry no scenario-specific string. This is the same self-referential
pitfall documented for the Father cleanup case, reproduced here without
relying on that case.

## T-06 - Findings, negative observations, and conclusion

| Status | Timeline result and limit |
| --- | --- |
| Observed | T-02's inventory contains only `fs:stat`, `syslog:line`, `systemd:journal`; no `bash_history` event occurs despite that parser being enabled. |
| Observed | T-03's generic `/tmp/`-only export contains `fs:stat` "Creation Time" rows for the complete staged source tree (P01), injector (P03) and victim (P02) executables, in build order, with inodes matching the disk investigation exactly (parser-level replication, not independent corroboration for these three targets). |
| Observed | T-04 shows only ordinary `sshd` orchestration sessions; no `sudo` record occurs in the window, consistent with a same-UID `ptrace` technique needing no privilege escalation. |
| Methodological negative | A naive whole-record `grep` for the scenario name `ptrace_fa` over exported psort JSON matches every record (22/22) because the evidence `pathspec` embeds the run identifier; restricting to parsed content fields is required for a real pivot (T-05). |
| Limitation | `fs:stat` supports a filesystem metadata event, not process execution; the timeline does not itself show the injector running or the victim's child shell. |
| Stopping condition | Stop after the bounded location export (78 events) and auth export (22 events) answer the staging question; the full 14,928-event store and the raw `timeline.jsonl` are not read. |

**Timeline conclusion:** The accepted Plaso storage's generic, location-based
`/tmp/` view — reached without any scenario-specific search — independently
resolves P01–P03 through the same ext4 `filestat` structure the disk
investigation reads directly. This is parser-level replication for these
three targets: it excludes a TSK- or Plaso-specific tool defect, but both
readings ultimately rest on one acquired filesystem, not two independent
acquisitions. Timeline evidence says nothing about the runtime
ptrace/injection behavior; that is memory's role (P05–P08).
