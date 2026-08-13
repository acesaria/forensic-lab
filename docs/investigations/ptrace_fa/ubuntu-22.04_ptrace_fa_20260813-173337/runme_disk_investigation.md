---
cwd: ../../../..
shell: bash
---

# ptrace_fa disk investigation — Runme notebook

__Run:__ `ubuntu-22.04_ptrace_fa_20260813-173337`

**Scope:** bounded TSK examination of prepared-binary staging (P01-P04), the
victim log, shell history, and relevant Linux logs. Command logs and terminal
transcripts remain scenario provenance, not disk evidence.

## D-00 - Case setup

```bash {"name":"D-00-Case-Setup","promptEnv":"never"}
set -euo pipefail

RUN_ID='ubuntu-22.04_ptrace_fa_20260813-173337'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
MANIFEST="$RUN_DIR/manifest.json"
ACQUISITION="$RUN_DIR/dumps/acquisition.json"
DISK_IMAGE="$RUN_DIR/dumps/disk/evidence_disk.E01"
DISK_DIR="$INV_DIR/derived/disk/d-01"

jq -e --arg run "$RUN_ID" '
  .run_id == $run and .scenario_id == "ptrace_fa"
  and .status == "completed" and .scenario_status == "completed"
  and .repository.commit == "aef7d0015bbcd1a87f051e16f4fe722f73507993-dirty"
' "$MANIFEST" >/dev/null
jq -e '
  .disk_preparation == "powered_off"
  and .disk_image.verification.status == "completed"
  and .disk_image.verification.exit_status == 0
' "$ACQUISITION" >/dev/null

mkdir -p "$DISK_DIR"
mmls -i ewf "$DISK_IMAGE"
ROOT_START_SECTOR=227328
FSSTAT_OUT="$DISK_DIR/d-00-fsstat.txt"
[[ -s "$FSSTAT_OUT" ]] || fsstat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" >"$FSSTAT_OUT"
sed -n '1,14p' "$FSSTAT_OUT"
export DISK_IMAGE DISK_DIR ROOT_START_SECTOR
```

**Output**

```text {"ignore":"true"}
GUID Partition Table (EFI)
Slot 006: start 0000227328, length 0020744159
FILE SYSTEM INFORMATION
File System Type: Ext4
Volume Name: cloudimg-rootfs
Last Mounted at: 2026-08-13 17:33:29 (CEST)
Unmounted properly
Last mounted on: /
```

The root filesystem is ext4 at sector 227328 and was unmounted properly. The
dirty revision is the disclosed deadline exception; all other acquisition
gates passed.

## D-01 - Generic temporary-staging discovery (P01)

```bash {"name":"D-01-Staging-Discovery","promptEnv":"never"}
set -euo pipefail

TMP_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /tmp "$DISK_IMAGE")"
fls -i ewf -o "$ROOT_START_SECTOR" -z Etc/UTC -l "$DISK_IMAGE" "$TMP_INODE"

FORENSIC_LAB_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /tmp/forensic-lab "$DISK_IMAGE")"
STAGING_LISTING="$DISK_DIR/staging-tree-recursive.txt"
fls -i ewf -o "$ROOT_START_SECTOR" -z Etc/UTC -l -r "$DISK_IMAGE" "$FORENSIC_LAB_INODE" | tee "$STAGING_LISTING"
```

**Output**

```text {"ignore":"true"}
r/r 74171: ptrace_fa-shellcode_inject_fa 2026-08-13 15:33:37 (UTC) 21768 1000 1000
r/r 74172: ptrace_fa-victim              2026-08-13 15:33:37 (UTC) 16136 1000 1000
d/d 258128: forensic-lab                 2026-08-13 15:33:38 (UTC) 4096  1000 1000
d/d 258129: ptrace_fa                    2026-08-13 15:33:38 (UTC) 4096  1000 1000
+ r/r 258130: shellcode_inject_fa        2026-08-13 15:33:38 (UTC) 21768 1000 1000
+ r/r 258131: victim                     2026-08-13 15:33:38 (UTC) 16136 1000 1000
+ r/r 258132: victim.log                 2026-08-13 15:33:38 (UTC) 22    1000 1000
```

**P01 observed.** Generic `/tmp` inspection exposes two upload-stage files and
the runtime directory containing the injector, victim, and log. Unlike the old
victim-build executor, there is no `src/` or `common/` tree and no compiler
output; that absence is expected under the prepared-input design.

## D-02 - Victim executable identity (P02)

```bash {"name":"D-02-Victim-Identity","promptEnv":"never"}
set -euo pipefail

VICTIM_INODE=258131
istat -i ewf -o "$ROOT_START_SECTOR" -z Etc/UTC "$DISK_IMAGE" "$VICTIM_INODE"
VICTIM_COPY="$DISK_DIR/victim"
[[ -e "$VICTIM_COPY" ]] || icat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" "$VICTIM_INODE" >"$VICTIM_COPY"
sha256sum "$VICTIM_COPY"
file -b "$VICTIM_COPY"
```

**Output**

```text {"ignore":"true"}
inode: 258131
Allocated
uid / gid: 1000 / 1000
mode: rrwxr-xr-x
size: 16136
File Created: 2026-08-13 15:33:38.156000000 (UTC)
951f93a6e76a77e6d7ef5dbab82887cfb306b31b3dad612c5e1282c80060bebc  victim
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

**P02 observed.** The allocated executable matches the preserved input hash.
Memory M-04 independently maps PID 1042 to this path and inode.

## D-03 - Injector executable identity (P03)

```bash {"name":"D-03-Injector-Identity","promptEnv":"never"}
set -euo pipefail

INJECTOR_INODE=258130
istat -i ewf -o "$ROOT_START_SECTOR" -z Etc/UTC "$DISK_IMAGE" "$INJECTOR_INODE"
INJECTOR_COPY="$DISK_DIR/shellcode_inject_fa"
[[ -e "$INJECTOR_COPY" ]] || icat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" "$INJECTOR_INODE" >"$INJECTOR_COPY"
sha256sum "$INJECTOR_COPY"
file -b "$INJECTOR_COPY"
```

**Output**

```text {"ignore":"true"}
inode: 258130
Allocated
uid / gid: 1000 / 1000
mode: rrwxr-xr-x
size: 21768
File Created: 2026-08-13 15:33:38.136000000 (UTC)
9c6c8f4ba79192dffa95f504c274fa1925b0b9d03d22820a968ee32d3572c8db  shellcode_inject_fa
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

**P03 observed.** The allocated injector matches the preserved input hash.

## D-04 - Static ptrace/foreign-allocation capability (P04)

```bash {"name":"D-04-Static-Capability","promptEnv":"never"}
set -euo pipefail

nm -D --dynamic --undefined-only "$INJECTOR_COPY" | grep -iE 'ptrace|waitpid'
strings -a "$INJECTOR_COPY" | grep -E 'ptrace|mmap:|Shellcode' | head -n 24
```

**Output**

```text {"ignore":"true"}
U ptrace@GLIBC_2.2.5
U waitpid@GLIBC_2.2.5
[+] mmap: 0x%lx (%du bytes)
[+] Shellcode iniettato a 0x%lx
[+] Shellcode eseguito
ptrace ATTACH
ptrace DETACH
ptrace GETREGS
ptrace SETREGS
ptrace CONT
ptrace_cont
ptrace_attach
ptrace_write
ptrace_getregs
ptrace_read
ptrace_detach
ptrace_step
ptrace_setregs
```

**P04 observed, static capability only.** The recovered binary imports
`ptrace`/`waitpid` and retains attach/detach, register-control, continuation,
remote-mapping, and injected-shellcode symbols/messages. No source file was
placed on the victim by this executor. These static observations do not prove
runtime injection; memory P05-P08 does.

## D-05 - Victim log, shell history, and Linux logs

```bash {"name":"D-05-History-And-Logs","promptEnv":"never"}
set -euo pipefail

HISTORY_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /home/labuser/.bash_history "$DISK_IMAGE")"
HISTORY_COPY="$DISK_DIR/labuser_bash_history"
[[ -e "$HISTORY_COPY" ]] || icat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" "$HISTORY_INODE" >"$HISTORY_COPY"
sha256sum "$HISTORY_COPY"
cat "$HISTORY_COPY"

VICTIM_LOG_COPY="$DISK_DIR/victim.log"
cat -A "$VICTIM_LOG_COPY"

for NAME in auth.log syslog kern.log; do
  INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n "/var/log/$NAME" "$DISK_IMAGE")"
  [[ -e "$DISK_DIR/$NAME" ]] || icat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" "$INODE" >"$DISK_DIR/$NAME"
done
grep -E 'Aug 13 15:33:3[5-9]|Aug 13 15:33:40' "$DISK_DIR/auth.log"
grep -E 'Aug 13 15:33:3[5-9]|Aug 13 15:33:40' "$DISK_DIR/kern.log"
printf 'audit_lookup=%s\n' "$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /var/log/audit "$DISK_IMAGE")"
```

**Output**

```text {"ignore":"true"}
2be68a70f0d7cf14bda3d4976db5e8a9e05b421a399ef3ed870aa9edf9fe0c19  labuser_bash_history
. /etc/os-release; printf '%s-%s %s\n' "$ID" "$VERSION_ID" "$(uname -m)"
mkdir -p /tmp/forensic-lab/ptrace_fa
install -m 0755 /tmp/ptrace_fa-shellcode_inject_fa /tmp/forensic-lab/ptrace_fa/shellcode_inject_fa
install -m 0755 /tmp/ptrace_fa-victim /tmp/forensic-lab/ptrace_fa/victim
cd /tmp/forensic-lab/ptrace_fa
id -un
nohup ./victim >/tmp/forensic-lab/ptrace_fa/victim.log 2>&1 & disown; echo $!
./shellcode_inject_fa 1042
kill -0 1042 && echo alive
exit
nohup: ignoring input$
Aug 13 15:33:36 ... Accepted publickey for labuser ...
Aug 13 15:33:37 ... Accepted publickey for labuser ...
Aug 13 15:33:38 ... session closed for user labuser
Aug 13 15:33:38 ... process 'victim' launched '/bin/sh' with NULL argv: empty string added
audit_lookup=File not found
```

The 502-byte history is allocated and untimestamped. It records command text
and order only, not per-command time, success, or completeness. Crucially, it
contains installation commands but no compiler/build commands, consistent with
the prepared-input executor. `victim.log` contains only `nohup` boilerplate and
does not prove injection. The bounded auth window contains ordinary SSH
orchestration sessions. `kern.log` records an exec message, not proof of a
successful shell or ptrace attachment. No audit directory exists on this
vanilla victim.

## D-06 - Synthesis

| Target | Result | Locator | Limitation |
|---|---|---|---|
| P01 | O | Runtime tree inode 258129; upload files 74171/74172 | Prepared binaries only; source/build tree intentionally absent. |
| P02 | O | Victim inode 258131, SHA-256 `951f93a6...` | Staging identity; execution is memory evidence. |
| P03 | O | Injector inode 258130, SHA-256 `9c6c8f4b...` | Injector exited before memory acquisition. |
| P04 | O | Recovered binary imports/symbols/messages | Static capability, not runtime proof. |

No deletion occurred and no carving was required. Disk provides static/runtime
staging context; RAM remains authoritative for injection behavior.
