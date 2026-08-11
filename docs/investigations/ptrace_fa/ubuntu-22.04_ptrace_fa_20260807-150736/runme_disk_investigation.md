---
cwd: ../../../..
shell: bash
---

# ptrace_fa disk investigation — Runme notebook

__Run:__ `ubuntu-22.04_ptrace_fa_20260807-150736`

**Scope:** post-mortem examination of the acquired disk and its ext4 root
filesystem, intentionally small: P01–P04 only. P04 is bounded to static
capability, not runtime proof — that is memory's role (see the memory
notebook).

Case-level per-artifact and aggregate metrics are recorded in
[runme_case_summary.md](./runme_case_summary.md); this notebook retains the
filesystem observations and limitations that support them.

> [!IMPORTANT]
> Run the cells in order from the repository root and in the same Runme
> terminal session. The acquired EWF image is read-only evidence; notebook
> output is written beneath `shared/investigations/.../derived/disk/`.

## Method

Preservation and acquisition are already complete. This notebook covers only
examination and analysis (NIST SP 800-86 terminology), using read-only TSK
commands (`mmls`, `fsstat`, `ifind`, `fls`, `istat`, `icat`) against the
immutable EWF image. Nothing was intentionally deleted in this scenario, so no
carving or recovery experiment is used.

## D-00 - Case setup

```bash {"name":"D-00-Case-Setup","promptEnv":"never"}
set -euo pipefail

printf '\n[D-00] Case setup\n'

RUN_ID='ubuntu-22.04_ptrace_fa_20260807-150736'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
export INV_DIR="$INV_DIR"
MANIFEST="$RUN_DIR/manifest.json"
RAW_STATUS="$RUN_DIR/analysis/raw_extraction_status.json"

jq -e --arg run "$RUN_ID" '
  .run_id == $run and .scenario_id == "ptrace_fa" and .status == "completed"
  and .repository.commit == "29bbcfcc24509f84497eb5bf09e04cb358d97bbe"
' "$MANIFEST" >/dev/null
jq -e '.tsk.status == "completed"' "$RAW_STATUS" >/dev/null

DISK_IMAGE="$RUN_DIR/dumps/disk/evidence_disk.E01"
export DISK_IMAGE="$DISK_IMAGE"
GUEST_TIMEZONE="$(jq -er '.platform.timezone' "$MANIFEST")"
export GUEST_TIMEZONE="$GUEST_TIMEZONE"

# mmls is a read-only TSK partition-table inspection of the immutable EWF
# image; it is not a rerun of the raw extraction pipeline.
mmls -i ewf "$DISK_IMAGE" | sed 's/[ \t]*$//'

ROOT_START_SECTOR=227328
export ROOT_START_SECTOR="$ROOT_START_SECTOR"

FSSTAT_OUT="$(fsstat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" 2>&1)"
printf '%s\n' "$FSSTAT_OUT" | head -n 12

D01_DIR="$INV_DIR/derived/disk/d-01"
export D01_DIR="$D01_DIR"
mkdir -p "$D01_DIR"

printf 'disk=%s\nroot_start_sector=%s\nguest_timezone=%s\nderived=%s\n' \
  "$DISK_IMAGE" "$ROOT_START_SECTOR" "$GUEST_TIMEZONE" "$D01_DIR"
```

**Output**

```text {"ignore":"true"}

[D-00] Case setup
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000033   0000000032   Partition Table
004:  013       0000002048   0000010239   0000008192
005:  014       0000010240   0000227327   0000217088
006:  000       0000227328   0008388574   0008161247
007:  -------   0008388575   0008388607   0000000033   Unallocated
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name: cloudimg-rootfs
Volume ID: 6139e552d013afaa4940f64706de0baa

Last Written at: 2026-03-20 12:14:06 (CET)
Last Checked at: 2026-03-20 12:06:58 (CET)

Last Mounted at: 2026-08-07 15:07:09 (CEST)
Unmounted properly
Last mounted on: /
disk=shared/experiments/ubuntu-22.04_ptrace_fa_20260807-150736/dumps/disk/evidence_disk.E01
root_start_sector=227328
guest_timezone=Etc/UTC
derived=shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/disk/d-01
```

Partition slot `000` at start sector `227328` is the ext4 root filesystem,
unmounted properly at acquisition. All following TSK commands use this
offset.

## D-01 - Discover the staging tree (P01)

**Question:** Without using the scenario or malware name, what survives under
the standard writable-temporary staging root every scenario in this lab uses?

```bash {"name":"D-01-Discover-Staging-Tree","promptEnv":"never"}
set -euo pipefail

printf '\n[D-01] Discover and enumerate the staging tree\n'

TMP_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /tmp "$DISK_IMAGE")"
fls -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" -l "$DISK_IMAGE" "$TMP_INODE" \
  | grep -v -E '^d/d [0-9]+:\s+\.'

FORENSIC_LAB_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /tmp/forensic-lab "$DISK_IMAGE")"
export FORENSIC_LAB_INODE="$FORENSIC_LAB_INODE"
printf '\nforensic_lab_inode=%s\n' "$FORENSIC_LAB_INODE"

STAGING_LISTING="$D01_DIR/staging-tree-recursive.txt"
fls -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" -l -r \
  "$DISK_IMAGE" "$FORENSIC_LAB_INODE" | tee "$STAGING_LISTING"
```

**Output**

```text {"ignore":"true"}

[D-01] Discover and enumerate the staging tree
d/d 258070:	snap-private-tmp	2026-08-07 13:07:11 (UTC)	2026-08-07 13:07:11 (UTC)	2026-08-07 13:07:11 (UTC)	2026-08-07 13:07:11 (UTC)	4096	0	0
d/d 258108:	forensic-lab	2026-08-07 13:07:38 (UTC)	2026-08-07 13:07:38 (UTC)	2026-08-07 13:07:38 (UTC)	2026-08-07 13:07:38 (UTC)	4096	1000	1000

forensic_lab_inode=258108
d/d 258110:	ptrace_fa	2026-08-07 13:07:43 (UTC)	2026-08-07 13:07:38 (UTC)	2026-08-07 13:07:43 (UTC)	2026-08-07 13:07:38 (UTC)	4096	1000	1000
+ d/d 258111:	src	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:38 (UTC)	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:38 (UTC)	4096	1000	1000
++ r/r 258158:	shellcode_inject_fa.c	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:39 (UTC)	4915	1000	1000
++ r/r 258149:	victim.c	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:42 (UTC)	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:39 (UTC)	1148	1000	1000
+ d/d 258114:	common	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:38 (UTC)	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:38 (UTC)	4096	1000	1000
++ r/r 258150:	ptrace_utils.c	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:41 (UTC)	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:39 (UTC)	2631	1000	1000
++ r/r 258151:	ptrace_utils.h	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:40 (UTC)	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:39 (UTC)	722	1000	1000
++ r/r 258154:	utils.c	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:41 (UTC)	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:39 (UTC)	3052	1000	1000
++ r/r 258157:	utils.h	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:40 (UTC)	2026-08-07 13:07:39 (UTC)	2026-08-07 13:07:39 (UTC)	468	1000	1000
+ r/r 258148:	shellcode_inject_fa	2026-08-07 13:07:42 (UTC)	2026-08-07 13:07:43 (UTC)	2026-08-07 13:07:42 (UTC)	2026-08-07 13:07:42 (UTC)	21768	1000	1000
+ r/r 258159:	victim	2026-08-07 13:07:43 (UTC)	2026-08-07 13:07:43 (UTC)	2026-08-07 13:07:43 (UTC)	2026-08-07 13:07:43 (UTC)	16136	1000	1000
+ r/r 258160:	victim.log	2026-08-07 13:07:43 (UTC)	2026-08-07 13:07:43 (UTC)	2026-08-07 13:07:43 (UTC)	2026-08-07 13:07:43 (UTC)	22	1000	1000
```

__P01 is observed.__ The standard `forensic-lab` staging root (used by every
scenario in this lab, not a planted name specific to `ptrace_fa`) contains an
allocated `ptrace_fa` tree with a complete `src/`+`common/` source layout
(4 `.c`/`.h` files), two compiled ELF outputs, and a small `victim.log`
artifact — all allocated, all owned by uid/gid `1000`, all created within
seconds of each other around `13:07:38`–`13:07:43 UTC`.

## D-02 - Victim executable identity (P02)

**Question:** Is the compiled victim executable present at its staging path,
and what identifies it?

```bash {"name":"D-02-Victim-Executable","promptEnv":"never"}
set -euo pipefail

printf '\n[D-02] Victim executable metadata and identity\n'

VICTIM_INODE=258159
export VICTIM_INODE="$VICTIM_INODE"
istat -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" "$DISK_IMAGE" "$VICTIM_INODE"

VICTIM_COPY="$D01_DIR/victim"
export VICTIM_COPY="$VICTIM_COPY"
if [[ -e "$VICTIM_COPY" ]]; then
  printf 'Retaining existing derived copy: %s\n' "$VICTIM_COPY"
else
  icat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" "$VICTIM_INODE" >"$VICTIM_COPY"
  chmod a-w "$VICTIM_COPY"
fi
sha256sum "$VICTIM_COPY"
file -b "$VICTIM_COPY"
```

**Output**

```text {"ignore":"true"}

[D-02] Victim executable metadata and identity
inode: 258159
Allocated
Group: 16
Generation Id: 3024410169
uid / gid: 1000 / 1000
mode: rrwxrwxr-x
Flags: Extents, 
size: 16136
num of links: 1

Inode Times:
Accessed:	2026-08-07 13:07:43.511107148 (UTC)
File Modified:	2026-08-07 13:07:43.379107148 (UTC)
Inode Modified:	2026-08-07 13:07:43.379107148 (UTC)
File Created:	2026-08-07 13:07:43.087107148 (UTC)

Direct Blocks:
1015826 1015827 1015828 1015829 
951f93a6e76a77e6d7ef5dbab82887cfb306b31b3dad612c5e1282c80060bebc  shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/disk/d-01/victim
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2cd41145ea0dc980504591fe2b4d7a34d1559c68, for GNU/Linux 3.2.0, not stripped
```

__P02 is observed.__ `/tmp/forensic-lab/ptrace_fa/victim`, inode `258159`, is
an allocated, executable ELF binary, 16,136 bytes, SHA-256
`951f93a6...060bebc`. The memory notebook (M-04) independently maps this same
path and inode in the live victim process's own executable mapping.

## D-03 - Injector executable identity (P03)

**Question:** Is the compiled injector present at its staging path?

```bash {"name":"D-03-Injector-Executable","promptEnv":"never"}
set -euo pipefail

printf '\n[D-03] Injector executable metadata and identity\n'

INJECTOR_INODE=258148
export INJECTOR_INODE="$INJECTOR_INODE"
istat -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" "$DISK_IMAGE" "$INJECTOR_INODE"

INJECTOR_COPY="$D01_DIR/shellcode_inject_fa"
export INJECTOR_COPY="$INJECTOR_COPY"
if [[ -e "$INJECTOR_COPY" ]]; then
  printf 'Retaining existing derived copy: %s\n' "$INJECTOR_COPY"
else
  icat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" "$INJECTOR_INODE" >"$INJECTOR_COPY"
  chmod a-w "$INJECTOR_COPY"
fi
sha256sum "$INJECTOR_COPY"
file -b "$INJECTOR_COPY"
```

**Output**

```text {"ignore":"true"}

[D-03] Injector executable metadata and identity
inode: 258148
Allocated
Group: 16
Generation Id: 3766687195
uid / gid: 1000 / 1000
mode: rrwxrwxr-x
Flags: Extents, 
size: 21768
num of links: 1

Inode Times:
Accessed:	2026-08-07 13:07:43.523107148 (UTC)
File Modified:	2026-08-07 13:07:42.631107148 (UTC)
Inode Modified:	2026-08-07 13:07:42.631107148 (UTC)
File Created:	2026-08-07 13:07:42.359107148 (UTC)

Direct Blocks:
589872 589873 589874 589875 589876 589877 
9c6c8f4ba79192dffa95f504c274fa1925b0b9d03d22820a968ee32d3572c8db  shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/disk/d-01/shellcode_inject_fa
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c13f5039217b6170d26a78763ae2d196c13707f9, for GNU/Linux 3.2.0, not stripped
```

__P03 is observed.__ `/tmp/forensic-lab/ptrace_fa/shellcode_inject_fa`, inode
`258148`, is an allocated, executable ELF binary, 21,768 bytes, SHA-256
`9c6c8f4b...3572c8db`, created about 0.7s before the victim executable — both
around the time the recursive `src`/`common` source files were also created
(D-01), consistent with a single ordinary build sequence.

## D-04 - Injector ptrace capability (P04, static only)

**Question:** Does the recovered injector, statically, implement
ptrace-based process injection? This is capability evidence, not proof of
execution — memory M-05/M-06 addresses runtime behavior separately.

```bash {"name":"D-04-Ptrace-Capability","promptEnv":"never"}
set -euo pipefail

printf '\n[D-04] Static ptrace-capability check\n'

echo "-- imported dynamic symbols (binary) --"
nm -D --dynamic --undefined-only "$INJECTOR_COPY" | grep -iE 'ptrace|waitpid'

PTRACE_UTILS_INODE=258150
export PTRACE_UTILS_INODE="$PTRACE_UTILS_INODE"
PTRACE_UTILS_COPY="$D01_DIR/ptrace_utils.c"
export PTRACE_UTILS_COPY="$PTRACE_UTILS_COPY"
if [[ -e "$PTRACE_UTILS_COPY" ]]; then
  printf 'Retaining existing derived copy: %s\n' "$PTRACE_UTILS_COPY"
else
  icat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" "$PTRACE_UTILS_INODE" >"$PTRACE_UTILS_COPY"
  chmod a-w "$PTRACE_UTILS_COPY"
fi
sha256sum "$PTRACE_UTILS_COPY"

echo "-- recovered common/ptrace_utils.c: ptrace() call sites --"
grep -n 'ptrace(' "$PTRACE_UTILS_COPY"

INJECTOR_SRC_INODE=258158
export INJECTOR_SRC_INODE="$INJECTOR_SRC_INODE"
INJECTOR_SRC_COPY="$D01_DIR/shellcode_inject_fa.c"
export INJECTOR_SRC_COPY="$INJECTOR_SRC_COPY"
if [[ -e "$INJECTOR_SRC_COPY" ]]; then
  printf 'Retaining existing derived copy: %s\n' "$INJECTOR_SRC_COPY"
else
  icat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" "$INJECTOR_SRC_INODE" >"$INJECTOR_SRC_COPY"
  chmod a-w "$INJECTOR_SRC_COPY"
fi
sha256sum "$INJECTOR_SRC_COPY"

echo "-- recovered src/shellcode_inject_fa.c: foreign-allocation setup --"
grep -n '__NR_mmap\|mmap_addr\|shellcode\[' "$INJECTOR_SRC_COPY" | head -n 6
```

**Output**

```text {"ignore":"true"}

[D-04] Static ptrace-capability check
-- imported dynamic symbols (binary) --
                 U ptrace@GLIBC_2.2.5
                 U waitpid@GLIBC_2.2.5
fdaf5af7a577569282afeef423bf375a2741d5f2ebecca9f1d8b8634864ecc70  shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/disk/d-01/ptrace_utils.c
-- recovered common/ptrace_utils.c: ptrace() call sites --
17:    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
24:        ptrace(PTRACE_DETACH, pid, NULL, NULL);
32:    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
40:    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1) {
48:    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) {
63:        long word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL);
82:        long word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL);
88:        if (ptrace(PTRACE_POKETEXT, pid, addr + i, word) == -1) {
98:    if (ptrace(PTRACE_CONT, pid, NULL, (void*)(long)signal) == -1) {
109:    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
08b50717b663b29a786084e4b7fbfe0b6d94f48d7707529feb283d25825c52be  shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/disk/d-01/shellcode_inject_fa.c
-- recovered src/shellcode_inject_fa.c: foreign-allocation setup --
24:unsigned char shellcode[] = {
62:    regs_mod.rax = 9;              // __NR_mmap
107:    unsigned long mmap_addr = regs_mod.rax;
108:    printf("[+] mmap: 0x%lx (%du bytes)\n", mmap_addr, sc_len);
118:    if (procfs_proc_mem_write(mmap_addr, pid, shellcode, sc_len) < 0) { //ptrace_write(pid, mmap_addr, shellcode, sc_len)
124:    printf("[+] Shellcode iniettato a 0x%lx\n", mmap_addr); 
```

__P04 is observed, bounded to static capability.__ The recovered injector
binary imports `ptrace`/`waitpid`; its recovered `common/ptrace_utils.c`
(inode `258150`, SHA-256 `fdaf5af7...4864ecc70`) implements
`PTRACE_ATTACH`/`PTRACE_GETREGS`/`PTRACE_SETREGS`/`PTRACE_PEEKTEXT`/
`PTRACE_POKETEXT`/`PTRACE_CONT`/`PTRACE_SINGLESTEP`/`PTRACE_DETACH`, and its
recovered `src/shellcode_inject_fa.c` (inode `258158`, SHA-256
`08b50717...25825c52be`) sets up a remote `__NR_mmap` (foreign memory
allocation) syscall via register injection before writing shellcode into the
allocated region. This is static source evidence of capability. It does not
by itself show the injector ran against the victim — that is established
separately by memory (P05–P08).

## D-05 - Shell history and Linux log examination (contextual)

**Question:** Per the repository's shell-history/log examination policy, what
do the relevant accounts' command histories and the principal `/var/log`
sources record, without searching by the scenario or run name? These are
contextual filesystem findings, not new P-targets.

```bash {"name":"D-05-History-And-Logs","promptEnv":"never"}
set -euo pipefail

printf '\n[D-05] Shell history and Linux log examination (contextual, not a P-target)\n'

echo "-- labuser bash history: metadata --"
LABUSER_HISTORY_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /home/labuser/.bash_history "$DISK_IMAGE")"
istat -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" "$DISK_IMAGE" "$LABUSER_HISTORY_INODE"

LABUSER_HISTORY_COPY="$D01_DIR/labuser_bash_history"
if [[ -e "$LABUSER_HISTORY_COPY" ]]; then
  printf 'Retaining existing derived copy: %s\n' "$LABUSER_HISTORY_COPY"
else
  icat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" "$LABUSER_HISTORY_INODE" >"$LABUSER_HISTORY_COPY"
  chmod a-w "$LABUSER_HISTORY_COPY"
fi
sha256sum "$LABUSER_HISTORY_COPY"

echo "-- labuser bash history: complete content (643 bytes, untimestamped) --"
cat "$LABUSER_HISTORY_COPY"

echo "-- root account: bounded bash-history lookup --"
ROOT_HOME_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /root "$DISK_IMAGE")"
fls -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" -l "$DISK_IMAGE" "$ROOT_HOME_INODE"

echo "-- victim.log: metadata (inode 258160) --"
VICTIM_LOG_INODE=258160
istat -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" "$DISK_IMAGE" "$VICTIM_LOG_INODE"

VICTIM_LOG_COPY="$D01_DIR/victim.log"
if [[ -e "$VICTIM_LOG_COPY" ]]; then
  printf 'Retaining existing derived copy: %s\n' "$VICTIM_LOG_COPY"
else
  icat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" "$VICTIM_LOG_INODE" >"$VICTIM_LOG_COPY"
  chmod a-w "$VICTIM_LOG_COPY"
fi
sha256sum "$VICTIM_LOG_COPY"

echo "-- victim.log: complete 22-byte content --"
cat -A "$VICTIM_LOG_COPY"

echo "-- /var/log: generic inventory --"
VARLOG_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /var/log "$DISK_IMAGE")"
fls -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" -l "$DISK_IMAGE" "$VARLOG_INODE"

echo "-- audit.log: presence check --"
AUDIT_DIR_CHECK="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /var/log/audit "$DISK_IMAGE")"
printf 'var_log_audit_lookup=%s\n' "$AUDIT_DIR_CHECK"

echo "-- persistent journal: presence only (content examined in timeline T-04) --"
JOURNAL_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /var/log/journal "$DISK_IMAGE")"
fls -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" -l "$DISK_IMAGE" "$JOURNAL_INODE"

echo "-- auth.log: bounded scenario window (2026-08-07 13:07:36-13:07:44 UTC) --"
AUTH_LOG_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /var/log/auth.log "$DISK_IMAGE")"
AUTH_LOG_COPY="$D01_DIR/auth.log"
if [[ -e "$AUTH_LOG_COPY" ]]; then
  printf 'Retaining existing derived copy: %s\n' "$AUTH_LOG_COPY"
else
  icat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" "$AUTH_LOG_INODE" >"$AUTH_LOG_COPY"
  chmod a-w "$AUTH_LOG_COPY"
fi
AUTH_WINDOW="$(grep -E 'Aug  7 13:07:3[6-9]|Aug  7 13:07:4[0-4]' "$AUTH_LOG_COPY")"
printf '%s\n' "$AUTH_WINDOW"

echo "-- syslog: bounded scenario window (2026-08-07 13:07:36-13:07:44 UTC) --"
SYSLOG_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /var/log/syslog "$DISK_IMAGE")"
SYSLOG_COPY="$D01_DIR/syslog"
if [[ -e "$SYSLOG_COPY" ]]; then
  printf 'Retaining existing derived copy: %s\n' "$SYSLOG_COPY"
else
  icat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" "$SYSLOG_INODE" >"$SYSLOG_COPY"
  chmod a-w "$SYSLOG_COPY"
fi
SYSLOG_WINDOW="$(grep -E 'Aug  7 13:07:3[6-9]|Aug  7 13:07:4[0-4]' "$SYSLOG_COPY")"
printf '%s\n' "$SYSLOG_WINDOW"

echo "-- kern.log: presence check and bounded scenario window --"
KERN_LOG_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /var/log/kern.log "$DISK_IMAGE")"
printf 'kern_log_inode=%s\n' "$KERN_LOG_INODE"
KERN_LOG_COPY="$D01_DIR/kern.log"
if [[ -e "$KERN_LOG_COPY" ]]; then
  printf 'Retaining existing derived copy: %s\n' "$KERN_LOG_COPY"
else
  icat -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" "$KERN_LOG_INODE" >"$KERN_LOG_COPY"
  chmod a-w "$KERN_LOG_COPY"
fi
KERN_WINDOW="$(grep -E 'Aug  7 13:07:3[6-9]|Aug  7 13:07:4[0-4]' "$KERN_LOG_COPY")"
printf '%s\n' "$KERN_WINDOW"

echo "-- bounded ptrace/injection keyword check across the shown window content only --"
PTRACE_HITS="$(printf '%s\n%s\n%s\n' "$AUTH_WINDOW" "$SYSLOG_WINDOW" "$KERN_WINDOW" | grep -ic 'ptrace\|inject' || true)"
printf 'ptrace_or_inject_matches_in_shown_window=%s\n' "$PTRACE_HITS"
```

**Output**

```text {"ignore":"true"}

[D-05] Shell history and Linux log examination (contextual, not a P-target)
-- labuser bash history: metadata --
inode: 258161
Allocated
Group: 16
Generation Id: 1276462040
uid / gid: 1000 / 1000
mode: rrw-------
Flags: Extents, 
size: 643
num of links: 1

Inode Times:
Accessed:	2026-08-07 13:07:43.655107148 (UTC)
File Modified:	2026-08-07 13:07:43.631107148 (UTC)
Inode Modified:	2026-08-07 13:07:43.631107148 (UTC)
File Created:	2026-08-07 13:07:43.631107148 (UTC)

Direct Blocks:
1015831 
Retaining existing derived copy: shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/disk/d-01/labuser_bash_history
6d696eab8e4bc9b7dfff667e84de8cd54cf61b6a3877d18f21ef8b736c75e4ab  shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/disk/d-01/labuser_bash_history
-- labuser bash history: complete content (643 bytes, untimestamped) --
PS1='__FORENSIC_LAB_8a349521b49fd620__$?__ '
mkdir -p /tmp/forensic-lab/ptrace_fa/src /tmp/forensic-lab/ptrace_fa/common
cd /tmp/forensic-lab/ptrace_fa
sed -i 's/0xc0, 0xa8, 0x64, 0x01, 0x66, 0x68, 0x11, 0x5c/0xc0, 0xa8, 0x64, 0x01, 0x66, 0x68, 0x11, 0x5c/' src/shellcode_inject_fa.c && grep -q '0xc0, 0xa8, 0x64, 0x01, 0x66, 0x68, 0x11, 0x5c' src/shellcode_inject_fa.c
gcc -Wall -Wextra -o shellcode_inject_fa src/shellcode_inject_fa.c common/ptrace_utils.c common/utils.c
gcc -o victim src/victim.c
id -un
nohup ./victim >/tmp/forensic-lab/ptrace_fa/victim.log 2>&1 & disown; echo $!
./shellcode_inject_fa 701
kill -0 701 && echo alive
exit
-- root account: bounded bash-history lookup --
r/r 1551:	.profile	2019-07-09 10:05:50 (UTC)	2026-03-20 11:01:37 (UTC)	2026-03-20 11:06:58 (UTC)	2026-03-20 11:06:58 (UTC)	161	0	0
r/r 1552:	.bashrc	2021-10-15 10:06:05 (UTC)	2026-03-20 11:01:37 (UTC)	2026-03-20 11:06:58 (UTC)	2026-03-20 11:06:58 (UTC)	3106	0	0
d/d 258055:	.ssh	2026-07-15 13:28:19 (UTC)	2026-07-15 13:28:19 (UTC)	2026-07-15 13:28:19 (UTC)	2026-07-15 13:28:19 (UTC)	4096	0	0
d/d 258075:	snap	2026-07-15 13:28:22 (UTC)	2026-07-15 13:28:22 (UTC)	2026-07-15 13:28:22 (UTC)	2026-07-15 13:28:22 (UTC)	4096	0	0
-- victim.log: metadata (inode 258160) --
inode: 258160
Allocated
Group: 16
Generation Id: 2373007218
uid / gid: 1000 / 1000
mode: rrw-rw-r--
Flags: Extents, 
size: 22
num of links: 1

Inode Times:
Accessed:	2026-08-07 13:07:43.463107148 (UTC)
File Modified:	2026-08-07 13:07:43.511107148 (UTC)
Inode Modified:	2026-08-07 13:07:43.511107148 (UTC)
File Created:	2026-08-07 13:07:43.463107148 (UTC)

Direct Blocks:
1015830 
Retaining existing derived copy: shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/disk/d-01/victim.log
0ea7cf1d885ad4976e0150df9dce6ffc37f00cf7db07e24b2b2e886ad0493c46  shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/disk/d-01/victim.log
-- victim.log: complete 22-byte content --
nohup: ignoring input$
-- /var/log: generic inventory --
d/d 73209:	journal	2026-07-15 13:28:09 (UTC)	2026-08-07 13:07:30 (UTC)	2026-07-15 13:28:09 (UTC)	2026-03-20 11:07:06 (UTC)	4096	101	0
r/r 73210:	wtmp	2026-08-07 13:08:03 (UTC)	2026-03-20 11:01:37 (UTC)	2026-08-07 13:08:03 (UTC)	2026-03-20 11:07:06 (UTC)	7296	43	0
r/r 73211:	btmp	2026-03-20 11:04:58 (UTC)	2026-03-20 11:01:37 (UTC)	2026-03-20 11:07:06 (UTC)	2026-03-20 11:07:06 (UTC)	0	43	0
r/r 73212:	lastlog	2026-08-07 13:07:37 (UTC)	2026-08-07 13:07:37 (UTC)	2026-08-07 13:07:37 (UTC)	2026-03-20 11:07:06 (UTC)	292292	43	0
r/r 73213:	dpkg.log	2026-07-15 13:28:51 (UTC)	2026-03-20 11:05:02 (UTC)	2026-07-15 13:28:51 (UTC)	2026-03-20 11:07:06 (UTC)	37468	0	0
d/d 73214:	apt	2026-07-15 13:28:45 (UTC)	2026-03-20 11:13:28 (UTC)	2026-07-15 13:28:45 (UTC)	2026-03-20 11:07:06 (UTC)	4096	0	0
d/d 73217:	dist-upgrade	2024-09-10 12:28:10 (UTC)	2026-03-20 11:08:18 (UTC)	2026-03-20 11:07:06 (UTC)	2026-03-20 11:07:06 (UTC)	4096	0	0
d/d 73218:	landscape	2026-07-15 13:28:23 (UTC)	2026-03-20 11:08:18 (UTC)	2026-07-15 13:28:23 (UTC)	2026-03-20 11:07:06 (UTC)	4096	116	111
d/d 73219:	unattended-upgrades	2026-07-15 13:28:20 (UTC)	2026-03-20 11:08:18 (UTC)	2026-07-15 13:28:20 (UTC)	2026-03-20 11:07:06 (UTC)	4096	4	0
r/r 73618:	alternatives.log	2026-07-15 13:28:50 (UTC)	2026-03-20 11:08:11 (UTC)	2026-07-15 13:28:50 (UTC)	2026-03-20 11:08:11 (UTC)	1444	0	0
d/d 61590:	private	2026-07-15 13:28:09 (UTC)	2026-07-15 13:28:09 (UTC)	2026-07-15 13:28:09 (UTC)	2026-07-15 13:28:09 (UTC)	4096	0	0
r/r 62401:	cloud-init.log	2026-08-07 13:07:24 (UTC)	2026-07-15 13:28:10 (UTC)	2026-08-07 13:07:24 (UTC)	2026-07-15 13:28:10 (UTC)	125718	4	104
r/r 62412:	cloud-init-output.log	2026-08-07 13:07:23 (UTC)	2026-07-15 13:28:10 (UTC)	2026-08-07 13:07:23 (UTC)	2026-07-15 13:28:10 (UTC)	9687	4	0
r/r 62466:	syslog	2026-08-07 13:07:58 (UTC)	2026-07-15 13:28:19 (UTC)	2026-08-07 13:07:58 (UTC)	2026-07-15 13:28:19 (UTC)	209879	4	104
r/r 62497:	kern.log	2026-08-07 13:07:43 (UTC)	2026-07-15 13:28:19 (UTC)	2026-08-07 13:07:43 (UTC)	2026-07-15 13:28:19 (UTC)	114487	4	104
r/r 62498:	auth.log	2026-08-07 13:08:02 (UTC)	2026-07-15 13:28:19 (UTC)	2026-08-07 13:08:02 (UTC)	2026-07-15 13:28:19 (UTC)	6679	4	104
r/r 3642:	dmesg	2026-08-07 13:07:30 (UTC)	2026-08-07 13:07:30 (UTC)	2026-08-07 13:07:30 (UTC)	2026-08-07 13:07:30 (UTC)	54085	4	0
r/r 62496:	dmesg.0	2026-07-15 13:28:24 (UTC)	2026-07-15 13:28:24 (UTC)	2026-08-07 13:07:30 (UTC)	2026-07-15 13:28:24 (UTC)	53449	4	0
-- audit.log: presence check --
var_log_audit_lookup=File not found
-- persistent journal: presence only (content examined in timeline T-04) --
d/d 1287:	d68636e922244a8b969a922a80c5da37	2026-07-15 13:28:23 (UTC)	2026-08-07 13:07:09 (UTC)	2026-07-15 13:28:23 (UTC)	2026-07-15 13:28:09 (UTC)	4096	101	0
-- auth.log: bounded scenario window (2026-08-07 13:07:36-13:07:44 UTC) --
Retaining existing derived copy: shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/disk/d-01/auth.log
Aug  7 13:07:36 lab-ubuntu-22 sshd[564]: Accepted publickey for labuser from 192.168.100.1 port 49880 ssh2: ED25519 SHA256:b+sPbwXWklIm2oxWubk7bIEnom4awIHQPkaKP93zfGs
Aug  7 13:07:36 lab-ubuntu-22 sshd[564]: pam_unix(sshd:session): session opened for user labuser(uid=1000) by (uid=0)
Aug  7 13:07:36 lab-ubuntu-22 systemd-logind[373]: New session 3 of user labuser.
Aug  7 13:07:37 lab-ubuntu-22 sshd[567]: Accepted publickey for labuser from 192.168.100.1 port 49886 ssh2: ED25519 SHA256:b+sPbwXWklIm2oxWubk7bIEnom4awIHQPkaKP93zfGs
Aug  7 13:07:37 lab-ubuntu-22 sshd[567]: pam_unix(sshd:session): session opened for user labuser(uid=1000) by (uid=0)
Aug  7 13:07:37 lab-ubuntu-22 systemd-logind[373]: New session 4 of user labuser.
Aug  7 13:07:43 lab-ubuntu-22 sshd[567]: pam_unix(sshd:session): session closed for user labuser
Aug  7 13:07:43 lab-ubuntu-22 systemd-logind[373]: Session 4 logged out. Waiting for processes to exit.
-- syslog: bounded scenario window (2026-08-07 13:07:36-13:07:44 UTC) --
Retaining existing derived copy: shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/disk/d-01/syslog
Aug  7 13:07:36 lab-ubuntu-22 systemd[1]: Started Session 3 of User labuser.
Aug  7 13:07:37 lab-ubuntu-22 systemd[1]: Started Session 4 of User labuser.
Aug  7 13:07:41 lab-ubuntu-22 systemd[1]: systemd-fsckd.service: Deactivated successfully.
Aug  7 13:07:43 lab-ubuntu-22 kernel: process 'victim' launched '/bin/sh' with NULL argv: empty string added
-- kern.log: presence check and bounded scenario window --
kern_log_inode=62497
Retaining existing derived copy: shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/disk/d-01/kern.log
Aug  7 13:07:43 lab-ubuntu-22 kernel: process 'victim' launched '/bin/sh' with NULL argv: empty string added
-- bounded ptrace/injection keyword check across the shown window content only --
ptrace_or_inject_matches_in_shown_window=0
```

__Observations, contextual.__ The bounded lookup finds an allocated, untimestamped
`bash_history` for `labuser` (inode `258161`, 643 bytes, uid/gid `1000`,
SHA-256 `6d696eab...b736c75e4ab`). Its complete content preserves the
scenario's terminal commands in order — staging directories, a no-op `sed`
edit, two `gcc` builds, `id -un`, the `nohup`-backgrounded victim launch,
the injector invocation against PID `701`, a liveness check, and `exit` —
but carries __no per-command timestamps__: it establishes command text and
order only, not per-command time, successful execution, or completeness. The
leading `PS1='__FORENSIC_LAB_...__'` line is the lab's own terminal-marker
configuration, not an operator-typed command. The bounded lookup for `root`
finds no `.bash_history` at all; `/root` contains only `.profile`, `.bashrc`,
`.ssh`, and `snap`, consistent with root actions in this scenario occurring
only through passwordless sudo from `labuser`'s session, not an interactive
root login shell.

`/tmp/forensic-lab/ptrace_fa/victim.log`, inode `258160`, is an allocated
22-byte file created at `13:07:43.463 UTC`, matching the bash history's
`nohup ./victim >victim.log 2>&1` redirection. Its complete content is
`nohup`'s own stderr notice that it is not reading from a terminal —
`nohup`'s boilerplate message, not output written by the `victim` binary
itself. It records that `nohup` executed and redirected; it says nothing
about `ptrace` or injection.

The generic `/var/log` inventory (18 entries) shows the standard Ubuntu set —
`syslog`, `auth.log`, `kern.log`, `dpkg.log`, `cloud-init*.log`,
`wtmp`/`btmp`/`lastlog`, `apt/`, `journal/`, and related bookkeeping — with
**no `audit.log` and no `/var/log/audit` directory at all**: `auditd` is not
installed or configured on this vanilla profile. The persistent journal is
present at `/var/log/journal/d68636e9...` (inode `73209`, one machine-id
subdirectory), confirming persistent (not solely volatile) journal storage;
its content is not extracted here — timeline T-04 already examines the
equivalent `systemd:journal` records through Plaso.

`auth.log`'s bounded scenario window (`13:07:36`–`13:07:44 UTC`, the
manifest's `scenario_started_at`/`scenario_ended_at`) contains only ordinary
`sshd`/`systemd-logind` session records for `labuser` sessions 3 and 4 — the
same record class T-04 already reports, with no `sudo` entry. `syslog`'s same
window adds two systemd session-start lines, one unrelated
`systemd-fsckd.service` deactivation, and one kernel-facility line at
`13:07:43`: `process 'victim' launched '/bin/sh' with NULL argv: empty string
added`. `kern.log` (present, inode `62497`) carries the identical line in the
same window and nothing else. This is a __recorded kernel message about an
exec call__, not proof that a shell was successfully spawned, that `ptrace`
attached, or that injection occurred; it is not counted toward P05 or any
other target here. __Bounded negative:__ none of the `auth.log`, `syslog`, or
`kern.log` content shown above — the only content examined, per the window
above — contains a `ptrace` or `inject` string (0 matches).

These are contextual filesystem findings. They do not create a new
P-target, change P01–P08 applicability, or change any metric in
[runme_case_summary.md](./runme_case_summary.md).

## D-06 - Disk investigation synthesis

| Target | Result | Locator | Limitation |
| --- | --- | --- | --- |
| P01 | Observed | `/tmp/forensic-lab/ptrace_fa`, inode `258110`; complete `src/`+`common/` tree (D-01) | None within this bound. |
| P02 | Observed | `/tmp/forensic-lab/ptrace_fa/victim`, inode `258159`, SHA-256 `951f93a6...060bebc` (D-02) | Identity and staging only; execution is a memory finding. |
| P03 | Observed | `/tmp/forensic-lab/ptrace_fa/shellcode_inject_fa`, inode `258148`, SHA-256 `9c6c8f4b...3572c8db` (D-03) | Identity and staging only. |
| P04 | Observed, static capability only | Imported `ptrace`/`waitpid` symbols; recovered `ptrace_utils.c` (inode `258150`) and `shellcode_inject_fa.c` (inode `258158`) (D-04) | Static source/binary evidence supports capability, not runtime execution. |

No deletion or cleanup occurs in this scenario; no carving, `ext4magic`, or
unallocated-space recovery was used. All four disk-applicable targets are
observed within one recursive listing and three targeted recoveries.
