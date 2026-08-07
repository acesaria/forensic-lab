---
cwd: ../../../..
shell: bash
---

# Father cleanup disk investigation — Runme notebook

__Run:__ `ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919`

**Scope:** post-mortem examination of the acquired disk and its ext4 root
filesystem.

Case-level per-artifact and aggregate metrics are recorded in
[runme_case_summary.md](./runme_case_summary.md); this notebook retains the
filesystem observations and limitations that support them.

> [!IMPORTANT]
> Run the cells in order from the repository root and in the same Runme terminal
> session. The acquired EWF image is read-only evidence; notebook output is
> written beneath the case-specific `shared/investigations/.../derived/`
> directory.

## Method

Preservation and acquisition have already been completed. This investigation
covers
the examination and analysis phases, following the general terminology of
NIST SP 800-86.

The acquired EWF image is not modified. Any derived files created during
recovery are stored separately and documented.

The case-specific order of examination is:

1. record the case parameters and filesystem geometry used during examination;
2. examine the allocated filesystem namespace and surviving persistence;
3. inspect known cleanup locations for deleted entries and metadata;
4. run one time-bounded recursive ext4 recovery completeness experiment,
   inventory all results, and only then check disclosed target paths;
5. consider bounded unallocated-space recovery only if a specific unresolved
   target remains;
6. summarize findings, negative observations, and limitations.

When a source-specific forensic tool directly answers a question, it is
preferred over a general text-processing command. For example, TSK `ifind` is
used to resolve a known filesystem path instead of searching the bodyfile with
`grep`.

## D-00 - Case setup

The executable companion script retrieves these values from the case metadata.
The notebook records only the resolved parameters needed to understand and
repeat the examination.

For another compatible run of the same scenario, change `RUN_ID`; the remaining
case variables are derived from its metadata and run without confirmation
prompts. The disclosed Father paths and targets remain scenario-specific.

```bash {"name":"D-00-Case-Setup-and-Metadata-Retrieval","promptEnv":"never"}
set -euo pipefail

printf '\n[D-00] Case setup, retrieve case identities from manifest \n'

RUN_ID='ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
export INV_DIR="$INV_DIR"
RAW_INDEX="$INV_DIR/raw_extraction_index.json"

DISK_IMAGE="$RUN_DIR/$(jq -er '.inputs.disk_image' "$RAW_INDEX")"
export DISK_IMAGE="$DISK_IMAGE"
BODYFILE="$RUN_DIR/$(jq -er '.extractors.tsk.output.path' "$RAW_INDEX")"

ROOT_START_SECTOR="$(
  jq -er '.extractors.tsk.filesystem.partition.start_sector' "$RAW_INDEX"
)"
export ROOT_START_SECTOR="$ROOT_START_SECTOR"
ROOT_SECTOR_COUNT="$(
  jq -er '.extractors.tsk.filesystem.partition.sector_count' "$RAW_INDEX"
)"
TSK_SECTOR_SIZE_BYTES="$(
  jq -er '.extractors.tsk.filesystem.partition.sector_size_bytes' "$RAW_INDEX"
)"
FS_BLOCK_SIZE_BYTES="$(
  jq -er '.extractors.tsk.filesystem.block_size_bytes' "$RAW_INDEX"
)"
export FS_BLOCK_SIZE_BYTES="$FS_BLOCK_SIZE_BYTES"
ROOT_OFFSET_BYTES=$((ROOT_START_SECTOR * TSK_SECTOR_SIZE_BYTES))
export ROOT_OFFSET_BYTES="$ROOT_OFFSET_BYTES"
ROOT_LENGTH_BYTES=$((ROOT_SECTOR_COUNT * TSK_SECTOR_SIZE_BYTES))
export ROOT_LENGTH_BYTES="$ROOT_LENGTH_BYTES"

printf \
  'run=%s\ndisk=%s\nbodyfile=%s\nroot_start=%s sectors\nroot_size=%s sectors\nsector_size=%s bytes\nfs_block_size=%s bytes\n' \
  "$RUN_ID" "$DISK_IMAGE" "$BODYFILE" \
  "$ROOT_START_SECTOR" "$ROOT_SECTOR_COUNT" \
  "$TSK_SECTOR_SIZE_BYTES" "$FS_BLOCK_SIZE_BYTES"

MANIFEST="$RUN_DIR/manifest.json"
ACQUISITION="$RUN_DIR/$(jq -er '.inputs.acquisition_manifest' "$RAW_INDEX")"

GUEST_TIMEZONE="$(jq -er '.platform.timezone' "$MANIFEST")"
export GUEST_TIMEZONE="$GUEST_TIMEZONE"
SCENARIO_START_UTC="$(jq -er '.timestamps.scenario_started_at' "$MANIFEST")"
SCENARIO_END_UTC="$(jq -er '.timestamps.scenario_ended_at' "$MANIFEST")"
SCENARIO_START_EPOCH="$(date -u -d "$SCENARIO_START_UTC" +%s)"
SCENARIO_END_EPOCH="$(date -u -d "$SCENARIO_END_UTC" +%s)"
EXT4MAGIC_START_EPOCH=$((SCENARIO_START_EPOCH - 60))
export EXT4MAGIC_START_EPOCH="$EXT4MAGIC_START_EPOCH"
EXT4MAGIC_END_EPOCH=$((SCENARIO_END_EPOCH + 60))
export EXT4MAGIC_END_EPOCH="$EXT4MAGIC_END_EPOCH"

printf \
  'manifest=%s\nacquisition=%s\nguest_timezone=%s\nstart_ts=%s\nend_ts=%s\n' \
  "$MANIFEST" "$ACQUISITION" "$GUEST_TIMEZONE" \
  "$SCENARIO_START_UTC" "$SCENARIO_END_UTC"
```

**Output**

```text {"ignore":"true"}
[D-00] Case setup, retrieve case identities from manifest
run=ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919
disk=shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/dumps/disk/evidence_disk.E01
bodyfile=shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/analysis/bodyfile
root_start=227328 sectors
root_size=8161247 sectors
sector_size=512 bytes
fs_block_size=4096 bytes
manifest=shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/manifest.json
acquisition=shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/dumps/acquisition.json
guest_timezone=Etc/UTC
start_ts=2026-08-05T12:49:19.071Z
end_ts=2026-08-05T12:49:20.859Z
```

Prepare the recovery workspace and export only the values used by later Runme
cells.

```bash {"name":"D-00-Recovery-Workspace","promptEnv":"never"}
set -euo pipefail

RECOVERY_ID="recovery-$(date -u +%Y%m%dT%H%M%SZ)"
export RECOVERY_ID="$RECOVERY_ID"
OUT_DIR="$INV_DIR/derived/disk/$RECOVERY_ID"
export OUT_DIR="$OUT_DIR"
ENTRY_DIR="$OUT_DIR/deleted-entries"
export ENTRY_DIR="$ENTRY_DIR"
EXT4_DIR="$OUT_DIR/ext4magic"
export EXT4_DIR="$EXT4_DIR"
UNALLOC_DIR="$OUT_DIR/unallocated"
export UNALLOC_DIR="$UNALLOC_DIR"
PHOTOREC_DIR="$OUT_DIR/photorec"
export PHOTOREC_DIR="$PHOTOREC_DIR"
ROOT_IMAGE="$OUT_DIR/root-partition.ext4"
export ROOT_IMAGE="$ROOT_IMAGE"

if [[ -e "$OUT_DIR" ]]; then
  printf 'error: recovery output already exists: %s\n' "$OUT_DIR" >&2
  exit 1
fi

mkdir -p \
  "$ENTRY_DIR" "$EXT4_DIR" "$UNALLOC_DIR"
printf 'recovery_output=%s\n' "$OUT_DIR"
```

**Output**

```text {"ignore":"true"}
recovery_output=shared/investigations/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/derived/disk/recovery-20260805T134432Z
```

| Parameter | Resolved value |
| --- | --- |
| Run ID | `ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919` |
| Disk image | `shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/dumps/disk/evidence_disk.E01` |
| TSK bodyfile | `shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/analysis/bodyfile` |
| Root partition start | `227328` sectors |
| Root partition length | `8161247` sectors |
| TSK sector size | `512` bytes |
| ext4 block size | `4096` bytes |
| Guest timezone | `Etc/UTC` |
| Scenario start | `2026-08-05T12:49:19.071Z` |
| Scenario end | `2026-08-05T12:49:20.859Z` |
| Disk acquisition | Offline, after the guest was powered off |
| Verified logical-media SHA-256 | `98c9bb7c7cc048ab78faea21375bd3133d6df9707165f0eec02afd105edad70b` (`ewfverify` exit 0) |
| Raw TSK export | Sleuth Kit `4.15.0`; 72,649 bodyfile rows |
| Bodyfile SHA-256 | `ab34214d5f01d15528924e5c51ae794aa4ef8651081b81bde390e5a690081853` |
| Recovery output | `shared/investigations/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/derived/disk/recovery-20260805T134432Z` |

The partition offset passed to TSK commands is therefore `227328` sectors.
Times are interpreted in the guest timezone (`Etc/UTC`).

## D-01 - Examine suspected system-wide LD_PRELOAD persistence

Given the suspected technique, the examination begins with
`/etc/ld.so.preload`, the standard system-wide preload configuration file.
TSK `ifind` is used to resolve the known path to an inode; `istat` then reports
the inode's allocation state and metadata.

### D-01.1 - Resolve the path and inspect its inode

```bash {"name":"D-01-1-Resolve-Path-and-Inspect-Inode","promptEnv":"never"}
set -euo pipefail

printf '\n[D-01.1] Resolve the path and inspect its inode \n'

# D-01.1: resolve the known pathname with the filesystem-aware TSK tool and inspect its inode
PRELOAD_INODE="$(
  ifind -i ewf -o "$ROOT_START_SECTOR" \
    -n /etc/ld.so.preload "$DISK_IMAGE"
)"
export PRELOAD_INODE="$PRELOAD_INODE"

# Print the captured result before using it in the next examination step.
printf 'preload_inode=%s\n' "$PRELOAD_INODE"

# D-01.1: examine the metadata address returned by ifind.
istat -i ewf -o "$ROOT_START_SECTOR" \
  -z "$GUEST_TIMEZONE" \
  "$DISK_IMAGE" "$PRELOAD_INODE"
```

**Output**

```text {"ignore":"true"}
[D-01.1] Resolve the path and inspect its inode
preload_inode=61596
inode: 61596
Allocated
uid / gid: 0 / 0
mode: rrw-r--r--
size: 17
num of links: 1

Inode Times:
Accessed:       2026-08-05 12:49:22.749540242 (UTC)
File Modified:  2026-08-05 12:49:22.745540242 (UTC)
Inode Modified: 2026-08-05 12:49:22.745540242 (UTC)
File Created:   2026-08-05 12:49:22.745540242 (UTC)
```

The pathname resolves to inode `61596`. The file is allocated, owned by
`root:root`, and has a size of 17 bytes. At this stage, this confirms that the
preload configuration file survives in the acquired filesystem. Its content
has not yet been examined. Its filesystem timestamps are about 1.9 seconds
after the host-recorded scenario end and before RAM acquisition began. Because
these timestamps come from different clocks and recording layers, they support
only coarse temporal association; they do not establish an exact post-scenario
write sequence.

### D-01.2 - Examine the configuration content

The file is only 17 bytes, so its content can be examined directly with TSK
`icat`.

```bash {"name":"D-01-2-Examine-Configuration-Content","promptEnv":"never"}
set -euo pipefail

# D-01.2: read the preload configuration.
printf '\n[D-01.2] Preload configuration content\n'

PRELOAD_PATH="$(
  icat -i ewf -o "$ROOT_START_SECTOR" \
    "$DISK_IMAGE" "$PRELOAD_INODE"
)"

printf 'preload_path=%s\n' "$PRELOAD_PATH"
```

**Output**

```text {"ignore":"true"}
[D-01.2] Preload configuration content
preload_path=/lib/selinux.so.3
```

The configuration references `/lib/selinux.so.3`. This is only a pathname:
the referenced file must now be resolved and examined before its purpose can
be assessed.

### D-01.3 - Resolve and inspect the referenced file

The examination resolves `/lib` first, then resolves the complete library path
explicitly as EWF evidence:

```bash {"name":"D-01-3-Resolve-and-Inspect-Referenced-File","promptEnv":"never"}
set -euo pipefail

# D-01.3: examine /lib before resolving the referenced library.
printf '\n[D-01.3] Referenced library path\n'

LIB_LINK_INODE="$(
  ifind -i ewf -o "$ROOT_START_SECTOR" \
    -n /lib "$DISK_IMAGE"
)"

printf 'lib_link_inode=%s\n' "$LIB_LINK_INODE"

istat -i ewf -o "$ROOT_START_SECTOR" \
  -z "$GUEST_TIMEZONE" \
  "$DISK_IMAGE" "$LIB_LINK_INODE"

# /lib points to usr/lib in the acquired filesystem.
PRELOAD_LIBRARY='/usr/lib/selinux.so.3'

LIBRARY_INODE="$(
  ifind -i ewf -o "$ROOT_START_SECTOR" \
    -n "$PRELOAD_LIBRARY" "$DISK_IMAGE"
)"
export LIBRARY_INODE="$LIBRARY_INODE"

printf 'resolved_path=%s\nlibrary_inode=%s\n' \
  "$PRELOAD_LIBRARY" "$LIBRARY_INODE"

istat -i ewf -o "$ROOT_START_SECTOR" \
  -z "$GUEST_TIMEZONE" \
  "$DISK_IMAGE" "$LIBRARY_INODE"
```

**Output**

```text {"ignore":"true"}
[D-01.3] Referenced library path
lib_link_inode=1542
inode: 1542
Allocated
size: 7
symbolic link to: usr/lib

resolved_path=/usr/lib/selinux.so.3
library_inode=62345
inode: 62345
Allocated
uid / gid: 0 / 0
mode: rrw-r--r--
size: 32784
num of links: 1

Inode Times:
Accessed:       2026-08-05 12:49:20.557540242 (UTC)
File Modified:  2026-08-05 12:49:20.473540242 (UTC)
Inode Modified: 2026-08-05 12:49:20.473540242 (UTC)
File Created:   2026-08-05 12:49:20.473540242 (UTC)
```

The `/lib` link points to `/usr/lib`; consequently, the referenced object
resolves to `/usr/lib/selinux.so.3`, inode `62345`. It is an allocated,
root-owned file created and modified during the scenario window. Its plausible
name is not sufficient to determine whether it is legitimate or malicious.

### D-01.4 - Recover and identify the referenced object

An existing derived copy is retained without overwriting it. Otherwise, the
allocated file is recovered to the investigation directory and made read-only.
Its hash is recorded and `file` is used for basic format identification.

```bash {"name":"D-01-4-Recover-and-Identify-Referenced-Object","promptEnv":"never"}
set -euo pipefail

# D-01.4: recover and identify the allocated shared object.
printf '\n[D-01.4] Recovered library identification\n'

D01_DIR="$INV_DIR/derived/d-01"
export D01_DIR="$D01_DIR"
LIBRARY_COPY="$D01_DIR/usr-lib-selinux.so.3"
export LIBRARY_COPY="$LIBRARY_COPY"

mkdir -p "$D01_DIR"

if [[ -e "$LIBRARY_COPY" ]]; then
  printf 'Retaining existing derived library: %s\n' "$LIBRARY_COPY"
else
  icat -i ewf -o "$ROOT_START_SECTOR" \
    "$DISK_IMAGE" "$LIBRARY_INODE" \
    >"$LIBRARY_COPY"
  chmod a-w "$LIBRARY_COPY"
fi

sha256sum "$LIBRARY_COPY"
file -b "$LIBRARY_COPY"
```

**Output**

```text {"ignore":"true"}
[D-01.4] Recovered library identification
87fece49fc15a48372a1ba76cf424755f9cfab6cce7e8073002757f7db2f0711  shared/investigations/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/derived/d-01/usr-lib-selinux.so.3
ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=96daef8bb7ab389abcb5aa9458436759949849c7, not stripped
```

The recovered file is an ELF shared object, which is consistent with its use
through `ld.so.preload`. This still does not prove that it is a rootkit:
attribution depends on the disclosed controlled-scenario context.

### D-01.5 - Characterise the recovered ELF statically

The file is examined without executing it. This follows a simple static-analysis
sequence: inspect the ELF header and dependencies, list all defined dynamic
symbols, then extract readable strings. Complete outputs are saved before
`grep` is used to keep the notebook display short.

```bash {"name":"D-01-5-Static-ELF-Characterisation","promptEnv":"never"}
set -euo pipefail

STATIC_OUTPUT="$D01_DIR/static-elf-standard.txt"

if [[ ! -e "$STATIC_OUTPUT" ]]; then
  printf '[ELF header]\n' >"$STATIC_OUTPUT"
  readelf -h "$LIBRARY_COPY" >>"$STATIC_OUTPUT"
  printf '\n[Dynamic section]\n' >>"$STATIC_OUTPUT"
  readelf -d "$LIBRARY_COPY" >>"$STATIC_OUTPUT"
  printf '\n[Defined dynamic symbols]\n' >>"$STATIC_OUTPUT"
  nm -D --defined-only "$LIBRARY_COPY" >>"$STATIC_OUTPUT"
  printf '\n[Strings of at least 8 characters]\n' >>"$STATIC_OUTPUT"
  strings -a -n 8 "$LIBRARY_COPY" >>"$STATIC_OUTPUT"
  chmod a-w "$STATIC_OUTPUT"
fi

grep -E 'Class:|Type:|Machine:|NEEDED' "$STATIC_OUTPUT"
grep ' T ' "$STATIC_OUTPUT"
grep -E 'preload|/proc/net/tcp|/bin/bash|AUTHENTICATE|Enjoy the shell' \
  "$STATIC_OUTPUT"
sha256sum "$STATIC_OUTPUT" | sed "s|$INV_DIR|shared/investigations/...|"
```

**Output**

```text {"ignore":"true"}
  Class:                             ELF64
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
0000000000003811 T __lxstat
00000000000038e5 T __lxstat64
00000000000026b9 T accept
0000000000002988 T access
0000000000002d49 T backconnect
0000000000002ac0 T execve
0000000000003d9d T exfil
0000000000002e4d T falsify_tcp
0000000000003497 T fopen
00000000000035e4 T fopen64
0000000000003a84 T fstat
0000000000002f44 T gcry_pk_verify
0000000000002cc2 T lpe_drop_shell
00000000000039b9 T lstat
0000000000003e0f T newconv
0000000000002fd4 T open
0000000000003120 T open64
000000000000326c T openat
000000000000339b T opendir
0000000000003ec8 T pam_authenticate
0000000000003731 T readdir
0000000000002fc2 T strfry
0000000000002cad T timebomb
0000000000003b2f T unlink
0000000000003c51 T unlinkat
AUTHENTICATE:
ld.so.preload
/etc/ld.so.preload
Enjoy the shell!
/bin/bash
ld.so.preload
/proc/net/tcp
ld.so.preload
ld.so.preload
ld.so.preload
d1c6a60d53ccd242248a3e40ca6f73fa53096184ed0892c3223886ea84a9b7de  shared/investigations/.../derived/d-01/static-elf-standard.txt
```

The combination of file-access hooks, directory-listing hooks, network-related
functions and shell-related strings is consistent with an `LD_PRELOAD`
interposition/backdoor library. This is stronger than identification by filename
alone, but static examination cannot show which functions actually executed.

### D-01.6 - Examine `/tmp` for surviving staging artifacts

`/tmp` is a common staging location on Linux. A recursive TSK listing provides a
small, standard examination of that directory without first selecting the
planted filename. A suspicious file found in the listing is then inspected with
`istat`.

```bash {"name":"D-01-6-Recursive-Tmp-Examination","promptEnv":"never"}
set -euo pipefail

TMP_OUTPUT="$D01_DIR/tmp-filesystem-examination.txt"
TMP_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /tmp "$DISK_IMAGE")"

if [[ ! -e "$TMP_OUTPUT" ]]; then
  printf '[Recursive /tmp listing]\n' >"$TMP_OUTPUT"
  fls -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" -l \
    -r "$DISK_IMAGE" "$TMP_INODE" >>"$TMP_OUTPUT"

  # Follow up the suspicious file exposed by the listing.
  CANDIDATE_PATH='/tmp/forensic-lab/father_ldpreload/probe/__malicious_file'
  CANDIDATE_INODE="$(
    ifind -i ewf -o "$ROOT_START_SECTOR" -n "$CANDIDATE_PATH" "$DISK_IMAGE"
  )"
  printf '\n[Candidate metadata: %s]\n' "$CANDIDATE_PATH" >>"$TMP_OUTPUT"
  istat -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" \
    "$DISK_IMAGE" "$CANDIDATE_INODE" >>"$TMP_OUTPUT"
  chmod a-w "$TMP_OUTPUT"
fi

printf '[Recursive /tmp listing]\n'
grep -E 'forensic-lab|father_ldpreload|probe|__malicious_file' \
  "$TMP_OUTPUT" | head -n 4
sed -n '/\[Candidate metadata:/,$p' "$TMP_OUTPUT"
sha256sum "$TMP_OUTPUT" | sed "s|$INV_DIR|shared/investigations/...|"
```

**Output**

```text {"ignore":"true"}
[Recursive /tmp listing]
d/d 258154:	forensic-lab	2026-08-05 12:49:19 (UTC)	2026-08-05 12:49:19 (UTC)	2026-08-05 12:49:19 (UTC)	2026-08-05 12:49:19 (UTC)	4096	1000	1000
+ d/d 258155:	father_ldpreload	2026-08-05 12:49:20 (UTC)	2026-08-05 12:49:19 (UTC)	2026-08-05 12:49:20 (UTC)	2026-08-05 12:49:19 (UTC)	4096	1000	1000
++ d/d 258156:	probe	2026-08-05 12:49:20 (UTC)	2026-08-05 12:49:20 (UTC)	2026-08-05 12:49:20 (UTC)	2026-08-05 12:49:19 (UTC)	4096	1000	1000
+++ r/r 260193:	__malicious_file	2026-08-05 12:49:20 (UTC)	2026-08-05 12:49:20 (UTC)	2026-08-05 12:49:20 (UTC)	2026-08-05 12:49:20 (UTC)	0	1000	1000
[Candidate metadata: /tmp/forensic-lab/father_ldpreload/probe/__malicious_file]
inode: 260193
Allocated
Group: 16
Generation Id: 86871881
uid / gid: 1000 / 1000
mode: rrw-rw-r--
Flags: Extents,
size: 0
num of links: 1

Inode Times:
Accessed:	2026-08-05 12:49:20.497540242 (UTC)
File Modified:	2026-08-05 12:49:20.497540242 (UTC)
Inode Modified:	2026-08-05 12:49:20.497540242 (UTC)
File Created: 2026-08-05 12:49:20.497540242 (UTC)

Direct Blocks:
4bf4cf6b2b5f773deb2f9e629e76930e8c4dd9480d7efb85692b70171db9deb0  shared/investigations/.../derived/d-01/tmp-filesystem-examination.txt
```

The ordinary `/tmp` review exposes the surviving `forensic-lab` hierarchy and
the allocated zero-byte `__malicious_file`. TSK provides inode `260193` as a
durable locator. Offline visibility does not by itself prove that a live process
hid the file; the live hiding check remains separate scenario validation.

## Recovery scope

This phase combines disclosed-ground-truth-guided checks with one recursive
ext4 recovery pass. The parent directories, time window, configuration marker
and TAR file type come from scenario facts. `ext4magic` does not use a target
list: all entries it returns within the disclosed time window are inventoried
before the target paths are checked. These are bounded validation experiments,
not open-ended forensic discovery.

| Recovery method terminology | Use in this investigation |
| --- | --- |
| deleted directory-entry examination | Disclosed-target-guided TSK `fls -d` examination of the three relevant parent directories |
| journal-assisted recovery attempt | Time-bounded recursive `ext4magic -R` experiment, followed by a full returned-entry inventory and disclosed-target validation |
| ground-truth-guided targeted content recovery from unallocated filesystem blocks | Marker-led `blkls`, `blkcalc`, and `blkcat` recovery of the disclosed `config.h` content |
| signature-based file carving from unallocated space | Disclosed-target-guided TAR-only PhotoRec attempt over ext4 free space |

| Recovery target | Disclosed pre-cleanup location |
| --- | --- |
| Uploaded archive | `/tmp/father-upstream-4eb2712.tar` |
| Extracted Father tree | `/tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/` |
| Modified configuration | `.../src/config.h` |
| Built shared object | `.../rk.so` |
| Bash-history cleanup target | `/home/labuser/.bash_history` |

## D-02 - Are deleted target entries still present?

TSK resolves each parent with `ifind` and asks its ext4 namespace for deleted
entries with `fls -d`.

```bash {"name":"D-02-Deleted-Directory-Entry-Checks","promptEnv":"never"}
set -euo pipefail

printf '[D-02] Deleted entries in the three relevant parent directories\n'

TMP_INODE="$(ifind -i ewf -o "$ROOT_START_SECTOR" -n /tmp "$DISK_IMAGE")"
FATHER_PARENT_INODE="$(
  ifind -i ewf -o "$ROOT_START_SECTOR" \
    -n /tmp/forensic-lab/father_ldpreload "$DISK_IMAGE"
)"
LABUSER_INODE="$(
  ifind -i ewf -o "$ROOT_START_SECTOR" -n /home/labuser "$DISK_IMAGE"
)"

printf 'parent inodes: /tmp=%s father_parent=%s /home/labuser=%s\n' \
  "$TMP_INODE" "$FATHER_PARENT_INODE" "$LABUSER_INODE"

fls -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" -d -l \
  "$DISK_IMAGE" "$TMP_INODE" \
  | tee "$ENTRY_DIR/tmp-deleted.txt"

fls -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" -d -l \
  "$DISK_IMAGE" "$FATHER_PARENT_INODE" \
  | tee "$ENTRY_DIR/father-parent-deleted.txt"

fls -i ewf -o "$ROOT_START_SECTOR" -z "$GUEST_TIMEZONE" -d -l \
  "$DISK_IMAGE" "$LABUSER_INODE" \
  | tee "$ENTRY_DIR/labuser-deleted.txt"

stat -c '%n %s bytes' \
  "$ENTRY_DIR/tmp-deleted.txt" \
  "$ENTRY_DIR/father-parent-deleted.txt" \
  "$ENTRY_DIR/labuser-deleted.txt"

if [[ ! -s "$ENTRY_DIR/tmp-deleted.txt" &&
      ! -s "$ENTRY_DIR/father-parent-deleted.txt" &&
      ! -s "$ENTRY_DIR/labuser-deleted.txt" ]]; then
  printf 'No deleted entries were returned; no target inode was available for istat/icat.\n'
fi
```

**Output**

```text {"ignore":"true"}
[D-02] Deleted entries in the three relevant parent directories
parent inodes: /tmp=1581 father_parent=258155 /home/labuser=258049
shared/investigations/.../derived/disk/recovery-20260805T134432Z/deleted-entries/tmp-deleted.txt 0 bytes
shared/investigations/.../derived/disk/recovery-20260805T134432Z/deleted-entries/father-parent-deleted.txt 0 bytes
shared/investigations/.../derived/disk/recovery-20260805T134432Z/deleted-entries/labuser-deleted.txt 0 bytes
No deleted entries were returned; no target inode was available for istat/icat.
```

In ext4, a directory entry associates a filename with an inode. Deletion removes
that association and makes the inode and data blocks available for reuse.
Residual directory-entry or inode information may sometimes remain recoverable,
but this is not guaranteed. In this case, `fls -d` found no interpretable
deleted entry in the three examined parent directories. The deleted target
entries were not recovered by this method, so there was no inode locator
available for `istat` or `icat`. This bounded negative does not establish
absence.

## D-03 - Can bounded recursive ext4magic recover any entry?

`ext4magic` required an offset-free ext4 derivative. The bounded recovery
experiment started at the filesystem root and used the scenario interval plus
60 seconds on each side with the permissive recursive `-R` mode. This can
consider both deleted and allocated matching inodes, so all recovered entries
are inventoried before the disclosed target paths are checked.

```bash {"name":"D-03-Bounded-Recursive-Journal-Recovery","promptEnv":"never"}
set -euo pipefail

printf '\n[D-03] Bounded recursive journal-assisted recovery\n'

if [[ -e "$ROOT_IMAGE" ]]; then
  sha256sum --check "$ROOT_IMAGE.sha256"
else
  ewfexport -q -u -f raw -o "$ROOT_OFFSET_BYTES" -B "$ROOT_LENGTH_BYTES" -t - \
    "$DISK_IMAGE" >"$ROOT_IMAGE"
  chmod a-w "$ROOT_IMAGE"
  sha256sum "$ROOT_IMAGE" | tee "$ROOT_IMAGE.sha256"
fi

chmod a-w "$ROOT_IMAGE" "$ROOT_IMAGE.sha256"
stat -c 'root derivative: %n %s bytes' "$ROOT_IMAGE"

RECOVER_DIR="$EXT4_DIR/recovered-R"
INVENTORY="$EXT4_DIR/recovered-R-inventory.txt"
TARGET_RESULTS="$EXT4_DIR/disclosed-target-results.txt"

mkdir -p "$RECOVER_DIR"

ext4magic "$ROOT_IMAGE" \
  -a "$EXT4MAGIC_START_EPOCH" -b "$EXT4MAGIC_END_EPOCH" \
  -R -d "$RECOVER_DIR" \
  2>&1 | tee "$EXT4_DIR/ext4magic-R.txt"

find "$RECOVER_DIR" -mindepth 1 \
  -printf '%y %s bytes %p\n' | sort | tee "$INVENTORY"

RECOVERED_ENTRIES="$(wc -l <"$INVENTORY")"
printf 'ext4magic completed successfully; recovered_entries=%s\n' \
  "$RECOVERED_ENTRIES"

for target in \
  'tmp/father-upstream-4eb2712.tar' \
  'tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/src/config.h' \
  'tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/rk.so' \
  'home/labuser/.bash_history'; do
  printf 'target=%s matches=%s\n' "$target" \
    "$(find "$RECOVER_DIR" -type f -path "*/$target" -printf . | wc -c)"
  find "$RECOVER_DIR" -type f -path "*/$target" \
    -printf '%s bytes %p\n' -exec sha256sum {} \;
done | tee "$TARGET_RESULTS"
```

**Output**

```text {"ignore":"true"}
[D-03] Bounded recursive journal-assisted recovery

e15c49befbb3b618416ae029f11abb3d8a08767587c1923743b68118bfa2427b  shared/investigations/.../derived/disk/recovery-20260805T134432Z/root-partition.ext4
root derivative: shared/investigations/.../derived/disk/recovery-20260805T134432Z/root-partition.ext4 4178558464 bytes
ext4magic : EXIT_SUCCESS
ext4magic completed successfully; recovered_entries=0
target=tmp/father-upstream-4eb2712.tar matches=0
target=tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/src/config.h matches=0
target=tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/rk.so matches=0
target=home/labuser/.bash_history matches=0
```

The recursive inventory was empty. `ext4magic` completed successfully, so this
is a successful zero-result recovery experiment rather than a tool failure.
The four zero-match checks occurred only after the complete inventory and are
ground-truth-guided validation.

The recursive scope remains bounded by the scenario interval plus 60 seconds on
each side, `ext4magic`'s journal semantics, and the journal data available in
this image. It recovered no entry and does not establish that historical data
never existed. The raw TSK `fsstat` record reports that ext4 was unmounted
properly, but the journal itself was not examined in this notebook. The zero
result therefore must not be attributed to a particular journal state.

## D-04 - Ground-truth-guided recovery of config.h content from unallocated blocks

This is ground-truth-guided, scenario-specific content recovery: the disclosed
Father marker selects the candidate. It is not technique-led discovery or a
general carving method.

This is not slack-space recovery: `blkls` was used without `-s`, so the stream
contains unallocated filesystem blocks rather than file slack.

### D-04.1 - Create and search the unallocated-block stream

```bash {"name":"D-04-1-Create-and-Search-Unallocated-Block-Stream","promptEnv":"never"}
set -euo pipefail

printf '\n[D-04] Recover the selected config.h from unallocated blocks\n'

printf '\n[D-04.1] Create and search the blkls unallocated-block stream\n'

UNALLOCATED="$UNALLOC_DIR/unallocated.blkls"
CONFIG_MARKER='#define STRING "__malicious_"'
export CONFIG_MARKER="$CONFIG_MARKER"

blkls -i ewf -o "$ROOT_START_SECTOR" "$DISK_IMAGE" \
  >"$UNALLOCATED" 2>"$UNALLOC_DIR/blkls.stderr"
sha256sum "$UNALLOCATED" >"$UNALLOCATED.sha256"
stat -c 'unallocated blocks: %n %s bytes' "$UNALLOCATED"

grep -aobF -- "$CONFIG_MARKER" "$UNALLOCATED" \
  >"$UNALLOC_DIR/config-pattern-hits.txt" || true
HIT_COUNT="$(wc -l <"$UNALLOC_DIR/config-pattern-hits.txt")"
printf 'marker_hits=%s\n' "$HIT_COUNT"

if [[ "$HIT_COUNT" -ne 1 ]]; then
  printf 'error: expected exactly one config marker hit, found %s\n' \
    "$HIT_COUNT" >&2
  exit 1
fi

HIT_OFFSET="$(
  cut -d: -f1 "$UNALLOC_DIR/config-pattern-hits.txt"
)"
export HIT_OFFSET="$HIT_OFFSET"
printf 'marker_offset_in_blkls=%s\n' "$HIT_OFFSET"
```

**Output**

```text {"ignore":"true"}
[D-04] Recover the selected config.h from unallocated blocks
[D-04.1] Create and search the blkls unallocated-block stream
unallocated blocks: shared/investigations/.../derived/disk/recovery-20260805T134432Z/unallocated/unallocated.blkls 1899761664 bytes
marker_hits=1
marker_offset_in_blkls=541503856
```

Exactly one marker hit was present, satisfying the script's precondition for
mapping the packed `blkls` block.

### D-04.2 - Map the packed blkls block to the original ext4 block

```bash {"name":"D-04-2-Map-Packed-Block-to-Ext4-Block","promptEnv":"never"}
set -euo pipefail

printf '\n[D-04.2] Map the packed blkls block to the original ext4 block\n'

PACKED_BLOCK=$((HIT_OFFSET / FS_BLOCK_SIZE_BYTES))
FILESYSTEM_BLOCK="$(
  blkcalc -i ewf -o "$ROOT_START_SECTOR" -u "$PACKED_BLOCK" "$DISK_IMAGE"
)"
export FILESYSTEM_BLOCK="$FILESYSTEM_BLOCK"
printf \
  'blkls_byte_offset=%s\nblkls_block=%s\nfilesystem_block=%s\n' \
  "$HIT_OFFSET" "$PACKED_BLOCK" "$FILESYSTEM_BLOCK" \
  | tee "$UNALLOC_DIR/config-block-map.txt"

blkstat "$ROOT_IMAGE" "$FILESYSTEM_BLOCK"
ifind -d "$FILESYSTEM_BLOCK" "$ROOT_IMAGE"
```

**Output**

```text {"ignore":"true"}
[D-04.2] Map the packed blkls block to the original ext4 block
blkls_byte_offset=541503856
blkls_block=132203
filesystem_block=589864
Fragment: 589864
Not Allocated
Group: 18
Inode not found
```

The `blkls` byte offset and packed-block number are locators for this run's
hashed unallocated stream; `filesystem_block=589864` is the corresponding ext4
block.
`blkstat` reports that block as not allocated in group `18`. `ifind -d` returned
`Inode not found`, a successful zero-result TSK examination rather than a tool
failure; no inode association was recovered for this block.

### D-04.3 - Extract and validate the boundary-delimited candidate

```bash {"name":"D-04-3-Extract-and-Validate-Boundary-Delimited-Candidate","promptEnv":"never"}
set -euo pipefail

printf '\n[D-04.3] Extract and validate the boundary-delimited candidate\n'

RECOVERED_CONFIG="$UNALLOC_DIR/recovered-config.h"
CONFIG_START_LINE='#ifndef CONFIG'
CONFIG_END_LINE='#endif'
BLOCK_FILE="$UNALLOC_DIR/config-source-block-$FILESYSTEM_BLOCK.bin"
blkcat -i ewf -o "$ROOT_START_SECTOR" \
  "$DISK_IMAGE" "$FILESYSTEM_BLOCK" >"$BLOCK_FILE"

sed -n "/^$CONFIG_START_LINE$/,/^$CONFIG_END_LINE$/p" \
  "$BLOCK_FILE" >"$RECOVERED_CONFIG"

head -n 1 "$RECOVERED_CONFIG" | grep -Fxq -- "$CONFIG_START_LINE"
grep -Fxq -- "$CONFIG_MARKER" "$RECOVERED_CONFIG"
tail -n 1 "$RECOVERED_CONFIG" | grep -Fxq -- "$CONFIG_END_LINE"
printf 'boundary_checks=passed\n'
head -n 1 "$RECOVERED_CONFIG"
printf '...\n'
grep -Fx -- "$CONFIG_MARKER" "$RECOVERED_CONFIG"
printf '...\n'
tail -n 1 "$RECOVERED_CONFIG"
stat -c '%n %s bytes' "$RECOVERED_CONFIG"
sha256sum "$RECOVERED_CONFIG"
file "$RECOVERED_CONFIG"
sha256sum "$RECOVERED_CONFIG" "$BLOCK_FILE" \
  >"$UNALLOC_DIR/recovered-config.sha256"
```

**Output**

```text {"ignore":"true"}
[D-04.3] Extract and validate the boundary-delimited candidate
boundary_checks=passed
#ifndef CONFIG
...
#define STRING "__malicious_"
...
#endif
shared/investigations/.../derived/disk/recovery-20260805T134432Z/unallocated/recovered-config.h 740 bytes
d14ebf96f7a5d2c10622f415fe1a1ecddeda2756387ba5ae8f52886d64120ad4  shared/investigations/.../derived/disk/recovery-20260805T134432Z/unallocated/recovered-config.h
shared/investigations/.../derived/disk/recovery-20260805T134432Z/unallocated/recovered-config.h: C source, ASCII text
```

Result: complete 740-byte candidate recovery using ground-truth-guided,
scenario-specific content selection. The start and end lines delimit a coherent
C-header candidate; they are not a general carving method. Pathname, inode,
timestamps and directory association were not recovered.

## D-05 - Can the uploaded TAR be recovered by file carving?

One PhotoRec run selected ext4 free space and enabled only TAR carving.
The output directory is created here, so a repeated cell stops before it can
append a log or create another `carved.*` directory.

```bash {"name":"D-05-TAR-Only-PhotoRec-Carving","promptEnv":"never"}
set -euo pipefail

printf '\n[D-05] TAR-only PhotoRec attempt\n'

mkdir "$PHOTOREC_DIR"

photorec \
  /log /logname "$PHOTOREC_DIR/photorec.log" \
  /d "$PHOTOREC_DIR/carved" \
  /cmd "$ROOT_IMAGE" \
  partition_none,options,mode_ext2,fileopt,everything,disable,tar,enable,freespace,search > /dev/null

sed -n '/Pass 0/,$p' "$PHOTOREC_DIR/photorec.log"

CARVED_FILES="$(
  find "$PHOTOREC_DIR" -type f ! -name photorec.log ! -name report.xml \
    -printf . | wc -c
)"
printf 'carved_files=%s\n' "$CARVED_FILES"

printf '\nRecovery record complete: %s\n' "$OUT_DIR"
```

**Output**

```text {"ignore":"true"}
[D-05] TAR-only PhotoRec attempt
Pass 0 (blocksize=4096) STATUS_FIND_OFFSET
blocksize=4096, offset=0
Elapsed time 0h00m00s
Pass 1 (blocksize=4096) STATUS_EXT2_ON
Elapsed time 0h00m02s
Pass 1 +0 file
Total: 0 files found

3706368 sectors contain unknown data, 0 invalid files found and rejected.
PhotoRec exited normally.
carved_files=0

Recovery record complete: shared/investigations/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/derived/disk/recovery-20260805T134432Z
```

PhotoRec completed normally and the output contained zero carved files, so
there was no TAR candidate to validate. The uploaded archive was not recovered
by this method; this does not establish that it never existed or that no
fragments remain.

## D-06 - Disk investigation synthesis

The allocated-filesystem examination found the surviving system-wide preload
configuration, statically characterised its referenced ELF, and found
suspicious residue during a recursive `/tmp` examination. The recovery
experiments produced one complete content candidate and otherwise completed
with zero results. No target had an entry-only, partial-content, or tool-failure
result. No generic unallocated-space `.c`, `.o`, or ELF search was performed.

| Finding or target | Result | Support | Limitation |
| --- | --- | --- | --- |
| Surviving LD_PRELOAD configuration | Observed in the allocated filesystem | D-01: allocated `/etc/ld.so.preload`, inode `61596`, contains `/lib/selinux.so.3`; the resolved `/usr/lib/selinux.so.3` is an allocated 32,784-byte ELF at inode `62345`, SHA-256 `87fece49...2f0711` | The configuration timestamps cannot be precisely sequenced against host-recorded scenario times |
| Recovered ELF characteristics | Observed with standard static tools | Complete header, dependency, dynamic-symbol and strings outputs; functions cover file, directory, network and shell behavior | Consistent with an interposition/backdoor library, but static examination does not establish runtime execution |
| Suspicious `/tmp` residue | Observed during recursive TSK examination | `/tmp/forensic-lab/father_ldpreload/probe/__malicious_file`, allocated inode `260193`, size 0, uid/gid `1000/1000` | Offline visibility does not independently prove live hiding |
| Uploaded TAR | Not recovered by this method | Empty `fls` and recursive ext4magic results; PhotoRec completed normally with `carved_files=0` | No recovered TAR candidate for structural or hash validation |
| Deleted Father directory | Not recovered by this method | Parent inode `258155`; `fls -d` returned no entry | No directory inode for `istat` or child examination |
| Modified `src/config.h` | Complete boundary-delimited candidate content recovered through a ground-truth-guided, scenario-specific search | Ext4 block `589864`; `blkstat`: not allocated, group `18`; `ifind -d`: successful `Inode not found` zero result; C-header candidate, 740 bytes, SHA-256 `d14ebf96...120ad4` | Pathname, inode, timestamps and directory association were not recovered |
| Built `rk.so` | Not recovered by this method | Empty recursive ext4magic result and no inode candidate | No complete candidate was recovered for comparison |
| `.bash_history` | Not recovered by this method | Parent inode `258049`; empty `fls` and recursive ext4magic results | Does not establish whether persistent history once existed |

These zero results describe only the bounded techniques used here and do not
establish absence of the TAR, directory, `rk.so`, or `.bash_history`.
