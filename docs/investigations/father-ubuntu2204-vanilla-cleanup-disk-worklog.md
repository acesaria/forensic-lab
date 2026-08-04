# Father cleanup disk/filesystem worklog

**Run:** `ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708`
**Scope:** post-mortem examination of the acquired disk and its ext4 root
filesystem.

## Method

Preservation and acquisition have already been completed. This worklog covers
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
The worklog records only the resolved parameters needed to understand and
repeat the examination.

| Parameter | Resolved value |
| --- | --- |
| Run ID | `ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708` |
| Disk image | `shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708/dumps/disk/evidence_disk.E01` |
| TSK bodyfile | `shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708/analysis/bodyfile` |
| Root partition start | `227328` sectors |
| Root partition length | `8161247` sectors |
| TSK sector size | `512` bytes |
| ext4 block size | `4096` bytes |
| Guest timezone | `Etc/UTC` |
| Scenario start | `2026-07-24T14:27:08.159Z` |
| Scenario end | `2026-07-24T14:27:10.260Z` |
| Recovery output | `shared/investigations/.../derived/recovery-20260729T162342Z` |

The partition offset passed to TSK commands is therefore `227328` sectors.
Times are interpreted in the guest timezone (`Etc/UTC`).

## D-01 - Examine suspected system-wide LD_PRELOAD persistence

Given the suspected technique, the examination begins with
`/etc/ld.so.preload`, the standard system-wide preload configuration file.
TSK `ifind` is used to resolve the known path to an inode; `istat` then reports
the inode's allocation state and metadata.

### D-01.1 - Resolve the path and inspect its inode

**Command**

```bash
ifind -i ewf -o 227328 -n /etc/ld.so.preload \
  "shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708/dumps/disk/evidence_disk.E01"
```

**Observed output**

```text
17436
```

The pathname resolves to inode `17436`. That inode is then examined directly:

**Command**

```bash
istat -i ewf -o 227328 -z Etc/UTC \
  "shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708/dumps/disk/evidence_disk.E01" \
  17436
```

**Observed output**

```text
inode: 17436
Allocated
Group: 1
Generation Id: 609040175
uid / gid: 0 / 0
mode: rrw-r--r--
Flags: Extents,
size: 17
num of links: 1

Inode Times:
Accessed:       2026-07-24 14:27:12.838920012 (UTC)
File Modified:  2026-07-24 14:27:12.834920012 (UTC)
Inode Modified: 2026-07-24 14:27:12.834920012 (UTC)
File Created:   2026-07-24 14:27:12.834920012 (UTC)

Direct Blocks:
485409
```

The file is allocated, owned by `root:root`, and has a size of 17 bytes.
At this stage, this confirms that the preload configuration file survives in
the acquired filesystem. Its content has not yet been examined.

### D-01.2 - Examine the configuration content

The file is only 17 bytes, so its content can be examined directly with TSK
`icat`.

**Command**

```bash
icat -i ewf -o 227328 \
  "shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708/dumps/disk/evidence_disk.E01" 17436
```

**Observed output**

```text
/lib/selinux.so.3
```

The configuration references `/lib/selinux.so.3`. This is only a pathname:
the referenced file must now be resolved and examined before its purpose can
be assessed.

### D-01.3 - Resolve and inspect the referenced file

We try via `ifind` to recover the inode from the file-path (`/lib/selinux.so.3`), but an error emerged. This could happen in presence of symbolic link:

**Command**
```bash
ifind -o 227328 -n '/lib/selinux.so.3' $DISK_IMAGE
```
**Output**
```text
Error extracting file from image (ext2fs_dir_open_meta: Error reading directory contents: 1542)
```

Let's confirm this hypothesis, resolving the path `/lib` first, before resolving the complete library path:

**Commands**

```bash
ifind -i ewf -o 227328 -n /lib \
  "shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708/dumps/disk/evidence_disk.E01"

istat -i ewf -o 227328 -z Etc/UTC \
  "shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708/dumps/disk/evidence_disk.E01" \
  1542

ifind -i ewf -o 227328 -n /usr/lib/selinux.so.3 \
  "shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708/dumps/disk/evidence_disk.E01"

istat -i ewf -o 227328 -z Etc/UTC \
  "shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708/dumps/disk/evidence_disk.E01" \
  17435
```

**Selected observed output**

```text
inode: 1542
Allocated
size: 7
symbolic link to: usr/lib

[---]

resolved_path=/usr/lib/selinux.so.3
library_inode=17435
inode: 17435
Allocated

Group: 1
Generation Id: 2334173266
uid / gid: 0 / 0
mode: rrw-r--r--
Flags: Extents,
size: 32784
num of links: 1

Inode Times:
Accessed:       2026-07-24 14:27:09.958920012 (UTC)
File Modified:  2026-07-24 14:27:09.890920012 (UTC)
Inode Modified: 2026-07-24 14:27:09.890920012 (UTC)
File Created:   2026-07-24 14:27:09.890920012 (UTC)

Direct Blocks:
485384 485385 485386 485387 485388 485389 485390 485391
485392
```

The `/lib` link points to `/usr/lib`; consequently, the referenced object
resolves to `/usr/lib/selinux.so.3`, inode `17435`. It is an allocated,
root-owned file created and modified during the scenario window. Its plausible
name is not sufficient to determine whether it is legitimate or malicious.

### D-01.4 - Recover and identify the referenced object

The allocated file is recovered to the investigation directory. Its hash is
recorded and `file` is used for basic format identification.

**Commands**

```bash
icat -i ewf -o 227328 \
  "shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708/dumps/disk/evidence_disk.E01" \
  17435 \
  > "$INV_DIR/derived/d-01/usr-lib-selinux.so.3"

sha256sum "$INV_DIR/derived/d-01/usr-lib-selinux.so.3"
file -b "$INV_DIR/derived/d-01/usr-lib-selinux.so.3"
```

**Observed output**

```text
87fece49fc15a48372a1ba76cf424755f9cfab6cce7e8073002757f7db2f0711  shared/investigations/ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708/derived/d-01/usr-lib-selinux.so.3
ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=96daef8bb7ab389abcb5aa9458436759949849c7, not stripped
```

The recovered file is an ELF shared object, which is consistent with its use
through `ld.so.preload`. This still does not prove that it is a rootkit:
attribution depends on the disclosed controlled-scenario context.
Further static ELF inspection can characterise its structure and possible
functionality. RAM and timeline evidence instead corroborate mapping/runtime
state and timing.

## D-02 - Scope of deleted-artifact recovery

This is separate from the allocated persistence examination. The recursive
ext4 recovery pass is a bounded completeness experiment and does not use a
target list. The target paths come from the scenario implementation and are
used only afterward for disclosed-ground-truth validation; they are not
discoveries from the disk.

| Recovery method terminology | Use in this worklog |
| --- | --- |
| deleted directory-entry examination | TSK `fls -d` examination of the three relevant parent directories |
| journal-assisted recovery attempt | Time-bounded recursive `ext4magic -R` completeness experiment, followed by a full inventory and disclosed-target validation |
| ground-truth-guided targeted content recovery from unallocated filesystem blocks | Marker-led `blkls`, `blkcalc`, and `blkcat` recovery of the disclosed `config.h` content |
| signature-based file carving from unallocated space | TAR-only PhotoRec attempt over ext4 free space |

| Recovery target | Disclosed pre-cleanup location |
| --- | --- |
| Uploaded archive | `/tmp/father-upstream-4eb2712.tar` |
| Extracted Father tree | `/tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/` |
| Modified configuration | `.../src/config.h` |
| Built shared object | `.../rk.so` |
| Bash-history cleanup target | `/home/labuser/.bash_history` |

## D-03 (R-01) - Are deleted target entries still present?

TSK resolves each parent with `ifind` and asks its ext4 namespace for deleted
entries with `fls -d`.

```bash
TMP_INODE="$(ifind -i ewf -o "$OFFSET" -n /tmp "$DISK_IMAGE")"
FATHER_INODE="$(ifind -i ewf -o "$OFFSET" \
  -n /tmp/forensic-lab/father_ldpreload "$DISK_IMAGE")"
LABUSER_INODE="$(ifind -i ewf -o "$OFFSET" -n /home/labuser "$DISK_IMAGE")"
fls -i ewf -o "$OFFSET" -z Etc/UTC -d -l "$DISK_IMAGE" "$TMP_INODE" \
  >"$OUT_DIR/deleted-entries/tmp-deleted.txt"
fls -i ewf -o "$OFFSET" -z Etc/UTC -d -l "$DISK_IMAGE" "$FATHER_INODE" \
  >"$OUT_DIR/deleted-entries/father-parent-deleted.txt"
fls -i ewf -o "$OFFSET" -z Etc/UTC -d -l "$DISK_IMAGE" "$LABUSER_INODE" \
  >"$OUT_DIR/deleted-entries/labuser-deleted.txt"
```

```text
/tmp inode: 1581; deleted entries: no output
father_ldpreload inode: 258151; deleted entries: no output
/home/labuser inode: 258049; deleted entries: no output
```

In ext4, a directory entry associates a filename with an inode. Deletion removes
that association and makes the inode and data blocks available for reuse.
Residual directory-entry or inode information may sometimes remain recoverable,
but this is not guaranteed. In this case, `fls -d` found no interpretable
deleted entry in the three examined parent directories. The deleted target
entries were not recovered by this method, so there was no inode locator
available for `istat` or `icat`. This bounded negative does not establish
absence.

## D-04 (R-02) - Can bounded recursive ext4magic recover any entry?

`ext4magic` required an offset-free ext4 derivative. The bounded completeness
experiment started at the filesystem root and used the scenario interval plus
60 seconds on each side with the permissive recursive `-R` mode. This can
consider both deleted and allocated matching inodes, so all recovered entries
are inventoried before the disclosed target paths are checked.

```bash
ewfexport -q -u -f raw -o 116391936 -B 4178558464 -t - \
  "$DISK_IMAGE" >"$OUT_DIR/root-partition.ext4"
chmod a-w "$OUT_DIR/root-partition.ext4"
sha256sum "$OUT_DIR/root-partition.ext4" |
  tee "$OUT_DIR/root-partition.ext4.sha256"

RECOVER_DIR="$OUT_DIR/ext4magic/recovered-R"
INVENTORY="$OUT_DIR/ext4magic/recovered-R-inventory.txt"
TARGET_RESULTS="$OUT_DIR/ext4magic/disclosed-target-results.txt"
mkdir -p "$RECOVER_DIR"

ext4magic "$OUT_DIR/root-partition.ext4" \
  -a 1784903168 -b 1784903290 \
  -R -d "$OUT_DIR/ext4magic/recovered-R" \
  2>&1 | tee "$OUT_DIR/ext4magic/ext4magic-R.txt"

find "$RECOVER_DIR" -mindepth 1 \
  -printf '%y %s bytes %p\n' | sort | tee "$INVENTORY"

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

```text
f54f171672e057fdb364f90383dd741a2e15d752d7267a63e8e1682305ed2cd5  root-partition.ext4
ext4magic : EXIT_SUCCESS
ext4magic completed successfully with zero recovered entries.
target=tmp/father-upstream-4eb2712.tar matches=0
target=tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/src/config.h matches=0
target=tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/rk.so matches=0
target=home/labuser/.bash_history matches=0
```

The recursive inventory was empty. `ext4magic` completed successfully, so this
is a successful zero-result recovery experiment rather than a tool failure.
The four zero-match checks occurred only after the complete inventory and are
ground-truth-guided validation.

The recursive scope is broader than the previous four-target input-list pass,
but remains bounded by the 122-second interval, ext4magic's journal semantics,
and the journal data available in this image. It recovered no entry and does
not establish that historical data never existed.

## D-05 - Is the modified config.h present in unallocated blocks?

The disclosed source archive supplied a validation reference. This is
ground-truth-guided validation, not technique-led discovery.

This is not slack-space recovery: `blkls` was used without `-s`, so the stream
contains unallocated filesystem blocks rather than file slack.

### Reference preparation

```bash
CONFIG_PATTERN='#define STRING "__malicious_"'
EXPECTED_CONFIG="$OUT_DIR/ground-truth/expected-modified-config.h"

tar -xOf scenarios/userland_father_ldpreload/files/father-upstream-4eb2712.tar \
  Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/src/config.h |
  sed "s|^#define STRING .*|$CONFIG_PATTERN|" >"$EXPECTED_CONFIG"

EXPECTED_CONFIG_SIZE="$(stat -c %s "$EXPECTED_CONFIG")"
REFERENCE_PATTERN_OFFSET="$(
  LC_ALL=C grep -aobF -- "$CONFIG_PATTERN" "$EXPECTED_CONFIG" |
    cut -d: -f1
)"
printf 'size=%s bytes\nmarker_offset=%s\n' \
  "$EXPECTED_CONFIG_SIZE" "$REFERENCE_PATTERN_OFFSET"
```

```text
size=740 bytes
marker_offset=368
```

### Marker location

```bash
UNALLOCATED="$OUT_DIR/unallocated/unallocated.blkls"
blkls -i ewf -o "$OFFSET" "$DISK_IMAGE" \
  >"$UNALLOCATED"
LC_ALL=C grep -aobF -- "$CONFIG_PATTERN" "$UNALLOCATED" \
  >"$OUT_DIR/unallocated/config-pattern-hits.txt" || true
wc -l <"$OUT_DIR/unallocated/config-pattern-hits.txt"
sed -n '1p' "$OUT_DIR/unallocated/config-pattern-hits.txt"
```

```text
1
541344112:#define STRING "__malicious_"
```

Exactly one marker hit was present, satisfying the script's precondition for
offset arithmetic.

### blkls-to-filesystem block mapping

```bash
HIT_OFFSET=541344112
BLOCK_SIZE=4096
PACKED_BLOCK=$((HIT_OFFSET / BLOCK_SIZE))
HIT_OFFSET_IN_BLOCK=$((HIT_OFFSET % BLOCK_SIZE))
FILESYSTEM_BLOCK="$(
  blkcalc -i ewf -o "$OFFSET" -u "$PACKED_BLOCK" "$DISK_IMAGE"
)"
printf '%s / %s = packed block %s, remainder %s\n' \
  "$HIT_OFFSET" "$BLOCK_SIZE" "$PACKED_BLOCK" "$HIT_OFFSET_IN_BLOCK"
printf 'blkcalc maps packed block %s to ext4 block %s\n' \
  "$PACKED_BLOCK" "$FILESYSTEM_BLOCK"
```

```text
541344112 / 4096 = packed block 132164, remainder 368
blkcalc maps packed block 132164 to ext4 block 589851
```

### Extraction and validation

```bash
CONFIG_START_IN_BLOCK=$((HIT_OFFSET_IN_BLOCK - REFERENCE_PATTERN_OFFSET))
printf 'marker offset in reference = %s\n' "$REFERENCE_PATTERN_OFFSET"
printf 'extraction start = %s - %s = %s\n' \
  "$HIT_OFFSET_IN_BLOCK" "$REFERENCE_PATTERN_OFFSET" "$CONFIG_START_IN_BLOCK"

BLOCK_FILE="$OUT_DIR/unallocated/config-source-block-$FILESYSTEM_BLOCK.bin"
RECOVERED_CONFIG="$OUT_DIR/unallocated/recovered-config.h"
blkcat -i ewf -o "$OFFSET" "$DISK_IMAGE" "$FILESYSTEM_BLOCK" >"$BLOCK_FILE"
dd if="$BLOCK_FILE" of="$RECOVERED_CONFIG" \
  bs=1 skip="$CONFIG_START_IN_BLOCK" count="$EXPECTED_CONFIG_SIZE" status=none
sha256sum "$RECOVERED_CONFIG" "$EXPECTED_CONFIG"
cmp "$RECOVERED_CONFIG" "$EXPECTED_CONFIG"
printf 'cmp exit status: %s\n' "$?"
file "$RECOVERED_CONFIG"
```

```text
marker offset in reference = 368
extraction start = 368 - 368 = 0
d14ebf96f7a5d2c10622f415fe1a1ecddeda2756387ba5ae8f52886d64120ad4  recovered-config.h
d14ebf96f7a5d2c10622f415fe1a1ecddeda2756387ba5ae8f52886d64120ad4  expected-modified-config.h
cmp exit status: 0
file: C source, ASCII text
```

Result: complete file-content recovery with ground-truth-guided identification.
The 740-byte recovered content is byte-identical to the disclosed reference.
Filename, inode, timestamps and directory association were not recovered.

## D-06 - Can the uploaded TAR be recovered by file carving?

One PhotoRec run selected ext4 free space and enabled only TAR carving.

```bash
photorec /log /logname "$OUT_DIR/photorec/photorec.log" \
  /d "$OUT_DIR/photorec/carved" \
  /cmd "$OUT_DIR/root-partition.ext4" \
  partition_none,options,mode_ext2,fileopt,everything,disable,tar,enable,freespace,search
```

```text
Pass 0 (blocksize=4096) STATUS_FIND_OFFSET
Pass 1 (blocksize=4096) STATUS_EXT2_ON
Pass 1 +0 file
Total: 0 files found
PhotoRec exited normally.
```

PhotoRec succeeded but returned no file, so there was no TAR candidate to
validate. The uploaded archive was not recovered by this method.

## D-07 - Target-by-target recovery synthesis

No target had an entry-only, partial-content, or tool-failure result. No generic
`.c`, `.o`, or ELF search was performed.

| Target | Result | Validation | Limitation |
| --- | --- | --- | --- |
| Uploaded TAR | Not recovered by this method | Empty `fls` and recursive ext4magic results; PhotoRec found 0 files | No recovered TAR candidate for structural or hash validation |
| Deleted Father directory | Not recovered by this method | Parent inode `258151`; `fls -d` returned no entry | No directory inode for `istat` or child examination |
| Modified `src/config.h` | Complete file-content recovery with ground-truth-guided identification | 740 bytes; SHA-256 `d14ebf96...120ad4`; `cmp` matched | Filename, inode, timestamps and directory association were not recovered |
| Built `rk.so` | Not recovered by this method | Empty recursive ext4magic result and no inode candidate | No complete candidate was recovered for comparison |
| `.bash_history` | Not recovered by this method | Parent inode `258049`; empty `fls` and recursive ext4magic results | Does not establish whether persistent history once existed |

These zero results describe only the bounded techniques used here and do not
establish absence of the TAR, directory, `rk.so`, or `.bash_history`.
