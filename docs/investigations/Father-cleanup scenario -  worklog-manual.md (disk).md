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
4. attempt targeted ext4 recovery only where justified;
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
Its internal structure and functionality must be examined separately through
RAM forensics and timeline analysis.

## D-02 - Scope of deleted-artifact recovery

This is a disclosed ground-truth-guided recovery check, separate from the
allocated persistence examination. The target paths come from the scenario
implementation and are not discoveries from the disk.

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
deleted entry in the three examined parent directories, so there was no inode
locator available for `istat` or `icat`. This is a bounded negative result, not
proof that the artifacts never existed.

## D-04 (R-02) - Can ext4magic recover any bounded file target?

`ext4magic` required an offset-free ext4 derivative and effective root
privileges. The final bounded attempt used the four disclosed file paths, the
scenario interval plus 60 seconds on each side, and the permissive `-R` mode.

```bash
ewfexport -q -u -f raw -o 116391936 -B 4178558464 -t - \
  "$DISK_IMAGE" >"$OUT_DIR/root-partition.ext4"
chmod a-w "$OUT_DIR/root-partition.ext4"
sha256sum "$OUT_DIR/root-partition.ext4"

sudo ext4magic "$OUT_DIR/root-partition.ext4" \
  -a 1784903168 -b 1784903290 \
  -i "$OUT_DIR/ext4magic/targets.txt" \
  -R -d "$OUT_DIR/ext4magic/recovered-R"

sudo find "$OUT_DIR/ext4magic/recovered-R" -mindepth 1 \
  -printf '%y %s bytes %p\n'
```

```text
f54f171672e057fdb364f90383dd741a2e15d752d7267a63e8e1682305ed2cd5  root-partition.ext4
targets.txt accept for inputfile
recovered-R accept for recoverdir
Using internal Journal at Inode 8
Activ Time after  : Fri Jul 24 16:26:08 2026
Activ Time before : Fri Jul 24 16:28:10 2026
ext4magic : EXIT_SUCCESS
No artifact was recovered for the four bounded file targets.
```

The tool completed but recovered no entry or content for any bounded target.
This is a negative method result, not a tool failure and not proof that no
historical journal data ever existed.

## D-05 - Is the modified config.h present in unallocated blocks?

The disclosed source archive supplied a validation reference. TSK then
extracted and mapped the one observed hit in unallocated blocks.

```bash
tar -xOf scenarios/userland_father_ldpreload/files/father-upstream-4eb2712.tar \
  Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/src/config.h |
  sed 's|^#define STRING .*|#define STRING "__malicious_"|' \
  >"$OUT_DIR/ground-truth/expected-modified-config.h"
blkls -i ewf -o "$OFFSET" "$DISK_IMAGE" \
  >"$OUT_DIR/unallocated/unallocated.blkls"
grep -aobF '#define STRING "__malicious_"' \
  "$OUT_DIR/unallocated/unallocated.blkls"
blkcalc -i ewf -o "$OFFSET" -u 132164 "$DISK_IMAGE"
blkcat -i ewf -o "$OFFSET" "$DISK_IMAGE" 589851 \
  >"$OUT_DIR/unallocated/config-source-block-589851.bin"
dd if="$OUT_DIR/unallocated/config-source-block-589851.bin" \
  of="$OUT_DIR/unallocated/recovered-config.h" \
  bs=1 count=740 status=none
sha256sum "$OUT_DIR/unallocated/recovered-config.h" \
  "$OUT_DIR/ground-truth/expected-modified-config.h"
cmp "$OUT_DIR/unallocated/recovered-config.h" \
  "$OUT_DIR/ground-truth/expected-modified-config.h"
file "$OUT_DIR/unallocated/recovered-config.h"
```

```text
541344112:#define STRING "__malicious_"
589851
d14ebf96f7a5d2c10622f415fe1a1ecddeda2756387ba5ae8f52886d64120ad4  recovered-config.h
d14ebf96f7a5d2c10622f415fe1a1ecddeda2756387ba5ae8f52886d64120ad4  expected-modified-config.h
cmp exit status: 0
file: C source, ASCII text
```

The hit at byte `541344112` maps from packed `blkls` block `132164` to ext4
block `589851`. The recovered 740 bytes are byte-identical to the disclosed
reference, so this target is full content, with ground-truth-guided identity.

One scenario-specific marker was found in the ext4 unallocated-block stream and mapped by TSK to filesystem block 589851. The recovered 740-byte slice was byte-identical to the disclosed modified config.h, establishing complete content recovery. No filename, inode, timestamps, or directory association were recovered; identification as src/config.h is therefore ground-truth guided

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
validate. The uploaded archive was not recovered by this bounded method.

## D-07 - Target-by-target recovery synthesis

No target had an entry-only, partial-content, or tool-failure result. No generic
`.c`, `.o`, or ELF search was performed.

| Target | Result | Validation | Limitation |
| --- | --- | --- | --- |
| Uploaded TAR | Not recovered | Empty `fls` and ext4magic results; PhotoRec found 0 files | No recovered TAR candidate for structural or hash validation |
| Deleted Father directory | Not recovered | Parent inode `258151`; `fls -d` returned no entry | No directory inode for `istat` or child examination |
| Modified `src/config.h` | Full content at ext4 block `589851` | 740 bytes; SHA-256 `d14ebf96...120ad4`; `cmp` matched | Selection and attribution are ground-truth-guided |
| Built `rk.so` | Not recovered | Empty ext4magic result and no inode candidate | No complete candidate was recovered for comparison |
| `.bash_history` | Not recovered | Parent inode `258049`; empty `fls` and ext4magic results | Does not establish whether persistent history once existed |

These zero results describe only the bounded techniques used here; they do not
prove that the TAR, directory, `rk.so`, or `.bash_history` never existed.
