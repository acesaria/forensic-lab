---
cwd: ../../../..
shell: bash
---

# Father disk investigation

__Run:__ `ubuntu-22.04_userland_father_ldpreload_20260813-124003`

This notebook examines the allocated persistence first, then attempts deleted-
file recovery from the least specialised method to the most explicit one:
`ext4magic`, `extundelete`, and finally direct ext4 journal interpretation.

The acquired EWF image remains read-only. Commands write only to the matching
`shared/investigations` workspace. Scenario records are used for final labelled
validation, not to select the deleted-file candidate.

## D-00 — Establish the case and export the root filesystem

**Question:** Is this the intended completed acquisition, and what filesystem
will the recovery tools examine?

`mmls` identifies the root partition at sector 227328. `ext4magic`,
`extundelete`, and `debugfs` require an unmounted ext4 image, so the cell exports
that partition once and makes it read-only.

```bash {"name":"D-00-Prepare-Root-Image","promptEnv":"never"}
set -euo pipefail

RUN_ID='ubuntu-22.04_userland_father_ldpreload_20260813-124003'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
OUT_DIR="$INV_DIR/derived/disk"

MANIFEST="$RUN_DIR/manifest.json"
ACQUISITION="$RUN_DIR/dumps/acquisition.json"
DISK_IMAGE="$RUN_DIR/dumps/disk/evidence_disk.E01"
INPUT_LIBRARY="$RUN_DIR/inputs/userland_father_ldpreload/rk.so"
ROOT_IMAGE="$OUT_DIR/root-partition.ext4"

ROOT_START_SECTOR=227328
ROOT_SECTOR_COUNT=20744159
SECTOR_SIZE_BYTES=512
ROOT_OFFSET_BYTES=$((ROOT_START_SECTOR * SECTOR_SIZE_BYTES))
ROOT_LENGTH_BYTES=$((ROOT_SECTOR_COUNT * SECTOR_SIZE_BYTES))

grep -E '"(status|scenario_status)": "completed"' "$MANIFEST"
grep -E '"(disk_acquisition_mode|disk_preparation)"' "$ACQUISITION"
mmls -i ewf "$DISK_IMAGE"
fls -V
debugfs -V 2>&1 | sed -n '1,2p'
ext4magic -V
extundelete --version

mkdir -p "$OUT_DIR"
if [[ ! -e "$ROOT_IMAGE" ]]; then
  img_cat -i ewf "$DISK_IMAGE" |
    dd of="$ROOT_IMAGE" bs=1M iflag=fullblock,skip_bytes,count_bytes \
      skip="$ROOT_OFFSET_BYTES" count="$ROOT_LENGTH_BYTES" status=progress
  chmod a-w "$ROOT_IMAGE"
fi

ROOT_IMAGE="$(realpath "$ROOT_IMAGE")"
export RUN_ID="$RUN_ID"
export RUN_DIR="$RUN_DIR"
export OUT_DIR="$OUT_DIR"
export DISK_IMAGE="$DISK_IMAGE"
export INPUT_LIBRARY="$INPUT_LIBRARY"
export ROOT_IMAGE="$ROOT_IMAGE"
export ROOT_START_SECTOR="$ROOT_START_SECTOR"

fsstat "$ROOT_IMAGE" | sed -n '1,20p'
printf 'root_image=%s\n' "$ROOT_IMAGE"
```

## D-01 — Examine the allocated persistence

**Question:** What LD_PRELOAD artifacts remain in the allocated filesystem?

Start from the technique: `/etc/ld.so.preload` names the system-wide preload
object. Offline filesystem tools are not affected by the library's `readdir()`
hook, so they can also expose the controlled hidden-file probe.

```bash {"name":"D-01-Allocated-Persistence","promptEnv":"never"}
set -euo pipefail

ALLOCATED_LIST="$OUT_DIR/allocated-father-files.txt"
fls -r -p -l -o "$ROOT_START_SECTOR" "$DISK_IMAGE" >"$ALLOCATED_LIST"

grep -E 'etc/ld.so.preload|selinux.so.3|__malicious_file' \
  "$ALLOCATED_LIST"

PRELOAD_INODE=74170
INSTALLED_LIBRARY_INODE=74169
PRELOAD_COPY="$OUT_DIR/ld.so.preload"
INSTALLED_LIBRARY="$OUT_DIR/selinux.so.3"

icat "$ROOT_IMAGE" "$PRELOAD_INODE" >"$PRELOAD_COPY"
icat "$ROOT_IMAGE" "$INSTALLED_LIBRARY_INODE" >"$INSTALLED_LIBRARY"
chmod a-w "$PRELOAD_COPY" "$INSTALLED_LIBRARY"

export INSTALLED_LIBRARY="$INSTALLED_LIBRARY"
printf '%s\n' '--- /etc/ld.so.preload ---'
sed -n '1,10p' "$PRELOAD_COPY"
```

**Observation.** The allocated filesystem contains `/etc/ld.so.preload`
(inode 74170), `/usr/lib/selinux.so.3` (inode 74169), and the controlled probe
file. The preload configuration names `/lib/selinux.so.3`; Ubuntu's merged
`/usr` layout accounts for the library's observed `/usr/lib` pathname. Offline
filesystem traversal exposes the probe even though the compromised live `ls`
did not.

## D-02 — Attempt recovery with ext4magic

**Question:** Can a standard journal-aware ext4 recovery tool restore the
deleted staging object by pathname?

The attempt is deliberately targeted and writes to a fresh directory. A failed
tool attempt is not evidence that the file never existed.

```bash {"name":"D-02-Ext4magic","promptEnv":"never"}
set -euo pipefail

EXT4MAGIC_DIR="$OUT_DIR/ext4magic"
EXT4MAGIC_LOG="$OUT_DIR/ext4magic.txt"

if [[ -e "$EXT4MAGIC_LOG" ]]; then
  printf 'error: output already exists: %s\n' "$EXT4MAGIC_LOG" >&2
  exit 1
fi

if ext4magic "$ROOT_IMAGE" -r -f tmp/rk.so -d "$EXT4MAGIC_DIR" \
    >"$EXT4MAGIC_LOG" 2>&1; then
  EXT4MAGIC_STATUS=0
else
  EXT4MAGIC_STATUS=$?
fi

printf 'ext4magic_exit_status=%s\n' "$EXT4MAGIC_STATUS"
sed -n '1,120p' "$EXT4MAGIC_LOG"
find "$EXT4MAGIC_DIR" -type f -print 2>/dev/null || true
```

**Observation.** ext4magic 0.3.2 exited successfully but produced no recovered
file. This is a valid zero result for this tool and targeted pathname, not proof
that the staging object never existed.

## D-03 — Attempt recovery with extundelete

**Question:** Does an independent standard recovery tool obtain a different
result from the same unmounted image?

```bash {"name":"D-03-Extundelete","promptEnv":"never"}
set -euo pipefail

EXTUNDELETE_DIR="$OUT_DIR/extundelete"
EXTUNDELETE_LOG="$OUT_DIR/extundelete.txt"

if [[ -e "$EXTUNDELETE_DIR" ]]; then
  printf 'error: output already exists: %s\n' "$EXTUNDELETE_DIR" >&2
  exit 1
fi

mkdir "$EXTUNDELETE_DIR"
if (
  cd "$EXTUNDELETE_DIR"
  extundelete "$ROOT_IMAGE" --restore-file tmp/rk.so
) >"$EXTUNDELETE_LOG" 2>&1; then
  EXTUNDELETE_STATUS=0
else
  EXTUNDELETE_STATUS=$?
fi

printf 'extundelete_exit_status=%s\n' "$EXTUNDELETE_STATUS"
sed -n '1,120p' "$EXTUNDELETE_LOG"
find "$EXTUNDELETE_DIR" -type f -print
```

**Observation.** extundelete 0.2.4 loaded 80 filesystem groups and 5,437
journal descriptors, then exited 1 because it could not associate
`tmp/rk.so` with an inode. This tool failure does not invalidate a recovery by
another method.

## D-04 — Locate historical directory metadata in the journal

**Question:** If automated recovery fails, does the journal preserve an older
copy of `/tmp` that still names the deleted object?

The directory's current inode and data block are first obtained with standard
filesystem tools. `debugfs logdump` then lists journal copies of that block.
The journal block containing `rk.so` is selected by content, not from the
scenario manifest.

```bash {"name":"D-04-Journal-Directory","promptEnv":"never"}
set -euo pipefail

TMP_INODE="$(ifind -n /tmp "$ROOT_IMAGE")"
TMP_DIRECTORY_BLOCK="$(
  debugfs -R 'blocks /tmp' "$ROOT_IMAGE" 2>/dev/null
)"
TMP_INODE=$((TMP_INODE))
TMP_DIRECTORY_BLOCK=$((TMP_DIRECTORY_BLOCK))
DIRECTORY_LOG="$OUT_DIR/tmp-directory-journal.txt"

istat "$ROOT_IMAGE" "$TMP_INODE" | sed -n '1,80p'
debugfs -R "logdump -O -b $TMP_DIRECTORY_BLOCK" "$ROOT_IMAGE" \
  >"$DIRECTORY_LOG" 2>&1
grep "FS block $TMP_DIRECTORY_BLOCK logged" "$DIRECTORY_LOG"

DIRECTORY_JOURNAL_BLOCKS="$(
  sed -n 's/.*journal block \([0-9]*\).*/\1/p' "$DIRECTORY_LOG"
)"

DIRECTORY_JOURNAL_BLOCK=''
for JOURNAL_BLOCK in $DIRECTORY_JOURNAL_BLOCKS; do
  DIRECTORY_COPY="$OUT_DIR/tmp-journal-$JOURNAL_BLOCK.bin"
  jcat -i ewf -o "$ROOT_START_SECTOR" \
    "$DISK_IMAGE" "$JOURNAL_BLOCK" >"$DIRECTORY_COPY"
  if grep -aq 'rk.so' "$DIRECTORY_COPY"; then
    DIRECTORY_JOURNAL_BLOCK="$JOURNAL_BLOCK"
    printf 'rk.so found in journal block %s\n' "$JOURNAL_BLOCK"
    grep -aob -m1 'rk.so' "$DIRECTORY_COPY"
  fi
done

if [[ -z "$DIRECTORY_JOURNAL_BLOCK" ]]; then
  printf 'rk.so was not found in the journal copies of /tmp\n' >&2
  exit 1
fi

DIRECTORY_SEQUENCE="$(
  sed -n "/journal block $DIRECTORY_JOURNAL_BLOCK / {
    s/.*sequence \([0-9]*\),.*/\1/p
  }" "$DIRECTORY_LOG"
)"
DIRECTORY_COPY="$OUT_DIR/tmp-journal-$DIRECTORY_JOURNAL_BLOCK.bin"
RK_NAME_OFFSET="$(grep -aob -m1 'rk.so' "$DIRECTORY_COPY" | cut -d: -f1)"
RK_DIRENT_OFFSET=$((RK_NAME_OFFSET - 8))
DELETED_INODE="$(
  dd if="$DIRECTORY_COPY" bs=1 skip="$RK_DIRENT_OFFSET" \
    count=4 status=none | od -An -tu4 --endian=little
)"
DELETED_INODE=$((DELETED_INODE))
export DELETED_INODE="$DELETED_INODE"
export DIRECTORY_SEQUENCE="$DIRECTORY_SEQUENCE"

printf 'journal_sequence=%s\ndeleted_inode=%s\n' \
  "$DIRECTORY_SEQUENCE" "$DELETED_INODE"
xxd -g 1 -s "$RK_DIRENT_OFFSET" -l 16 "$DIRECTORY_COPY"
```

**Observation.** `/tmp` is inode 1581 and its directory data occupies
filesystem block 16758. Of the journal copies listed by `debugfs`, journal
block 669 contains `rk.so` at byte offset 336. The preceding ext4 directory-
entry fields identify inode 74163. `logdump` reported a short read while
scanning the stale journal tail, after enumerating the relevant block copies;
the warning is retained in the complete log.

## D-05 — Decode the historical inode

**Question:** Does the journal preserve the deleted file's metadata after its
inode number has been reused?

`debugfs imap` locates the inode inside its inode-table block. The current inode
is displayed first to make reuse explicit. Journal block 657 preserves the
earlier state; only the ext4 fields needed for recovery are decoded.

```bash {"name":"D-05-Journal-Inode","promptEnv":"never"}
set -euo pipefail

INODE_LOCATION="$(debugfs -R "imap <$DELETED_INODE>" "$ROOT_IMAGE" 2>&1)"
printf '%s\n' "$INODE_LOCATION"
INODE_TABLE_BLOCK="$(
  printf '%s\n' "$INODE_LOCATION" |
    sed -n 's/.*located at block \([0-9]*\),.*/\1/p'
)"
INODE_OFFSET="$(
  printf '%s\n' "$INODE_LOCATION" |
    sed -n 's/.*offset \(0x[0-9a-fA-F]*\).*/\1/p'
)"
INODE_TABLE_BLOCK=$((INODE_TABLE_BLOCK))
INODE_OFFSET=$((INODE_OFFSET))
INODE_LOG="$OUT_DIR/inode-table-journal.txt"

istat "$ROOT_IMAGE" "$DELETED_INODE" | sed -n '1,17p'

debugfs -R "logdump -O -b $INODE_TABLE_BLOCK" "$ROOT_IMAGE" \
  >"$INODE_LOG" 2>&1
grep "FS block $INODE_TABLE_BLOCK logged" "$INODE_LOG"

INODE_JOURNAL_BLOCK="$(
  sed -n "/sequence $DIRECTORY_SEQUENCE, / {
    s/.*journal block \([0-9]*\).*/\1/p
  }" "$INODE_LOG"
)"
if [[ -z "$INODE_JOURNAL_BLOCK" ]]; then
  printf 'no inode-table copy in journal sequence %s\n' \
    "$DIRECTORY_SEQUENCE" >&2
  exit 1
fi

INODE_COPY="$OUT_DIR/inode-journal-$INODE_JOURNAL_BLOCK.bin"
jcat -i ewf -o "$ROOT_START_SECTOR" \
  "$DISK_IMAGE" "$INODE_JOURNAL_BLOCK" >"$INODE_COPY"

FILE_UID="$(
  dd if="$INODE_COPY" bs=1 skip=$((INODE_OFFSET + 2)) \
    count=2 status=none | od -An -tu2 --endian=little
)"
FILE_SIZE="$(
  dd if="$INODE_COPY" bs=1 skip=$((INODE_OFFSET + 4)) \
    count=4 status=none | od -An -tu4 --endian=little
)"
EXTENT_LENGTH="$(
  dd if="$INODE_COPY" bs=1 skip=$((INODE_OFFSET + 56)) \
    count=2 status=none | od -An -tu2 --endian=little
)"
DATA_BLOCK_HIGH="$(
  dd if="$INODE_COPY" bs=1 skip=$((INODE_OFFSET + 58)) \
    count=2 status=none | od -An -tu2 --endian=little
)"
DATA_BLOCK_LOW="$(
  dd if="$INODE_COPY" bs=1 skip=$((INODE_OFFSET + 60)) \
    count=4 status=none | od -An -tu4 --endian=little
)"

FILE_UID=$((FILE_UID))
FILE_SIZE=$((FILE_SIZE))
EXTENT_LENGTH=$((EXTENT_LENGTH))
DATA_BLOCK=$((DATA_BLOCK_LOW + (DATA_BLOCK_HIGH << 32)))

export FILE_SIZE="$FILE_SIZE"
export EXTENT_LENGTH="$EXTENT_LENGTH"
export DATA_BLOCK="$DATA_BLOCK"

printf 'inode=%s\nuid=%s\nsize=%s\ndata_block=%s\nextent_length=%s\n' \
  "$DELETED_INODE" "$FILE_UID" "$FILE_SIZE" \
  "$DATA_BLOCK" "$EXTENT_LENGTH"
xxd -g 1 -s "$INODE_OFFSET" -l 128 "$INODE_COPY"
```

**Observation.** The current allocated inode 74163 is a root-owned
31,700,270-byte file, so its current state cannot describe `rk.so`. The
historical journal copy records UID 1000, size 32,784, and one nine-block extent
beginning at filesystem block 1015822. This is direct evidence of inode reuse.

## D-06 — Recover content and correlate the deployment path

**Question:** Do the journal-predicted blocks still contain a coherent ELF, and
can its deployment relationship be corroborated?

`blkstat` checks allocation before `blkcat` reads the extent. The installed
library provides an evidence-derived comparison. Only after the deleted
candidate has been selected and reconstructed is the immutable scenario input
used for labelled validation.

```bash {"name":"D-06-Recover-and-Correlate","promptEnv":"never"}
set -euo pipefail

BLOCK_STATUS="$OUT_DIR/deleted-data-block-status.txt"
EXTENT_COPY="$OUT_DIR/rk.so.extent"
RECOVERED_LIBRARY="$OUT_DIR/rk.so.recovered"

blkstat "$ROOT_IMAGE" "$DATA_BLOCK" | tee "$BLOCK_STATUS"
blkcat "$ROOT_IMAGE" "$DATA_BLOCK" "$EXTENT_LENGTH" >"$EXTENT_COPY"
head -c "$FILE_SIZE" "$EXTENT_COPY" >"$RECOVERED_LIBRARY"
chmod a-w "$EXTENT_COPY" "$RECOVERED_LIBRARY"

file "$RECOVERED_LIBRARY"
sha256sum "$RECOVERED_LIBRARY" "$INSTALLED_LIBRARY" "$INPUT_LIBRARY"
cmp "$RECOVERED_LIBRARY" "$INSTALLED_LIBRARY"
cmp "$RECOVERED_LIBRARY" "$INPUT_LIBRARY"
```

**Observation.** Block 1015822 is unallocated. The reconstructed 32,784-byte
ELF has SHA-256
`87fece49fc15a48372a1ba76cf424755f9cfab6cce7e8073002757f7db2f0711`
and matches both allocated `/usr/lib/selinux.so.3` and the immutable staged
input byte for byte.

## Conclusion

The allocated filesystem shows active system-wide LD_PRELOAD persistence and
the hidden-file probe. Automated recovery did not restore the deleted staging
object: ext4magic returned a valid zero result and extundelete failed. Direct
journal examination nevertheless reconstructed the historical chain
`/tmp/rk.so` → inode 74163 → UID 1000 → size 32,784 → unallocated extent
1015822–1015830. The recovered content matches the root-owned library installed
under the system-looking name `selinux.so.3`.

The recovery is therefore educationally useful as provenance reconstruction,
not merely as duplication of bytes already present elsewhere. Its limitation
is equally important: the low-level offsets and journal blocks are findings
specific to this acquisition and must be rediscovered for another run.
