---
cwd: ../../../..
shell: bash
---

# Father cleanup disk recovery probe — Runme notebook

__Run:__ ubuntu-22.04_userland_father_ldpreload_cleanup_20260813-105240

**Status:** provisional. This short notebook reproduces the principal deleted-
file finding while the runner persistence barrier is still being tested. It is
not the final disk investigation.

The acquired EWF image is read-only. All output is written beneath the matching
case-specific shared/investigations directory. The journal block addresses
below are findings from this acquisition and must not be reused for another run.

## D-00 - Prepare the case-specific root image

debugfs and extundelete need a raw ext4 filesystem image. TSK commands can read
the EWF evidence directly. The root partition geometry was verified with mmls:
start sector 227328, length 20744159, sector size 512 bytes.

```bash {"name":"D-00-Prepare-Root-Image","promptEnv":"never"}
set -euo pipefail

RUN_ID='ubuntu-22.04_userland_father_ldpreload_cleanup_20260813-105240'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
PROBE_ID="recovery-probe-$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$INV_DIR/derived/disk/$PROBE_ID"

DISK_IMAGE="$RUN_DIR/dumps/disk/evidence_disk.E01"
INPUT_LIBRARY="$RUN_DIR/inputs/userland_father_ldpreload_cleanup/rk.so"
ROOT_IMAGE="$INV_DIR/derived/disk/root-partition.ext4"

ROOT_START_SECTOR=227328
ROOT_SECTOR_COUNT=20744159
SECTOR_SIZE_BYTES=512
ROOT_OFFSET_BYTES=$((ROOT_START_SECTOR * SECTOR_SIZE_BYTES))
ROOT_LENGTH_BYTES=$((ROOT_SECTOR_COUNT * SECTOR_SIZE_BYTES))

mkdir -p "$OUT_DIR"

if [[ ! -e "$ROOT_IMAGE" ]]; then
  img_cat -i ewf "$DISK_IMAGE" |
    dd of="$ROOT_IMAGE" bs=1M iflag=fullblock,skip_bytes,count_bytes \
      skip="$ROOT_OFFSET_BYTES" count="$ROOT_LENGTH_BYTES" status=progress
  chmod a-w "$ROOT_IMAGE"
fi

ROOT_IMAGE="$(realpath "$ROOT_IMAGE")"

export OUT_DIR="$OUT_DIR"
export DISK_IMAGE="$DISK_IMAGE"
export INPUT_LIBRARY="$INPUT_LIBRARY"
export ROOT_IMAGE="$ROOT_IMAGE"
export ROOT_START_SECTOR="$ROOT_START_SECTOR"

printf 'disk=%s\nroot_image=%s\ninput_library=%s\n' \
  "$DISK_IMAGE" "$ROOT_IMAGE" "$INPUT_LIBRARY"
```

**Output**

The 10,621,009,408-byte root partition was exported beneath the current run's
derived investigation directory and made read-only. The EWF evidence was not
modified. iflag=fullblock is required because dd reads from a pipe.

## D-01 - Recover the historical /tmp directory entry

Filesystem block 16758 is /tmp's directory block. debugfs logdump -O shows its
historical journal copies. Journal block 710 contains the deleted rk.so
directory entry.

```bash {"name":"D-01-Recover-Historical-Directory-Entry","promptEnv":"never"}
set -euo pipefail

TMP_DIRECTORY_BLOCK=16758
DIRECTORY_JOURNAL_BLOCK=710
DIRECTORY_LOG="$OUT_DIR/tmp-directory-journal.txt"
DIRECTORY_COPY="$OUT_DIR/tmp-directory-journal-block-710.bin"

debugfs -R "logdump -O -b $TMP_DIRECTORY_BLOCK" "$ROOT_IMAGE" \
  >"$DIRECTORY_LOG" 2>&1

jcat -i ewf -o "$ROOT_START_SECTOR" \
  "$DISK_IMAGE" "$DIRECTORY_JOURNAL_BLOCK" >"$DIRECTORY_COPY"

RK_NAME_OFFSET="$(grep -aob -m1 'rk.so' "$DIRECTORY_COPY" | cut -d: -f1)"
RK_DIRENT_OFFSET=$((RK_NAME_OFFSET - 8))
DELETED_INODE="$(
  dd if="$DIRECTORY_COPY" bs=1 skip="$RK_DIRENT_OFFSET" count=4 status=none |
    od -An -tu4 --endian=little
)"
DELETED_INODE=$((DELETED_INODE))
export DELETED_INODE="$DELETED_INODE"

printf 'name_offset=%s\ndirent_offset=%s\ndeleted_inode=%s\n' \
  "$RK_NAME_OFFSET" "$RK_DIRENT_OFFSET" "$DELETED_INODE"
xxd -g 1 -s "$RK_DIRENT_OFFSET" -l 16 "$DIRECTORY_COPY"
```

**Output**

Observed: the historical directory entry names rk.so and points to inode 74163.
The eight bytes before the name are the little-endian
inode, record length, name length, and file type fields of an ext4 directory
entry.

## D-02 - Recover the historical inode

Filesystem block 4924 is the inode-table block containing inode 74163. Journal
block 702 preserves its pre-deletion version. The inode begins 512 bytes into
that block. Only the fields needed for recovery are decoded.

```bash {"name":"D-02-Recover-Historical-Inode","promptEnv":"never"}
set -euo pipefail

INODE_TABLE_BLOCK=4924
INODE_JOURNAL_BLOCK=702
INODE_OFFSET=512
INODE_LOG="$OUT_DIR/inode-table-journal.txt"
INODE_COPY="$OUT_DIR/inode-table-journal-block-702.bin"

debugfs -R "logdump -O -b $INODE_TABLE_BLOCK" "$ROOT_IMAGE" \
  >"$INODE_LOG" 2>&1

jcat -i ewf -o "$ROOT_START_SECTOR" \
  "$DISK_IMAGE" "$INODE_JOURNAL_BLOCK" >"$INODE_COPY"

FILE_UID="$(
  dd if="$INODE_COPY" bs=1 skip=$((INODE_OFFSET + 2)) count=2 status=none |
    od -An -tu2 --endian=little
)"
FILE_SIZE="$(
  dd if="$INODE_COPY" bs=1 skip=$((INODE_OFFSET + 4)) count=4 status=none |
    od -An -tu4 --endian=little
)"
EXTENT_LENGTH="$(
  dd if="$INODE_COPY" bs=1 skip=$((INODE_OFFSET + 56)) count=2 status=none |
    od -An -tu2 --endian=little
)"
DATA_BLOCK_HIGH="$(
  dd if="$INODE_COPY" bs=1 skip=$((INODE_OFFSET + 58)) count=2 status=none |
    od -An -tu2 --endian=little
)"
DATA_BLOCK_LOW="$(
  dd if="$INODE_COPY" bs=1 skip=$((INODE_OFFSET + 60)) count=4 status=none |
    od -An -tu4 --endian=little
)"
FILE_UID=$((FILE_UID))
FILE_SIZE=$((FILE_SIZE))
EXTENT_LENGTH=$((EXTENT_LENGTH))
DATA_BLOCK_HIGH=$((DATA_BLOCK_HIGH))
DATA_BLOCK_LOW=$((DATA_BLOCK_LOW))
DATA_BLOCK=$((DATA_BLOCK_LOW + (DATA_BLOCK_HIGH << 32)))

export FILE_SIZE="$FILE_SIZE"
export EXTENT_LENGTH="$EXTENT_LENGTH"
export DATA_BLOCK="$DATA_BLOCK"

printf 'inode=%s\nuid=%s\nsize=%s\ndata_block=%s\nextent_length=%s\n' \
  "$DELETED_INODE" "$FILE_UID" "$FILE_SIZE" \
  "$DATA_BLOCK" "$EXTENT_LENGTH"
xxd -g 1 -s "$INODE_OFFSET" -l 128 "$INODE_COPY"
```

**Output**

Observed: inode 74163, UID 1000, size 32784, and one
nine-block extent beginning at filesystem block 1015820.

## D-03 - Recover and verify the file content

The journal supplies identity, size, and block mapping. The file content itself
comes from the now-unallocated filesystem blocks. blkstat records their
allocation state before blkcat reads the extent.

```bash {"name":"D-03-Recover-and-Verify-Content","promptEnv":"never"}
set -euo pipefail

BLOCK_STATUS="$OUT_DIR/data-block-status.txt"
EXTENT_COPY="$OUT_DIR/rk-so-extent.bin"
RECOVERED_LIBRARY="$OUT_DIR/rk.so.recovered"

blkstat -i ewf -o "$ROOT_START_SECTOR" \
  "$DISK_IMAGE" "$DATA_BLOCK" | tee "$BLOCK_STATUS"

blkcat -i ewf -o "$ROOT_START_SECTOR" \
  "$DISK_IMAGE" "$DATA_BLOCK" "$EXTENT_LENGTH" >"$EXTENT_COPY"
head -c "$FILE_SIZE" "$EXTENT_COPY" >"$RECOVERED_LIBRARY"
chmod a-w "$EXTENT_COPY" "$RECOVERED_LIBRARY"

sha256sum "$RECOVERED_LIBRARY" "$INPUT_LIBRARY"

if cmp -s "$RECOVERED_LIBRARY" "$INPUT_LIBRARY"; then
  printf 'verification=exact byte-for-byte match\n'
else
  printf 'verification=FAILED\n' >&2
  exit 1
fi
```

**Output**

Observed SHA-256 for both files:
87fece49fc15a48372a1ba76cf424755f9cfab6cce7e8073002757f7db2f0711.
This is journal-assisted recovery: historical metadata came from the journal,
whereas the verified content came from unallocated blocks.

## D-04 - Try extundelete as an independent comparison

This is one bounded attempt against the derived, unmounted root image. A zero
result or tool failure does not invalidate D-01 through D-03.

```bash {"name":"D-04-Extundelete-Comparison","promptEnv":"never"}
set -euo pipefail

EXTUNDELETE_DIR="$OUT_DIR/extundelete"
EXTUNDELETE_LOG="$OUT_DIR/extundelete.txt"
EXTUNDELETE_FILE="$EXTUNDELETE_DIR/RECOVERED_FILES/tmp/rk.so"

if [[ -e "$EXTUNDELETE_DIR/RECOVERED_FILES" ]]; then
  printf 'error: extundelete output already exists: %s\n' \
    "$EXTUNDELETE_DIR/RECOVERED_FILES" >&2
  exit 1
fi

mkdir -p "$EXTUNDELETE_DIR"

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

if [[ -f "$EXTUNDELETE_FILE" ]]; then
  sha256sum "$EXTUNDELETE_FILE" "$INPUT_LIBRARY"
  if cmp -s "$EXTUNDELETE_FILE" "$INPUT_LIBRARY"; then
    printf 'extundelete_verification=exact byte-for-byte match\n'
  else
    printf 'extundelete_verification=FAILED\n' >&2
    exit 1
  fi
else
  printf 'extundelete_verification=not recovered\n'
fi
```

**Output**

extundelete 0.2.4 loaded 80 filesystem groups and 5,467 journal descriptors,
then exited 1: it could not associate tmp/rk.so with the correct inode and
recovered no file. This tool failure does not weaken the independently verified
journal/TSK recovery.
