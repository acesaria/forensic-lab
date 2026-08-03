#!/usr/bin/env bash

set -euo pipefail

export LC_ALL=C

DISK_IMAGE='shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708/dumps/disk/evidence_disk.E01'
OFFSET=227328
BLOCK_SIZE=4096
TIMEZONE='Etc/UTC'
OUT_DIR='shared/investigations/ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708/derived/recovery-20260729T162342Z'
ENTRY_DIR="$OUT_DIR/deleted-entries"
EXT4_DIR="$OUT_DIR/ext4magic"
UNALLOC_DIR="$OUT_DIR/unallocated"
PHOTOREC_DIR="$OUT_DIR/photorec"
ROOT_IMAGE="$OUT_DIR/root-partition.ext4"
UNALLOCATED="$UNALLOC_DIR/unallocated.blkls"
EXPECTED_CONFIG="$OUT_DIR/ground-truth/expected-modified-config.h"
RECOVERED_CONFIG="$UNALLOC_DIR/recovered-config.h"

printf '[R-01] Deleted entries in the three relevant parent directories\n'

TMP_INODE="$(ifind -i ewf -o "$OFFSET" -n /tmp "$DISK_IMAGE")"
FATHER_PARENT_INODE="$(
  ifind -i ewf -o "$OFFSET" \
    -n /tmp/forensic-lab/father_ldpreload "$DISK_IMAGE"
)"
LABUSER_INODE="$(
  ifind -i ewf -o "$OFFSET" -n /home/labuser "$DISK_IMAGE"
)"

printf 'parent inodes: /tmp=%s father_parent=%s /home/labuser=%s\n' \
  "$TMP_INODE" "$FATHER_PARENT_INODE" "$LABUSER_INODE"

fls -i ewf -o "$OFFSET" -z "$TIMEZONE" -d -l \
  "$DISK_IMAGE" "$TMP_INODE" \
  | tee "$ENTRY_DIR/tmp-deleted.txt"

fls -i ewf -o "$OFFSET" -z "$TIMEZONE" -d -l \
  "$DISK_IMAGE" "$FATHER_PARENT_INODE" \
  | tee "$ENTRY_DIR/father-parent-deleted.txt"

fls -i ewf -o "$OFFSET" -z "$TIMEZONE" -d -l \
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

printf '\n[R-02] Journal-assisted recovery of four file targets\n'

ewfexport -q -u -f raw -o 116391936 -B 4178558464 -t - \
  "$DISK_IMAGE" >"$ROOT_IMAGE"
chmod a-w "$ROOT_IMAGE"
sha256sum "$ROOT_IMAGE" | tee "$ROOT_IMAGE.sha256"
stat -c 'root derivative: %n %s bytes' "$ROOT_IMAGE"

mkdir -p "$EXT4_DIR"

printf '%s\n' \
  '"tmp/father-upstream-4eb2712.tar"' \
  '"tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/src/config.h"' \
  '"tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/rk.so"' \
  '"home/labuser/.bash_history"' >"$EXT4_DIR/targets.txt"

RECOVER_DIR="$EXT4_DIR/recovered-R"
INVENTORY="$EXT4_DIR/recovered-R-inventory.txt"

sudo ext4magic "$ROOT_IMAGE" \
  -a 1784903168 -b 1784903290 \
  -i "$EXT4_DIR/targets.txt" \
  -R -d "$RECOVER_DIR" \
  2>&1 | tee "$EXT4_DIR/ext4magic-R.txt"

sudo find "$RECOVER_DIR" -mindepth 1 \
  -printf '%y %s bytes %p\n' | tee "$INVENTORY"

if [[ ! -s "$INVENTORY" ]]; then
  printf 'No artifact was recovered for the four bounded file targets.\n'
fi

printf '\n[R-03] Recover the selected config.h from unallocated blocks\n'

tar -xOf \
  scenarios/userland_father_ldpreload/files/father-upstream-4eb2712.tar \
  Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/src/config.h |
  sed 's|^#define STRING .*|#define STRING "__malicious_"|' \
    >"$EXPECTED_CONFIG"

blkls -i ewf -o "$OFFSET" "$DISK_IMAGE" \
  >"$UNALLOCATED" 2>"$UNALLOC_DIR/blkls.stderr"
sha256sum "$UNALLOCATED" >"$UNALLOCATED.sha256"
stat -c 'unallocated blocks: %n %s bytes' "$UNALLOCATED"

grep -aobF '#define STRING "__malicious_"' "$UNALLOCATED" \
  >"$UNALLOC_DIR/config-pattern-hits.txt"
sed -n '1p' "$UNALLOC_DIR/config-pattern-hits.txt"

HIT_OFFSET="$(
  cut -d: -f1 "$UNALLOC_DIR/config-pattern-hits.txt"
)"
PACKED_BLOCK=$((HIT_OFFSET / BLOCK_SIZE))
BLOCK_OFFSET=$((HIT_OFFSET % BLOCK_SIZE))
FILESYSTEM_BLOCK="$(
  blkcalc -i ewf -o "$OFFSET" -u "$PACKED_BLOCK" "$DISK_IMAGE"
)"
printf \
  'blkls_byte_offset=%s\nblkls_block=%s\nfilesystem_block=%s\nblock_byte_offset=%s\n' \
  "$HIT_OFFSET" "$PACKED_BLOCK" "$FILESYSTEM_BLOCK" "$BLOCK_OFFSET" \
  >"$UNALLOC_DIR/config-block-map.txt"

BLOCK_FILE="$UNALLOC_DIR/config-source-block-$FILESYSTEM_BLOCK.bin"
blkcat -i ewf -o "$OFFSET" \
  "$DISK_IMAGE" "$FILESYSTEM_BLOCK" >"$BLOCK_FILE"

PATTERN_OFFSET="$(
  grep -aboF -m 1 '#define STRING "__malicious_"' "$EXPECTED_CONFIG" |
    cut -d: -f1
)"
CONFIG_START=$((BLOCK_OFFSET - PATTERN_OFFSET))
dd if="$BLOCK_FILE" of="$RECOVERED_CONFIG" \
  bs=1 skip="$CONFIG_START" count=740 status=none

stat -c '%n %s bytes' "$RECOVERED_CONFIG"
sha256sum "$RECOVERED_CONFIG" "$EXPECTED_CONFIG"
cmp "$RECOVERED_CONFIG" "$EXPECTED_CONFIG"
file "$RECOVERED_CONFIG"
sha256sum "$RECOVERED_CONFIG" "$BLOCK_FILE" \
  >"$UNALLOC_DIR/recovered-config.sha256"

printf '\n[R-04] TAR-only PhotoRec attempt\n'

photorec \
  /log /logname "$PHOTOREC_DIR/photorec.log" \
  /d "$PHOTOREC_DIR/carved" \
  /cmd "$ROOT_IMAGE" \
  partition_none,options,mode_ext2,fileopt,everything,disable,tar,enable,freespace,search
sed -n '/Pass 0/,/PhotoRec exited normally/p' \
  "$PHOTOREC_DIR/photorec.log"
printf 'PhotoRec returned zero files, so no TAR validation followed.\n'

printf '\nRecovery record complete: %s\n' "$OUT_DIR"
