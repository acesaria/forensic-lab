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
GROUND_TRUTH_DIR="$OUT_DIR/ground-truth"
ROOT_IMAGE="$OUT_DIR/root-partition.ext4"
UNALLOCATED="$UNALLOC_DIR/unallocated.blkls"
EXPECTED_CONFIG="$GROUND_TRUTH_DIR/expected-modified-config.h"
RECOVERED_CONFIG="$UNALLOC_DIR/recovered-config.h"
CONFIG_PATTERN='#define STRING "__malicious_"'

mkdir -p \
  "$ENTRY_DIR" "$EXT4_DIR" "$UNALLOC_DIR" "$PHOTOREC_DIR" "$GROUND_TRUTH_DIR"

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

printf '\n[R-02] Bounded recursive journal-assisted recovery\n'

ewfexport -q -u -f raw -o 116391936 -B 4178558464 -t - \
  "$DISK_IMAGE" >"$ROOT_IMAGE"
chmod a-w "$ROOT_IMAGE"
sha256sum "$ROOT_IMAGE" | tee "$ROOT_IMAGE.sha256"
stat -c 'root derivative: %n %s bytes' "$ROOT_IMAGE"

RECOVER_DIR="$EXT4_DIR/recovered-R"
INVENTORY="$EXT4_DIR/recovered-R-inventory.txt"
TARGET_RESULTS="$EXT4_DIR/disclosed-target-results.txt"

mkdir -p "$RECOVER_DIR"

ext4magic "$ROOT_IMAGE" \
  -a 1784903168 -b 1784903290 \
  -R -d "$RECOVER_DIR" \
  2>&1 | tee "$EXT4_DIR/ext4magic-R.txt"

find "$RECOVER_DIR" -mindepth 1 \
  -printf '%y %s bytes %p\n' | sort | tee "$INVENTORY"

if [[ ! -s "$INVENTORY" ]]; then
  printf 'ext4magic completed successfully with zero recovered entries.\n'
else
  printf 'ext4magic completed successfully; recovered_entries=%s\n' \
    "$(wc -l <"$INVENTORY")"
fi

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

printf '\n[R-03] Recover the selected config.h from unallocated blocks\n'

printf '\n[R-03.1] Prepare the disclosed validation reference\n'

tar -xOf \
  scenarios/userland_father_ldpreload/files/father-upstream-4eb2712.tar \
  Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332/src/config.h |
  sed "s|^#define STRING .*|$CONFIG_PATTERN|" \
    >"$EXPECTED_CONFIG"

EXPECTED_CONFIG_SIZE="$(stat -c %s "$EXPECTED_CONFIG")"
REFERENCE_PATTERN_OFFSET="$(
  LC_ALL=C grep -aobF -- "$CONFIG_PATTERN" "$EXPECTED_CONFIG" |
    cut -d: -f1
)"
printf 'reference=%s\nsize=%s bytes\nmarker_offset=%s\n' \
  "$EXPECTED_CONFIG" "$EXPECTED_CONFIG_SIZE" "$REFERENCE_PATTERN_OFFSET"

printf '\n[R-03.2] Search the blkls unallocated-block stream\n'

blkls -i ewf -o "$OFFSET" "$DISK_IMAGE" \
  >"$UNALLOCATED" 2>"$UNALLOC_DIR/blkls.stderr"
sha256sum "$UNALLOCATED" >"$UNALLOCATED.sha256"
stat -c 'unallocated blocks: %n %s bytes' "$UNALLOCATED"

LC_ALL=C grep -aobF -- "$CONFIG_PATTERN" "$UNALLOCATED" \
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
printf 'marker_offset_in_blkls=%s\n' "$HIT_OFFSET"

printf '\n[R-03.3] Map the hit to the original ext4 block\n'

PACKED_BLOCK=$((HIT_OFFSET / BLOCK_SIZE))
HIT_OFFSET_IN_BLOCK=$((HIT_OFFSET % BLOCK_SIZE))
FILESYSTEM_BLOCK="$(
  blkcalc -i ewf -o "$OFFSET" -u "$PACKED_BLOCK" "$DISK_IMAGE"
)"
CONFIG_START_IN_BLOCK=$((HIT_OFFSET_IN_BLOCK - REFERENCE_PATTERN_OFFSET))
printf \
  'blkls_byte_offset=%s\nblkls_block=%s\nfilesystem_block=%s\nmarker_offset_in_block=%s\nmarker_offset_in_reference=%s\nextraction_start_in_block=%s - %s = %s\n' \
  "$HIT_OFFSET" "$PACKED_BLOCK" "$FILESYSTEM_BLOCK" \
  "$HIT_OFFSET_IN_BLOCK" "$REFERENCE_PATTERN_OFFSET" \
  "$HIT_OFFSET_IN_BLOCK" "$REFERENCE_PATTERN_OFFSET" "$CONFIG_START_IN_BLOCK" \
  | tee "$UNALLOC_DIR/config-block-map.txt"

printf '\n[R-03.4] Extract and validate the content\n'

BLOCK_FILE="$UNALLOC_DIR/config-source-block-$FILESYSTEM_BLOCK.bin"
blkcat -i ewf -o "$OFFSET" \
  "$DISK_IMAGE" "$FILESYSTEM_BLOCK" >"$BLOCK_FILE"

dd if="$BLOCK_FILE" of="$RECOVERED_CONFIG" \
  bs=1 skip="$CONFIG_START_IN_BLOCK" count="$EXPECTED_CONFIG_SIZE" status=none

stat -c '%n %s bytes' "$RECOVERED_CONFIG"
sha256sum "$RECOVERED_CONFIG" "$EXPECTED_CONFIG"
cmp "$RECOVERED_CONFIG" "$EXPECTED_CONFIG"
printf 'Recovered config matches the disclosed validation reference.\n'
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
