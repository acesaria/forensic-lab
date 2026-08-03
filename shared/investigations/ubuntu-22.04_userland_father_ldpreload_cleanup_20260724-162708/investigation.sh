#!/usr/bin/env bash

# Case-specific record for setup and allocated-filesystem examination.
# recovery.sh covers deleted-entry and unallocated-space recovery.

set -euo pipefail

RUN_ID='ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
RAW_INDEX="$INV_DIR/raw_extraction_index.json"

DISK_IMAGE="$RUN_DIR/$(jq -er '.inputs.disk_image' "$RAW_INDEX")"
BODYFILE="$RUN_DIR/$(jq -er '.extractors.tsk.output.path' "$RAW_INDEX")"

ROOT_START_SECTOR="$(
  jq -er '.extractors.tsk.filesystem.partition.start_sector' "$RAW_INDEX"
)"
ROOT_SECTOR_COUNT="$(
  jq -er '.extractors.tsk.filesystem.partition.sector_count' "$RAW_INDEX"
)"
TSK_SECTOR_SIZE_BYTES="$(
  jq -er '.extractors.tsk.filesystem.partition.sector_size_bytes' "$RAW_INDEX"
)"
FS_BLOCK_SIZE_BYTES="$(
  jq -er '.extractors.tsk.filesystem.block_size_bytes' "$RAW_INDEX"
)"

printf \
  'run=%s\ndisk=%s\nbodyfile=%s\nroot_start=%s sectors\nroot_size=%s sectors\nsector_size=%s bytes\nfs_block_size=%s bytes\n' \
  "$RUN_ID" "$DISK_IMAGE" "$BODYFILE" \
  "$ROOT_START_SECTOR" "$ROOT_SECTOR_COUNT" \
  "$TSK_SECTOR_SIZE_BYTES" "$FS_BLOCK_SIZE_BYTES"

MANIFEST="$RUN_DIR/manifest.json"
ACQUISITION="$RUN_DIR/$(jq -er '.inputs.acquisition_manifest' "$RAW_INDEX")"

GUEST_TIMEZONE="$(jq -er '.platform.timezone' "$MANIFEST")"
SCENARIO_START_UTC="$(jq -er '.timestamps.scenario_started_at' "$MANIFEST")"
SCENARIO_END_UTC="$(jq -er '.timestamps.scenario_ended_at' "$MANIFEST")" 

printf \
  'manifest=%s\nacquisition=%s\nguest_timezone=%s\nstart_ts=%s\nend_ts=%s\n' \
  "$MANIFEST" "$ACQUISITION" "$GUEST_TIMEZONE" \
  "$SCENARIO_START_UTC" "$SCENARIO_END_UTC"


printf '\n[D-01.1] Resolve the path and inspect its inode \n'

# D-01.1: resolve the known pathname with the filesystem-aware TSK tool and inspect its inode
PRELOAD_INODE="$(
  ifind -i ewf -o "$ROOT_START_SECTOR" \
    -n /etc/ld.so.preload "$DISK_IMAGE"
)"

# Print the captured result before using it in the next examination step.
printf 'preload_inode=%s\n' "$PRELOAD_INODE"

# D-01.2: examine the metadata address returned by ifind.
istat -i ewf -o "$ROOT_START_SECTOR" \
  -z "$GUEST_TIMEZONE" \
  "$DISK_IMAGE" "$PRELOAD_INODE"

# D-01.2: read the preload configuration.
printf '\n[D-01.2] Preload configuration content\n'

PRELOAD_PATH="$(
  icat -i ewf -o "$ROOT_START_SECTOR" \
    "$DISK_IMAGE" "$PRELOAD_INODE"
)"

printf 'preload_path=%s\n' "$PRELOAD_PATH"

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

printf 'resolved_path=%s\nlibrary_inode=%s\n' \
  "$PRELOAD_LIBRARY" "$LIBRARY_INODE"

istat -i ewf -o "$ROOT_START_SECTOR" \
  -z "$GUEST_TIMEZONE" \
  "$DISK_IMAGE" "$LIBRARY_INODE"

# D-01.4: recover and identify the allocated shared object.
printf '\n[D-01.4] Recovered library identification\n'

D01_DIR="$INV_DIR/derived/d-01"
LIBRARY_COPY="$D01_DIR/usr-lib-selinux.so.3"

mkdir -p "$D01_DIR"

icat -i ewf -o "$ROOT_START_SECTOR" \
  "$DISK_IMAGE" "$LIBRARY_INODE" \
  > "$LIBRARY_COPY"

sha256sum "$LIBRARY_COPY"
file -b "$LIBRARY_COPY"
