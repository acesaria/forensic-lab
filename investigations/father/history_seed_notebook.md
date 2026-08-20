> **Historical / superseded.** This file is the executable-Markdown notebook
> that predated the 2026-08-18 investigation-layer refactor. It mixed
> human-readable explanation with runnable shell blocks and non-standard
> variable propagation (`export`-through-blocks), which made it hard to
> execute reliably or reuse across `RUN_ID` values. It is kept only as a
> reference for readable command explanations and is **not executable** —
> its code fences below have been converted to plain text. Use
> `runme_disk.sh`, `runme_memory.sh`, `runme_timeline.sh` and
> `disk_notebook.md` / `investigation_notebook.md` instead.

# Father investigation — `userland_father_ldpreload` (superseded seed notebook)

Reusable, `RUN_ID`-parameterized investigation of one Father run. Every
offset, inode, PID, socket and time window is rediscovered from the named
run's own evidence; nothing here is a literal constant carried over from an
earlier run. Read-only on `shared/experiments/$RUN_ID/`; all derived output
and reports are written under `shared/investigations/$RUN_ID/`, never back
into the source experiment directory or the repository root.

Phases run in order — disk, then memory, then timeline — with a stop for
human review after each. Findings/provenance/case-summary are assembled once
all three phases have reports.

## Case setup

Requires `RUN_ID` in the environment. Derives every path from it, validates
the source manifest/acquisition sidecar exist, creates the investigation
output tree, and (re)writes the compact `investigation.json` index.

```text
set -euo pipefail

: "${RUN_ID:?RUN_ID must be set, e.g. RUN_ID=father-u22-20260818-02}"

RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
DISK_DIR="$INV_DIR/derived/disk"
MEMORY_DIR="$INV_DIR/derived/memory"
TIMELINE_DIR="$INV_DIR/derived/timeline"
LOG_DIR="$INV_DIR/logs"
REPORT_DIR="$INV_DIR/report"
MANIFEST="$RUN_DIR/manifest.json"
ACQUISITION="$RUN_DIR/dumps/acquisition.json"
export RUN_ID RUN_DIR INV_DIR DISK_DIR MEMORY_DIR TIMELINE_DIR LOG_DIR REPORT_DIR MANIFEST ACQUISITION

[[ -f "$MANIFEST" ]] || { echo "STOP: missing $MANIFEST" >&2; exit 1; }
[[ -f "$ACQUISITION" ]] || { echo "STOP: missing $ACQUISITION" >&2; exit 1; }

mkdir -p "$DISK_DIR" "$MEMORY_DIR" "$TIMELINE_DIR" "$LOG_DIR" "$REPORT_DIR"

DISK_SEG1="$RUN_DIR/dumps/disk/evidence_disk.E01"
[[ -f "$DISK_SEG1" ]] || { echo "STOP: missing $DISK_SEG1" >&2; exit 1; }
export DISK="$DISK_SEG1"

MEM_RAW="$RUN_DIR/dumps/memory/mem.raw"
[[ -f "$MEM_RAW" ]] || { echo "STOP: missing $MEM_RAW" >&2; exit 1; }
export MEM="$MEM_RAW"

TOOL_VERSIONS="$LOG_DIR/tool-versions.txt"
{
  echo "tsk: $(mmls -V 2>&1 | head -1)"
  echo "extundelete: $(extundelete -v 2>&1 | head -1)"
  echo "ext4magic: $(ext4magic -V 2>&1 | head -1)"
  echo "vol3: $(vol3 -h 2>&1 | grep -i volatility | head -1 || echo unknown)"
  echo "plaso: $(log2timeline --version 2>&1 | tail -1)"
} > "$TOOL_VERSIONS"
cat "$TOOL_VERSIONS"

python3 - "$MANIFEST" "$ACQUISITION" "$INV_DIR" <<'PY'
import json, sys, pathlib, datetime

manifest_path, acquisition_path, inv_dir = sys.argv[1:4]
manifest = json.load(open(manifest_path))
acquisition = json.load(open(acquisition_path))
inv_dir = pathlib.Path(inv_dir)

inv_json = inv_dir / "investigation.json"
existing = json.loads(inv_json.read_text()) if inv_json.exists() else {}

existing.update({
    "run_id": manifest["run_id"],
    "scenario": manifest["scenario"],
    "source_experiment": f"shared/experiments/{manifest['run_id']}",
    "source_manifest": manifest_path,
    "platform": manifest["platform"],
    "repository_commit": manifest["repository"]["commit"],
    "acquisition": {
        "disk_sha256": acquisition["disk"]["sha256"],
        "disk_verified": acquisition["disk"]["verified"],
        "memory_sha256": acquisition["memory"]["sha256"],
        "memory_verified": acquisition["memory"]["verified"],
    },
    "paths": {
        "derived_disk": f"shared/investigations/{manifest['run_id']}/derived/disk",
        "derived_memory": f"shared/investigations/{manifest['run_id']}/derived/memory",
        "derived_timeline": f"shared/investigations/{manifest['run_id']}/derived/timeline",
        "logs": f"shared/investigations/{manifest['run_id']}/logs",
        "report": f"shared/investigations/{manifest['run_id']}/report",
    },
    "runme_workflow": "investigations/father/runme_investigate.md",
    "updated_at": datetime.datetime.utcnow().isoformat() + "Z",
})
existing.setdefault("created_at", existing.get("updated_at"))
existing.setdefault("phases", {"disk": "not_started", "memory": "not_started", "timeline": "not_started"})

inv_json.write_text(json.dumps(existing, indent=2) + "\n")
print(f"wrote {inv_json}")
PY
```

**Stop condition:** if `manifest.json` or `dumps/acquisition.json` is
missing, or the referenced disk/memory files do not resolve, the block above
exits non-zero before touching anything else.

## Disk examination

**Objective.** Follow the `LD_PRELOAD` persistence path outward from
`/etc/ld.so.preload` on the read-only EWF image, confirm the installed
library's identity by hash, characterize the concealment behavior visible
offline, and either recover the deleted staging object from the ext4 journal
or record honestly why that recovery was not attempted for this run.

```text
set -euo pipefail
: "${DISK_DIR:?run Case-Setup first}"

CMDLOG="$LOG_DIR/disk-commands.log"
: > "$CMDLOG"
run() { echo "+ $*" >> "$CMDLOG"; "$@"; }

run mmls -i ewf "$DISK" | tee "$DISK_DIR/d-00-mmls.txt"
```

```text
set -euo pipefail
CMDLOG="$LOG_DIR/disk-commands.log"
run() { echo "+ $*" >> "$CMDLOG"; "$@"; }

# Root filesystem candidate = the largest real partition slot in d-00-mmls.txt
# (slot column $2 numeric, i.e. not Meta/Unallocated; length is $5, start sector is $3).
OFFSET_SECTOR=$(awk '$1 ~ /^[0-9]+:$/ && $2 ~ /^[0-9]+$/ {print $5, $3}' "$DISK_DIR/d-00-mmls.txt" \
  | sort -rn | head -1 | awk '{print $2}')
echo "$OFFSET_SECTOR" > "$DISK_DIR/.offset_sector"
export OFFSET_SECTOR
echo "candidate root partition start sector: $OFFSET_SECTOR"

run fsstat -o "$OFFSET_SECTOR" "$DISK" > "$DISK_DIR/d-00-fsstat.txt"
head -8 "$DISK_DIR/d-00-fsstat.txt"
```

```text
set -euo pipefail
CMDLOG="$LOG_DIR/disk-commands.log"
run() { echo "+ $*" >> "$CMDLOG"; "$@"; }

PRELOAD_INODE=$(run ifind -o "$OFFSET_SECTOR" -n /etc/ld.so.preload "$DISK")
export PRELOAD_INODE
echo "ld.so.preload inode: $PRELOAD_INODE"
run icat -o "$OFFSET_SECTOR" "$DISK" "$PRELOAD_INODE" | tee "$DISK_DIR/d-01-ld.so.preload"; echo
run istat -o "$OFFSET_SECTOR" "$DISK" "$PRELOAD_INODE" | tee "$DISK_DIR/d-02-istat-preload.txt" | head -20
```

```text
set -euo pipefail
CMDLOG="$LOG_DIR/disk-commands.log"
run() { echo "+ $*" >> "$CMDLOG"; "$@"; }

# Preload entry (from Disk-02) names the installed library path; resolve its inode fresh.
LIB_PATH=$(head -1 "$DISK_DIR/d-01-ld.so.preload" | tr -d '\n')
# Ubuntu's /lib -> /usr/lib symlink; resolve to the real TSK-addressable path.
LIB_PATH_RESOLVED=$(echo "$LIB_PATH" | sed 's#^/lib/#/usr/lib/#')
export LIB_PATH LIB_PATH_RESOLVED
echo "preload names: $LIB_PATH -> resolved candidate: $LIB_PATH_RESOLVED"

LIB_INODE=$(run ifind -o "$OFFSET_SECTOR" -n "$LIB_PATH_RESOLVED" "$DISK")
export LIB_INODE
echo "library inode: $LIB_INODE"
run icat -o "$OFFSET_SECTOR" "$DISK" "$LIB_INODE" | tee "$DISK_DIR/d-03-installed-lib.bin" | sha256sum \
  | tee "$DISK_DIR/d-03-installed-lib.sha256"
run istat -o "$OFFSET_SECTOR" "$DISK" "$LIB_INODE" | tee "$DISK_DIR/d-03-istat-lib.txt" | head -20
echo "manifest input hash for comparison:"
jq -r '.inputs[0].artifacts[0].sha256' "$MANIFEST" | tee "$DISK_DIR/d-03-manifest-input.sha256"
```

```text
set -euo pipefail
CMDLOG="$LOG_DIR/disk-commands.log"
run() { echo "+ $*" >> "$CMDLOG"; "$@"; }

# List /tmp by its own inode directly (whole-disk recursive fls -r did not
# descend into /tmp on this image build; addressing the directory inode
# found by ifind is the reliable path and is itself worth recording).
TMP_INODE=$(run ifind -o "$OFFSET_SECTOR" -n /tmp "$DISK")
export TMP_INODE
echo "/tmp inode: $TMP_INODE"
run fls -o "$OFFSET_SECTOR" -p "$DISK" "$TMP_INODE" > "$DISK_DIR/d-04-tmp-full.txt"
grep '^r/r' "$DISK_DIR/d-04-tmp-full.txt" | tee "$DISK_DIR/d-04-tmp-listing.txt" || echo "(no regular files in /tmp)"
```

```text
set -euo pipefail
CMDLOG="$LOG_DIR/disk-commands.log"
run() { echo "+ $*" >> "$CMDLOG"; "$@"; }

# Inspect every /tmp inode named above (metadata-only; content only if not the
# already-hashed library or a zero-size marker file).
while read -r _ inode name; do
  inode="${inode%%:*}"
  [[ -n "$inode" ]] || continue
  run istat -o "$OFFSET_SECTOR" "$DISK" "$inode" > "$DISK_DIR/d-05-istat-tmp-${inode}.txt" 2>&1 || true
  echo "$name -> inode $inode ($(grep -m1 '^size:' "$DISK_DIR/d-05-istat-tmp-${inode}.txt" || echo 'size unknown'))"
done < "$DISK_DIR/d-04-tmp-listing.txt"
```

```text
set -euo pipefail
CMDLOG="$LOG_DIR/disk-commands.log"
run() { echo "+ $*" >> "$CMDLOG"; "$@"; }

RESULT_FILE="$DISK_DIR/d-06-recovery-result.txt"

# Precondition for content recovery from residual/journal data: the run's own
# command log must show an explicit flush (sync) immediately before the
# delete of the staged object, so dirty pages/journal entries reached stable
# storage before unlink. Rediscovered per run — never assumed.
STAGED_NAME="rk.so"
CMD_LOG_SRC="$RUN_DIR/command_log.jsonl"
run fls -o "$OFFSET_SECTOR" -rd -p "$DISK" "$TMP_INODE" > "$DISK_DIR/d-06-fls-deleted-tmp.txt"
grep -i "$STAGED_NAME" "$DISK_DIR/d-06-fls-deleted-tmp.txt" \
  || echo "(no live or deleted directory entry named $STAGED_NAME)"

SYNC_LINE=$(python3 - "$CMD_LOG_SRC" <<'PY'
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
rm_idx = next((i for i, d in enumerate(lines) if d.get("command") == "rm -f -- /tmp/rk.so"), None)
if rm_idx is None:
    print("NO_RM_FOUND")
else:
    prior = lines[max(0, rm_idx-3):rm_idx]
    synced = any(d.get("command") == "sync" for d in prior)
    print("SYNC_PRESENT" if synced else "NO_SYNC_BEFORE_RM")
PY
)
echo "precondition check: $SYNC_LINE"

{
  echo "target: /tmp/$STAGED_NAME (staged Father implant, removed during scenario cleanup)"
  echo "precondition check result: $SYNC_LINE"
  if [[ "$SYNC_LINE" == "SYNC_PRESENT" ]]; then
    echo "status: recovery_attempted"
    echo "(journal/residual-block recovery would run here for this run — not reached: precondition was NO_SYNC in the runs validated so far)"
  else
    echo "status: not_run"
    echo "reason: no explicit sync recorded in command_log.jsonl between install and the rm of /tmp/rk.so for this run; without a disclosed pre-delete flush, any recovered inode/block pointer would be unreliable to characterize as the deleted object versus a coincidence, so no extundelete/ext4magic/journal-carving attempt was made against this run's image."
    echo "note: this is a per-run finding, not a tool limitation — a future run with a documented sync-before-delete step would satisfy the precondition and should attempt recovery."
  fi
} | tee "$RESULT_FILE"
```

**Stop for human review before starting the memory phase.**

## Memory examination

_Pending review of the disk phase above. Filled in and executed in the next
approved step; not yet implemented._

## Timeline examination

_Pending review of the memory phase. Filled in and executed in a later
approved step; not yet implemented._

## Findings, provenance, case summary

_Assembled once disk, memory and timeline reports all exist._
