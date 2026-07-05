"""Sleuth Kit bodyfile adapter.

Input is the raw `fls -m /` bodyfile already produced by the repo's TSK
extractor. No ground truth is read; every row is converted as a filesystem
artifact observation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from orchestrator.adapters.common import iso_from_epoch, make_tool_finding
from orchestrator.canonical import EvidenceSource, ToolFinding

_SERVICE_DIRS = (
    "/etc/systemd/",
    "/usr/lib/systemd/",
    "/lib/systemd/",
)
_SERVICE_SUFFIXES = (".service", ".timer", ".socket", ".path", ".mount")
_HISTORY_NAMES = (
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    ".python_history",
)


# bodyfile columns: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
# fls -m appends "(deleted)" / "(deleted-realloc)" to the name of unallocated
# entries, which is how a deleted inode is recognised here.
def parse_bodyfile(lines: Iterable[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in lines:
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 11:
            continue
        name = parts[1]
        deleted = "(deleted" in name
        clean = name.split(" (deleted")[0]
        if not clean.startswith("/"):
            clean = "/" + clean
        rows.append(
            {
                "path": clean,
                "inode": parts[2],
                "mode": parts[3],
                "size": _to_int(parts[6]),
                "atime": _to_float(parts[7]),
                "mtime": _to_float(parts[8]),
                "ctime": _to_float(parts[9]),
                "crtime": _to_float(parts[10]),
                "deleted": deleted,
                "reallocated": "(deleted-realloc)" in name,
            }
        )
    return rows


def _to_int(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return 0


def _to_float(s: str) -> float | None:
    try:
        return float(s)
    except ValueError:
        return None


_TIME_KINDS = ("atime", "mtime", "ctime", "crtime")


def adapt_bodyfile(
    lines: Iterable[str],
    *,
    run_id: str,
    tool_version: str = "unknown",
    input_name: str = "bodyfile",
) -> list[ToolFinding]:
    # Bodyfile rows are disk *objects*, not timeline events (plaso owns those):
    # one finding per row, typed MACB metadata under entity["timestamps"], and
    # no scalar event time is claimed for the row.
    findings: list[ToolFinding] = []
    for idx, row in enumerate(parse_bodyfile(lines), start=1):
        path = row["path"]
        entity: dict[str, Any] = {
            "type": "path",
            "value": path,
            "inode": row.get("inode"),
            "mode": row.get("mode"),
            "size": row.get("size"),
            "deleted": bool(row.get("deleted")),
        }
        if row.get("reallocated"):
            # A reallocated inode's metadata belongs to the new file, not the
            # deleted name: record no timestamps, offsets stay absent.
            entity["reallocated"] = True
        else:
            timestamps = {
                kind: ts
                for kind in _TIME_KINDS
                if (ts := iso_from_epoch(row.get(kind))) is not None
            }
            if timestamps:
                entity["timestamps"] = timestamps
        findings.append(
            make_tool_finding(
                run_id=run_id,
                tool="sleuthkit",
                tool_version=tool_version,
                source_type=EvidenceSource.DISK,
                artifact_class=_artifact_class(path, bool(row.get("deleted"))),
                entity=entity,
                raw_ref=f"bodyfile:{input_name}:line={idx}:inode={row.get('inode')}",
                provenance={
                    "adapter": "sleuthkit.bodyfile",
                    "input": input_name,
                    "row_index": idx,
                    "parser": "fls -m bodyfile",
                },
            )
        )
    return findings


def adapt_bodyfile_file(
    path: str | Path,
    *,
    run_id: str,
    tool_version: str = "unknown",
) -> list[ToolFinding]:
    p = Path(path)
    return adapt_bodyfile(
        p.read_text(encoding="utf-8").splitlines(),
        run_id=run_id,
        tool_version=tool_version,
        input_name=str(p),
    )


def _artifact_class(path: str, deleted: bool) -> str:
    if deleted:
        return "deleted_file_candidate"
    if "ld.so.preload" in path or path.endswith(".preload"):
        return "preload_configuration"
    if path.endswith(".so") or ".so." in path:
        return "shared_object"
    if "preload" in path.rsplit("/", 1)[-1]:
        return "preload_configuration"
    if any(path.startswith(d) for d in _SERVICE_DIRS) and path.endswith(_SERVICE_SUFFIXES):
        return "service_unit_file"
    base = path.rsplit("/", 1)[-1]
    if base in _HISTORY_NAMES or path.startswith("/var/log/"):
        return "shell_history_log_event"
    return "file"
