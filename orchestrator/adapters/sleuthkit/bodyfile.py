"""Sleuth Kit bodyfile adapter.

Input is the raw `fls -m /` bodyfile already produced by the repo's TSK
extractor. No ground truth is read; every row is converted as a filesystem
artifact observation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from orchestrator.adapters.common import iso_from_epoch, make_tool_finding
from orchestrator.canonical import EvidenceSource, TemporalQuality, ToolFinding
from orchestrator.evaluation.detect.tsk_heuristics import parse_bodyfile

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


def adapt_bodyfile(
    lines: Iterable[str],
    *,
    run_id: str,
    tool_version: str = "unknown",
    input_name: str = "bodyfile",
) -> list[ToolFinding]:
    findings: list[ToolFinding] = []
    for idx, row in enumerate(parse_bodyfile(lines), start=1):
        path = row["path"]
        time = iso_from_epoch(row.get("crtime") or row.get("mtime") or row.get("ctime"))
        findings.append(
            make_tool_finding(
                run_id=run_id,
                tool="sleuthkit",
                tool_version=tool_version,
                source_type=EvidenceSource.DISK,
                artifact_class=_artifact_class(path, bool(row.get("deleted"))),
                entity={
                    "type": "path",
                    "value": path,
                    "inode": row.get("inode"),
                    "mode": row.get("mode"),
                    "size": row.get("size"),
                    "deleted": bool(row.get("deleted")),
                },
                time=time,
                raw_ref=f"bodyfile:{input_name}:line={idx}:inode={row.get('inode')}",
                provenance={
                    "adapter": "sleuthkit.bodyfile",
                    "input": input_name,
                    "row_index": idx,
                    "parser": "fls -m bodyfile",
                },
                temporal_quality=TemporalQuality.EXACT if time else TemporalQuality.NONE,
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
