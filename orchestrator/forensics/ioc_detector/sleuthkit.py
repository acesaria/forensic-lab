# orchestrator/forensics/ioc_detector/sleuthkit.py
#
# Disk detection (Sleuth Kit). Selects the inode(s) matching a spec's path from
# the cached fls listing, asks the recovery chain for each inode's content, and
# grades the result: a live or content-recovered file is "present"/"recovered",
# a deleted inode with no recoverable body is a bare "entry_only" tombstone.

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from orchestrator.forensics.ioc_detector.recovery import recover_content
from orchestrator.forensics.ioc_detector.status import (
    DISK_STATUS_DELETED_ENTRY_ONLY,
    DISK_STATUS_DELETED_RECOVERED,
    DISK_STATUS_NOT_FOUND,
    DISK_STATUS_PRESENT,
    STATUS_RANK,
    empty_detection,
    found_from_status,
)

if TYPE_CHECKING:
    from orchestrator.forensics.ioc_detector.context import DetectorContext

_log = logging.getLogger(__name__)


def _classify_candidate(
    ctx: "DetectorContext", row: dict[str, Any], content_contains: str | None
) -> tuple[str, bool | None, int | None, str | None]:
    # Returns (status, content_match, recovered_bytes, recovery_method).
    # content_match is None when the spec has no content_contains; recovered_bytes
    # is None for a directory entry; recovery_method names the backend that read
    # the body (None when there was no body).
    deleted = row["deleted"]
    if row["is_dir"]:
        status = DISK_STATUS_DELETED_ENTRY_ONLY if deleted else DISK_STATUS_PRESENT
        return status, None, None, None

    blob, method = recover_content(ctx, row["inode"])
    has_body = bool(blob)
    content_match: bool | None = None
    if content_contains is not None:
        text = blob.decode("utf-8", errors="replace") if has_body else ""
        content_match = content_contains in text

    if not has_body:
        if not deleted:
            # Live entry we cannot read (e.g. a FIFO): the ambiguous case worth
            # flagging, recorded as present with zero recovered bytes.
            _log.warning(
                "no content recovered for live inode %s (%s)",
                row["inode"],
                row["path"],
            )
            return DISK_STATUS_PRESENT, content_match, 0, None
        return DISK_STATUS_DELETED_ENTRY_ONLY, content_match, 0, None

    status = DISK_STATUS_DELETED_RECOVERED if deleted else DISK_STATUS_PRESENT
    return status, content_match, len(blob), method


def detect_disk(spec: dict[str, Any], ctx: "DetectorContext") -> dict[str, Any]:
    query = spec["query"]
    rows = ctx.fls_rows()

    path_equals = query.get("path_equals")
    path_suffix = query.get("path_suffix")
    if path_equals is not None:
        candidates = [r for r in rows if r["path"] == path_equals]
    elif path_suffix is not None:
        candidates = [r for r in rows if r["path"].endswith(path_suffix)]
    else:
        candidates = []

    if not candidates:
        return empty_detection()

    content_contains = query.get("content_contains")

    matches: list[dict[str, Any]] = []
    best_status = DISK_STATUS_NOT_FOUND
    best_path: str | None = None
    best_inode: str | None = None
    best_deleted: bool | None = None
    best_bytes: int | None = None
    best_method: str | None = None
    content_match_any = False
    any_body_readable = False
    for r in candidates:
        status, content_match, nbytes, method = _classify_candidate(
            ctx, r, content_contains
        )
        if STATUS_RANK[status] > STATUS_RANK[best_status]:
            best_status = status
            best_path = r["path"]
            best_inode = r["inode"]
            best_deleted = r["deleted"]
            best_bytes = nbytes
            best_method = method
        if content_match:
            content_match_any = True
        if nbytes:
            any_body_readable = True
        match: dict[str, Any] = {
            "path": r["path"],
            "inode": r["inode"],
            "deleted": r["deleted"],
            "is_dir": r["is_dir"],
            "status": status,
        }
        if content_match is not None:
            match["content_match"] = content_match
        if nbytes is not None:
            match["recovered_bytes"] = nbytes
        matches.append(match)

    found = found_from_status(best_status)
    # Content gate: when a body was readable, the marker must be in it. When no
    # body survives (entry-only), the path match alone stands as a weaker trace.
    if content_contains is not None and any_body_readable and not content_match_any:
        found = False

    if not found:
        return {
            "found": False,
            "status": best_status,
            "evidence": None,
            "timestamp": None,
            "matches": matches,
        }

    method_str = f"fls+{best_method}" if best_method else "fls"
    if content_contains is not None and content_match_any:
        match_desc = f"content '{content_contains}'"
    elif path_equals is not None:
        match_desc = f"path == {path_equals}"
    elif path_suffix is not None:
        match_desc = f"path endswith {path_suffix}"
    else:
        match_desc = "path"

    return {
        "found": True,
        "status": best_status,
        "evidence": {
            "tool": "sleuthkit",
            "method": method_str,
            "locator": best_path,
            "match": match_desc,
            # provenance: which inode carried it and whether/how much content was
            # recovered (None = directory/no body, 0 = tombstone only).
            "inode": best_inode,
            "deleted": best_deleted,
            "recovered_bytes": best_bytes,
        },
        "timestamp": None,  # attached from the timeline in detect_iocs_for_run
        "matches": matches,
    }
