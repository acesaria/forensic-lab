# orchestrator/evaluation/detect/tsk_heuristics.py
#
# Sleuth Kit filesystem heuristics (Phase 3.3) over an fls -m bodyfile. GT-blind:
# flags deleted-but-recoverable inodes in temp/hidden locations, executables
# created in temp or persistence paths within the case window, and timestamp
# anomalies (creation after modification). Filesystem times are real epochs ->
# ts_quality "wallclock".
#
# bodyfile columns: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
# fls -m appends "(deleted)" / "(deleted-realloc)" to the name of unallocated
# entries, which is how a deleted inode is recognised here.

from __future__ import annotations

from typing import Any, Iterable

from orchestrator.evaluation.detect.base import make_finding
from orchestrator.evaluation.contracts.models import Finding
from orchestrator.forensics.timeutil import epoch_us_to_iso_ms, parse_iso_utc

_TOOL = "tsk"
_TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
_PERSIST_PREFIXES = (
    "/etc/cron",
    "/etc/systemd",
    "/usr/lib/systemd",
    "/lib/systemd",
    "/etc/init.d",
    "/etc/rc.local",
)
_RC_BASENAMES = (".bashrc", ".bash_profile", ".profile", ".zshrc")


def _epoch_to_iso(epoch: int | float | None) -> str | None:
    if epoch is None:
        return None
    try:
        return epoch_us_to_iso_ms(int(float(epoch) * 1_000_000))
    except (ValueError, OverflowError):
        return None


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
                "mtime": _to_float(parts[8]),
                "ctime": _to_float(parts[9]),
                "crtime": _to_float(parts[10]),
                "deleted": deleted,
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


def _bodyfile_rows(raw: dict[str, Any]) -> list[dict[str, Any]]:
    tsk = raw.get("tsk", {})
    if isinstance(tsk.get("rows"), list):
        return tsk["rows"]
    body = tsk.get("bodyfile")
    if isinstance(body, str):
        return parse_bodyfile(body.splitlines())
    if isinstance(body, list):
        return parse_bodyfile(body)
    return []


def _is_executable(mode: str) -> bool:
    return "x" in (mode or "")


def _is_regular_file(mode: str) -> bool:
    # fls -m mode is "<nametype>/<metatype><perms>", e.g. "r/rrwxr-xr-x" for a
    # regular file, "d/drwxr-xr-x" for a directory. Directories carry the x bit
    # too, so the temp-exec heuristic must gate on the file type, not just "x".
    t = (mode or "").strip()
    return t[:1] == "r"


def _in_window(epoch: float | None, window: dict[str, Any] | None) -> bool:
    if not window:
        return True
    if epoch is None:
        return True
    start = window.get("start")
    end = window.get("end")
    lo = parse_iso_utc(start) if isinstance(start, str) else float("-inf")
    hi = parse_iso_utc(end) if isinstance(end, str) else float("inf")
    return lo <= epoch <= hi


def _persistence_path(path: str) -> bool:
    if any(path.startswith(p) for p in _PERSIST_PREFIXES):
        return True
    base = path.rsplit("/", 1)[-1]
    return base in _RC_BASENAMES


def detect_deleted_recoverable(raw, cfg) -> Iterable[Finding]:
    # Deleted inode under a temp dir or a hidden dotfile in a user home.
    for r in _bodyfile_rows(raw):
        if not r["deleted"]:
            continue
        path = r["path"]
        base = path.rsplit("/", 1)[-1]
        temp = any(path.startswith(d) for d in _TEMP_DIRS)
        hidden_home = path.startswith("/home/") and base.startswith(".")
        hidden_root = path.startswith("/root/") and base.startswith(".")
        if not (temp or hidden_home or hidden_root):
            continue
        yield make_finding(
            source_tool=_TOOL,
            detector="tsk:deleted_recoverable",
            event_class="file_deleted",
            entity_type="path",
            entity_value=path,
            ts_quality="wallclock",
            technique="T1070.004",
            ts_utc=_epoch_to_iso(r["ctime"] or r["mtime"] or r["crtime"]),
            raw_ref=f"bodyfile:inode={r['inode']}",
            confidence="medium",
        )


def detect_temp_or_persistence_exec(raw, cfg) -> Iterable[Finding]:
    window = cfg.get("case_window") if cfg else None
    for r in _bodyfile_rows(raw):
        if r["deleted"]:
            continue
        path = r["path"]
        crtime = r["crtime"]
        if not _in_window(crtime, window):
            continue
        temp = any(path.startswith(d) for d in _TEMP_DIRS)
        persist = _persistence_path(path)
        if temp and _is_regular_file(r["mode"]) and _is_executable(r["mode"]):
            yield make_finding(
                source_tool=_TOOL,
                detector="tsk:temp_exec_created",
                event_class="file_created",
                entity_type="path",
                entity_value=path,
                ts_quality="wallclock",
                technique="T1059.004",
                ts_utc=_epoch_to_iso(crtime or r["mtime"]),
                raw_ref=f"bodyfile:inode={r['inode']}",
                confidence="medium",
            )
        elif persist:
            yield make_finding(
                source_tool=_TOOL,
                detector="tsk:persistence_path_created",
                event_class="persistence_installed",
                entity_type="path",
                entity_value=path,
                ts_quality="wallclock",
                technique="T1053.003",
                ts_utc=_epoch_to_iso(crtime or r["mtime"]),
                raw_ref=f"bodyfile:inode={r['inode']}",
                confidence="medium",
            )


def detect_timestamp_anomaly(raw, cfg) -> Iterable[Finding]:
    # Creation time strictly later than modification time: a classic timestomp
    # tell where the filesystem records both (ext4 crtime). Scoped to the case
    # window: crtime > mtime is the norm on a cloud image (files unpacked with
    # preserved mtimes), so without a window this fires on the whole filesystem.
    window = cfg.get("case_window") if cfg else None
    for r in _bodyfile_rows(raw):
        crtime, mtime = r["crtime"], r["mtime"]
        if crtime is None or mtime is None:
            continue
        if not _in_window(mtime, window) and not _in_window(crtime, window):
            continue
        if crtime > mtime + 1:  # 1 s slack for same-second creation/write
            yield make_finding(
                source_tool=_TOOL,
                detector="tsk:timestamp_anomaly",
                event_class="file_modified",
                entity_type="path",
                entity_value=r["path"],
                ts_quality="wallclock",
                technique="T1070.006",
                ts_utc=_epoch_to_iso(mtime),
                raw_ref=f"bodyfile:inode={r['inode']}",
                confidence="low",
            )


_DETECTORS = (
    detect_deleted_recoverable,
    detect_temp_or_persistence_exec,
    detect_timestamp_anomaly,
)


def detect(raw_outputs: dict[str, Any], rules_config: dict[str, Any]) -> Iterable[Finding]:
    for fn in _DETECTORS:
        yield from fn(raw_outputs, rules_config)
