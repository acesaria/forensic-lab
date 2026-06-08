# orchestrator/forensics/ioc_detector.py
#
# Generic IOC detector. Given a run's acquisitions plus a list of ArtifactSpec
# dicts (see artifact_specs.py), it drives the existing forensics runners and
# reports, per artifact, whether it was found and which raw matches backed that
# call. Confidence scoring lives in evaluator.py -- this layer only reports
# observations.
#
# The detector is deliberately tolerant about tool field names: Volatility and
# fls field spellings drift between versions, so matching scans candidate keys
# (and, as a fallback, all string values) rather than hard-coding one schema.

from __future__ import annotations

from pathlib import Path
from typing import Any
import logging

from orchestrator.forensics.sleuth_runner import (
    SleuthKitRunner,
    parse_fls_line,
)
from orchestrator.forensics.vol_runner import VolatilityRunner, first_present

_log = logging.getLogger(__name__)

# Disk artifact recovery states. Defined once here (the producer) and imported
# by evaluator.py (the consumer) so the two never drift. Ordered weakest ->
# strongest; _STATUS_RANK uses that order to pick the best of several candidates.
# Memory/timeline detections have no deletion semantics, so they reuse only
# present / not_found from this same set.
DISK_STATUS_NOT_FOUND = "not_found"
DISK_STATUS_DELETED_ENTRY_ONLY = "deleted_entry_only"
DISK_STATUS_DELETED_RECOVERED = "deleted_recovered"
DISK_STATUS_PRESENT = "present"

DISK_STATUSES = (
    DISK_STATUS_NOT_FOUND,
    DISK_STATUS_DELETED_ENTRY_ONLY,
    DISK_STATUS_DELETED_RECOVERED,
    DISK_STATUS_PRESENT,
)
_STATUS_RANK = {name: i for i, name in enumerate(DISK_STATUSES)}

import re as _re

_ADDR_RE = _re.compile(r"[\d.:a-f]+:\d+$", _re.IGNORECASE)


def detect_iocs_for_run(
    run_id: str,
    ground_truth: dict[str, Any],
    specs: list[dict[str, Any]],
    sleuth: SleuthKitRunner,
    vol: VolatilityRunner,
    disk_path: Path,
    memory_path: Path,
    distro_id: str,
    timeline_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    # Caches keep each expensive runner call (fls listing, a vol3 plugin) to one
    # invocation per run, no matter how many specs consult it.
    cache: dict[str, Any] = {
        "fls": None,  # parsed fls rows for the disk image
        "plugins": {},  # plugin name -> rows
    }

    specs_by_step: dict[str, list[dict[str, Any]]] = {}
    for spec in specs:
        specs_by_step.setdefault(spec["step"], []).append(spec)

    steps_report: dict[str, Any] = {}
    for step in ground_truth.get("steps", []):
        step_name = step.get("step")
        if step_name is None:
            continue
        artifacts: dict[str, Any] = {}
        for spec in specs_by_step.get(step_name, []):
            artifacts[spec["id"]] = _detect_artifact(
                spec,
                sleuth,
                vol,
                disk_path,
                memory_path,
                distro_id,
                timeline_events,
                cache,
            )
        steps_report[step_name] = {"artifacts": artifacts}

    return {"run_id": run_id, "steps": steps_report}


def _detect_artifact(
    spec: dict[str, Any],
    sleuth: SleuthKitRunner,
    vol: VolatilityRunner,
    disk_path: Path,
    memory_path: Path,
    distro_id: str,
    timeline_events: list[dict[str, Any]] | None,
    cache: dict[str, Any],
) -> dict[str, Any]:
    artifact_type = spec["artifact_type"]
    if artifact_type == "disk":
        return _detect_disk_artifact(spec, sleuth, disk_path, cache)
    if artifact_type == "memory":
        return _detect_memory_artifact(spec, vol, memory_path, distro_id, cache)
    if artifact_type == "timeline":
        return _detect_timeline_artifact(spec, timeline_events)
    return _empty_detection()


def _empty_detection() -> dict[str, Any]:
    return {
        "found": False,
        "status": DISK_STATUS_NOT_FOUND,
        "matched_by": None,
        "matches": [],
    }


def _normalize_fls_path(name: str) -> str:
    # fls -p emits volume-root-relative paths without a leading slash and marks
    # directories with a trailing slash. Normalize to an absolute-looking path
    # so specs can write "/etc/ld.so.preload".
    return "/" + name.lstrip("/").rstrip("/")


def _load_fls_rows(
    sleuth: SleuthKitRunner,
    disk_path: Path,
    cache: dict[str, Any],
) -> list[dict[str, Any]]:
    if cache["fls"] is not None:
        return cache["fls"]
    offset = sleuth.partition_offset(disk_path)
    cache["offset"] = offset
    rows: list[dict[str, Any]] = []
    # -p gives full paths; -r recurses the whole filesystem so one call covers
    # every disk spec.
    for line in sleuth.fls(disk_path, offset, flags="-r -p -l"):
        parsed = parse_fls_line(line)
        if parsed is None:
            continue
        parsed["path"] = _normalize_fls_path(parsed["name"])
        rows.append(parsed)
    cache["fls"] = rows
    return rows


def _read_inode(
    sleuth: SleuthKitRunner, disk_path: Path, offset: int, inode: str
) -> bytes | None:
    # None means "content gone": icat raised or there were no blocks to read.
    # That is exactly what separates deleted_entry_only from deleted_recovered.
    try:
        return sleuth.icat(disk_path, offset, inode)
    except RuntimeError as exc:
        _log.warning("icat failed for inode %s: %s", inode, exc)
        return None


def _classify_candidate(
    sleuth: SleuthKitRunner,
    disk_path: Path,
    offset: int,
    row: dict[str, Any],
    content_contains: str | None,
) -> tuple[str, bool | None, int | None]:
    # Returns (status, content_match, recovered_bytes). content_match is None
    # when the spec has no content_contains; recovered_bytes is None when there
    # was no body to measure (directory entry).
    deleted = row["deleted"]
    if row["is_dir"]:
        status = DISK_STATUS_DELETED_ENTRY_ONLY if deleted else DISK_STATUS_PRESENT
        return status, None, None

    blob = _read_inode(sleuth, disk_path, offset, row["inode"])
    has_body = bool(blob)
    content_match: bool | None = None
    if content_contains is not None:
        text = blob.decode("utf-8", errors="replace") if has_body else ""
        content_match = content_contains in text

    if not has_body:
        if not deleted:
            # Live entry we cannot read: the ambiguous case worth flagging.
            _log.warning(
                "icat returned no content for live inode %s (%s)",
                row["inode"],
                row["path"],
            )
            return DISK_STATUS_PRESENT, content_match, 0
        return DISK_STATUS_DELETED_ENTRY_ONLY, content_match, 0

    status = DISK_STATUS_DELETED_RECOVERED if deleted else DISK_STATUS_PRESENT
    return status, content_match, len(blob)


def _found_from_status(status: str, query: dict[str, Any]) -> bool:
    # Default: present and deleted_recovered are found; a bare tombstone is not.
    # Specs override via query flags, so future scenarios change policy with data
    # rather than new branches in the detector.
    if status == DISK_STATUS_PRESENT:
        return True
    if status == DISK_STATUS_DELETED_RECOVERED:
        return query.get("treat_deleted_recovered_as_found", True)
    if status == DISK_STATUS_DELETED_ENTRY_ONLY:
        return query.get("treat_deleted_entry_as_found", False)
    return False


def _detect_disk_artifact(
    spec: dict[str, Any],
    sleuth: SleuthKitRunner,
    disk_path: Path,
    cache: dict[str, Any],
) -> dict[str, Any]:
    query = spec["query"]
    rows = _load_fls_rows(sleuth, disk_path, cache)

    path_equals = query.get("path_equals")
    path_suffix = query.get("path_suffix")
    if path_equals is not None:
        candidates = [r for r in rows if r["path"] == path_equals]
    elif path_suffix is not None:
        candidates = [r for r in rows if r["path"].endswith(path_suffix)]
    else:
        candidates = []

    if not candidates:
        return {
            "found": False,
            "status": DISK_STATUS_NOT_FOUND,
            "matched_by": None,
            "matches": [],
        }

    offset = cache["offset"]
    content_contains = query.get("content_contains")

    matches: list[dict[str, Any]] = []
    best_status = DISK_STATUS_NOT_FOUND
    content_match_any = False
    for r in candidates:
        status, content_match, nbytes = _classify_candidate(
            sleuth, disk_path, offset, r, content_contains
        )
        if _STATUS_RANK[status] > _STATUS_RANK[best_status]:
            best_status = status
        if content_match:
            content_match_any = True
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

    found = _found_from_status(best_status, query)
    if content_contains is not None:
        # Content specs need the marker in a readable body, on top of the
        # path/status gate above.
        found = found and content_match_any

    return {
        "found": found,
        "status": best_status,
        "matched_by": "sleuth" if found else None,
        "matches": matches,
    }


def _row_string_values(row: dict[str, Any]) -> list[str]:
    return [v for v in row.values() if isinstance(v, str)]


# Memory artifact categories resolve to an ordered list of vol3 plugins. The
# detector walks them in priority order and stops at the first that yields a
# match, so a spec says "shared_library" instead of pinning a plugin name that
# drifts between vol3 releases. Scenario 02 categories are listed now so adding
# a spec stays data-only.
MEMORY_CATEGORY_PLUGINS: dict[str, tuple[str, ...]] = {
    "shared_library": ("linux.proc.Maps",),
    # sockstat walks live process fd tables; sockscan pool-scans for socket
    # structs and so recovers a connection whose owning process has already
    # exited (e.g. a reverse shell left in CLOSE state). Try the richer
    # sockstat first, fall back to sockscan for the orphaned case.
    "network_socket": ("linux.sockstat", "linux.sockscan"),
    "process": ("linux.pslist", "linux.psscan"),
    "kernel_module": ("linux.lsmod", "linux.hidden_modules", "linux.check_modules"),
    "syscall_hook": ("linux.check_syscall",),
    "credential_artifact": ("linux.bash", "linux.envars"),
    "ebpf_program": ("linux.bpf", "linux.ebpf"),
}


def _resolve_memory_plugins(spec: dict[str, Any]) -> tuple[str, ...]:
    # Explicit query["plugin"] wins for backward compatibility; otherwise the
    # candidate list comes from artifact_category.
    explicit = spec.get("query", {}).get("plugin")
    if explicit:
        return (explicit,)
    return MEMORY_CATEGORY_PLUGINS.get(spec.get("artifact_category", ""), ())


def _get_plugin_rows(
    vol: VolatilityRunner,
    memory_path: Path,
    distro_id: str,
    plugin: str,
    cache: dict[str, Any],
) -> list[dict[str, Any]]:
    rows = cache["plugins"].get(plugin)
    if rows is None:
        try:
            rows = vol.run_plugin(memory_path, distro_id, plugin)
        except RuntimeError as exc:
            # A candidate plugin may not exist for this kernel/build; skip it so
            # the next plugin in the category's priority list still gets a turn.
            _log.warning("vol3 plugin %s failed: %s", plugin, exc)
            rows = []
        cache["plugins"][plugin] = rows
    return rows


def _row_contains(row: dict[str, Any], needle: str) -> bool:
    # Prefer a path/name-like column, fall back to every string value: vol3
    # column names drift, so scanning all strings keeps substring matching robust.
    mapped = first_present(
        row, "File Path", "Path", "FilePath", "File", "Name", "Module"
    )
    haystacks = [mapped] if isinstance(mapped, str) else _row_string_values(row)
    return any(needle in h for h in haystacks)


def _summarize_row(row: dict[str, Any]) -> dict[str, Any]:
    # Tolerant projection of the columns a reviewer cares about; absent ones are
    # dropped so the match record stays readable across different plugins.
    fields = {
        "pid": first_present(row, "PID", "Pid", "pid"),
        "process": first_present(row, "Process Name", "Comm", "Process", "Name"),
        "path": first_present(row, "File Path", "Path", "FilePath", "File"),
        "local_port": first_present(row, "LocalPort", "Local Port", "Source Port"),
        "foreign_port": first_present(row, "ForeignPort", "Foreign Port", "Destination Port"),
        "state": first_present(row, "State"),
    }
    return {k: v for k, v in fields.items() if v is not None}


def _socket_port_match(row: dict[str, Any], port: int) -> bool:
    # Column names drift between vol3 builds: sockstat/sockscan on recent
    # builds emit "Source Port"/"Destination Port" rather than Local/Foreign.
    local = first_present(row, "LocalPort", "Local Port", "LocalAddr Port", "Source Port")
    foreign = first_present(row, "ForeignPort", "Foreign Port", "Destination Port")

    for value in (local, foreign):
        if isinstance(value, (int, str)):
            try:
                if int(value) == port:
                    return True
            except ValueError:
                continue

    # Some vol3 builds fold the port into an address string ("0.0.0.0:4444").
    for text in _row_string_values(row):
        if _ADDR_RE.match(text) and f":{port}" in text:
            return True

    return False


def _socket_name_ok(
    row: dict[str, Any], names: list[str], has_other_criteria: bool
) -> bool:
    # A present process name must match. But sockscan recovers orphaned socket
    # structs whose owning process has exited: those carry no process name, and
    # rejecting them would discard exactly the post-mortem evidence we want.
    # Accept a nameless row only when some other positive criterion (port/path)
    # already qualified it, so a names-only query stays strict.
    proc = first_present(row, "Process Name", "Comm", "Process")
    if isinstance(proc, str) and proc:
        return any(n in proc for n in names)
    return has_other_criteria


def _match_memory_rows(
    rows: list[dict[str, Any]], query: dict[str, Any]
) -> list[dict[str, Any]]:
    # Match strategy is inferred from which query keys are present, so one matcher
    # serves every category: a path/name substring and/or a socket port with
    # optional process names. Every present criterion must hold.
    path_needle = query.get("path_substring")
    name_needle = query.get("name_substring")
    port = query.get("port")
    names = query.get("process_names")
    if path_needle is None and name_needle is None and port is None and names is None:
        return []

    has_other_criteria = (
        path_needle is not None or name_needle is not None or port is not None
    )

    matches: list[dict[str, Any]] = []
    for row in rows:
        if path_needle is not None and not _row_contains(row, path_needle):
            continue
        if name_needle is not None and not _row_contains(row, name_needle):
            continue
        if port is not None and not _socket_port_match(row, port):
            continue
        if names is not None and not _socket_name_ok(row, names, has_other_criteria):
            continue
        matches.append(_summarize_row(row))
    return matches


def _detect_memory_artifact(
    spec: dict[str, Any],
    vol: VolatilityRunner,
    memory_path: Path,
    distro_id: str,
    cache: dict[str, Any],
) -> dict[str, Any]:
    query = spec["query"]
    # Walk candidate plugins in priority order; the first non-empty match wins and
    # is recorded in matched_by so the report shows which plugin produced the hit.
    for plugin in _resolve_memory_plugins(spec):
        rows = _get_plugin_rows(vol, memory_path, distro_id, plugin, cache)
        matches = _match_memory_rows(rows, query)
        if matches:
            return {
                "found": True,
                "status": DISK_STATUS_PRESENT,
                "matched_by": plugin,
                "matches": matches,
            }
    return {
        "found": False,
        "status": DISK_STATUS_NOT_FOUND,
        "matched_by": None,
        "matches": [],
    }


def _detect_timeline_artifact(
    spec: dict[str, Any],
    events: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    if events is None:
        return {
            "found": False,
            "status": DISK_STATUS_NOT_FOUND,
            "matched_by": None,
            "matches": [],
        }

    query = spec["query"]
    needles = query.get("message_contains_any", [])
    matches: list[dict[str, Any]] = []
    for event in events:
        message = event.get("message")
        if not isinstance(message, str):
            continue
        if any(n in message for n in needles):
            matches.append(
                {
                    "datetime": event.get("datetime"),
                    "message": message,
                }
            )

    # filename_substring matches filesystem-metadata (filestat) events by path
    # rather than command text. The scenario runs non-interactively, so shell
    # history is thin; the path of a dropped/modified file is the reliable
    # timeline signal. Plaso spells the path differently across parsers, so scan
    # filename, display_name, then message.
    name_needle = query.get("filename_substring")
    if name_needle is not None:
        for event in events:
            for key in ("filename", "display_name", "message"):
                val = event.get(key)
                if isinstance(val, str) and name_needle in val:
                    matches.append(
                        {"datetime": event.get("datetime"), "message": val}
                    )
                    break

    found = bool(matches)
    return {
        "found": found,
        "status": DISK_STATUS_PRESENT if found else DISK_STATUS_NOT_FOUND,
        "matched_by": "plaso" if found else None,
        "matches": matches,
    }
