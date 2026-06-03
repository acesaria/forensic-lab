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
    return _empty_detection(spec["tool"])


def _empty_detection(tool: str) -> dict[str, Any]:
    return {"found": False, "tool_hits": {tool: False}, "matches": []}


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

    matches = [
        {
            "path": r["path"],
            "inode": r["inode"],
            "deleted": r["deleted"],
            "is_dir": r["is_dir"],
        }
        for r in candidates
    ]
    # TODO: disk "found" warning -- found is currently bool(matches) and counts
    # deleted entries. fls -r still lists files unlinked by cleanup (marked
    # deleted=True), so a "present"-style spec like bash_history_present reports
    # found even after the file was removed. The deleted flag is recorded per
    # match; a later pass should let specs opt into present-only matching.
    found = bool(matches)

    # content_contains only applies on top of an exact-path hit: extract the
    # file via icat and confirm the marker string is present.
    content_contains = query.get("content_contains")
    if found and content_contains is not None and path_equals is not None:
        offset = cache["offset"]
        content_ok = False
        for r in candidates:
            if r["deleted"] or r["is_dir"]:
                continue
            try:
                blob = sleuth.icat(disk_path, offset, r["inode"])
            except RuntimeError as exc:
                _log.warning("icat failed for inode %s: %s", r["inode"], exc)
                continue
            text = blob.decode("utf-8", errors="replace")
            if content_contains in text:
                content_ok = True
                break
        for m in matches:
            m["content_match"] = content_ok
        found = content_ok

    return {"found": found, "tool_hits": {"sleuth": found}, "matches": matches}


def _row_string_values(row: dict[str, Any]) -> list[str]:
    return [v for v in row.values() if isinstance(v, str)]


def _get_plugin_rows(
    vol: VolatilityRunner,
    memory_path: Path,
    distro_id: str,
    plugin: str,
    cache: dict[str, Any],
) -> list[dict[str, Any]]:
    rows = cache["plugins"].get(plugin)
    if rows is None:
        rows = vol.run_plugin(memory_path, distro_id, plugin)
        cache["plugins"][plugin] = rows
    return rows


def _detect_memory_artifact(
    spec: dict[str, Any],
    vol: VolatilityRunner,
    memory_path: Path,
    distro_id: str,
    cache: dict[str, Any],
) -> dict[str, Any]:
    query = spec["query"]
    plugin = query["plugin"]
    rows = _get_plugin_rows(vol, memory_path, distro_id, plugin, cache)
    matches: list[dict[str, Any]] = []

    if plugin == "linux.proc_maps":
        needle = query["path_substring"]
        for row in rows:
            mapped = first_present(row, "File Path", "Path", "FilePath", "File")
            haystacks = [mapped] if isinstance(mapped, str) else _row_string_values(row)
            if any(needle in h for h in haystacks):
                matches.append(
                    {
                        "pid": first_present(row, "PID", "Pid", "pid"),
                        "path": mapped if isinstance(mapped, str) else None,
                    }
                )

    elif plugin == "linux.netstat":
        port = query.get("port")
        names = query.get("process_names")
        for row in rows:
            if not _netstat_port_match(row, port):
                continue
            if names is not None and not _netstat_name_match(row, names):
                continue
            matches.append(
                {
                    "pid": first_present(row, "PID", "Pid", "pid"),
                    "process": first_present(row, "Process Name", "Comm", "Process"),
                    "local_port": first_present(row, "LocalPort", "Local Port"),
                    "foreign_port": first_present(row, "ForeignPort", "Foreign Port"),
                    "state": first_present(row, "State"),
                }
            )

    found = bool(matches)
    return {"found": found, "tool_hits": {"vol3": found}, "matches": matches}


def _netstat_port_match(row: dict[str, Any], port: int | None) -> bool:
    if port is None:
        return True
    local = first_present(row, "LocalPort", "Local Port", "LocalAddr Port")
    foreign = first_present(row, "ForeignPort", "Foreign Port")
    for value in (local, foreign):
        try:
            if value is not None and int(value) == int(port):
                return True
        except (TypeError, ValueError):
            continue
    # Some vol3 builds fold the port into an address string ("0.0.0.0:4444").
    for text in _row_string_values(row):
        if _ADDR_RE.match(text) and f":{port}" in text:
            return True
    return False


def _netstat_name_match(row: dict[str, Any], names: list[str]) -> bool:
    proc = first_present(row, "Process Name", "Comm", "Process")
    if isinstance(proc, str) and any(n in proc for n in names):
        return True
    return False


def _detect_timeline_artifact(
    spec: dict[str, Any],
    events: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    if events is None:
        return {"found": False, "tool_hits": {"plaso": False}, "matches": []}

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

    found = bool(matches)
    return {"found": found, "tool_hits": {"plaso": found}, "matches": matches}
