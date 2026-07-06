"""Volatility3 JSON adapter."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from orchestrator.adapters.common import (
    classify_fs_path,
    load_json_or_jsonl,
    make_tool_finding,
)
from orchestrator.canonical import EvidenceSource, ToolFinding

_ADDR_RE = re.compile(r"(?P<ip>[0-9a-fA-F:.]+):(?P<port>\d+)")


def adapt_plugin_rows(
    plugin_rows: dict[str, list[dict[str, Any]]],
    *,
    run_id: str,
    tool_version: str = "unknown",
) -> list[ToolFinding]:
    findings: list[ToolFinding] = []
    for plugin, rows in plugin_rows.items():
        if not isinstance(rows, list):
            continue
        for idx, row in enumerate(rows, start=1):
            if not isinstance(row, dict):
                continue
            finding = _row_to_finding(
                plugin,
                idx,
                row,
                run_id=run_id,
                tool_version=tool_version,
            )
            if finding is not None:
                findings.append(finding)
    return findings


def adapt_volatility_json_file(
    path: str | Path,
    *,
    run_id: str,
    plugin: str | None = None,
    tool_version: str = "unknown",
) -> list[ToolFinding]:
    p = Path(path)
    data = load_json_or_jsonl(p)
    if isinstance(data, dict) and isinstance(data.get("rows"), list):
        plugin_rows = {plugin or str(data.get("plugin") or p.stem): data["rows"]}
    elif isinstance(data, dict) and all(isinstance(v, list) for v in data.values()):
        plugin_rows = {str(k): v for k, v in data.items()}
    elif isinstance(data, list):
        plugin_rows = {plugin or p.stem: data}
    else:
        plugin_rows = {}
    findings = adapt_plugin_rows(
        plugin_rows,
        run_id=run_id,
        tool_version=tool_version,
    )
    for finding in findings:
        finding.provenance["input_file"] = str(p)
    return findings


def _row_to_finding(
    plugin: str,
    idx: int,
    row: dict[str, Any],
    *,
    run_id: str,
    tool_version: str,
) -> ToolFinding | None:
    lowered = plugin.lower()
    if lowered.endswith(("pslist", "psscan")) or "malfind" in lowered:
        entity = _process_entity(row)
        artifact_class = "process"
    elif any(name in lowered for name in ("sockstat", "netstat", "sockscan")):
        entity = _socket_entity(row)
        artifact_class = "socket"
    elif lowered.endswith("bash") or ".bash" in lowered:
        command = _first(row, "Command", "command", "CommandLine")
        if command in (None, ""):
            return None
        entity = {"type": "command", "value": str(command), "pid": _pid(row)}
        artifact_class = "shell_history_log_event"
    elif "maps" in lowered or "elfs" in lowered:
        path = _first(row, "File Path", "Path", "FilePath", "File", "Mapping")
        if path in (None, ""):
            return None
        entity = {"type": "path", "value": str(path), "pid": _pid(row)}
        artifact_class = (
            "library_mapping"
            if classify_fs_path(str(path)) == "shared_object"
            else "file"
        )
    else:
        return None

    return make_tool_finding(
        run_id=run_id,
        tool="volatility3",
        tool_version=tool_version,
        source_type=EvidenceSource.MEMORY,
        artifact_class=artifact_class,
        entity=entity,
        time=None,
        raw_ref=f"vol3:{plugin}:row={idx}:pid={_pid(row)}",
        provenance={
            "adapter": "volatility3.json",
            "plugin": plugin,
            "row_index": idx,
        },
    )


def _process_entity(row: dict[str, Any]) -> dict[str, Any]:
    name = _first(row, "Process Name", "Comm", "Process", "Name")
    path = _first(row, "File Path", "Path", "FilePath", "File")
    return {
        "type": "process",
        "value": str(name or path or _pid(row) or "unknown"),
        "pid": _pid(row),
        "ppid": _first(row, "PPID", "Ppid", "ppid"),
        "path": path,
    }


def _socket_entity(row: dict[str, Any]) -> dict[str, Any]:
    dst_ip = _first(row, "Destination Addr", "ForeignAddr", "Foreign Address", "Dest IP", "DestinationAddr")
    dst_port = _first(row, "Destination Port", "ForeignPort", "Foreign Port", "DestinationPort")
    src_ip = _first(row, "Source Addr", "LocalAddr", "Local Address", "SourceAddr")
    src_port = _first(row, "Source Port", "LocalPort", "Local Port", "SourcePort")
    if dst_ip in (None, ""):
        for value in row.values():
            if isinstance(value, str):
                match = _ADDR_RE.search(value)
                if match:
                    dst_ip = match.group("ip")
                    dst_port = match.group("port")
                    break
    value = f"{dst_ip}:{dst_port}" if dst_ip not in (None, "") and dst_port not in (None, "") else str(dst_ip or src_ip or "unknown")
    return {
        "type": "socket",
        "value": value,
        "pid": _pid(row),
        "protocol": _first(row, "Proto", "Protocol"),
        "local": {"address": src_ip, "port": src_port},
        "remote": {"address": dst_ip, "port": dst_port},
    }


def _first(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None


def _pid(row: dict[str, Any]) -> Any:
    return _first(row, "PID", "Pid", "pid")
