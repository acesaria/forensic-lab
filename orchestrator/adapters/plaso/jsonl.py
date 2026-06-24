"""Plaso psort JSONL adapter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from orchestrator.adapters.common import iso_from_plaso_timestamp, make_tool_finding
from orchestrator.canonical import EvidenceSource, TemporalQuality, ToolFinding


def adapt_plaso_events(
    events: Iterable[dict[str, Any]],
    *,
    run_id: str,
    tool_version: str = "unknown",
    input_name: str = "plaso-jsonl",
) -> list[ToolFinding]:
    findings: list[ToolFinding] = []
    for idx, event in enumerate(events, start=1):
        path = event.get("filename") or event.get("display_name")
        message = event.get("message")
        entity_value = str(path or message or "").strip()
        if not entity_value:
            continue
        timestamp = event.get("timestamp")
        if timestamp is None and isinstance(event.get("date_time"), dict):
            timestamp = event["date_time"].get("timestamp")
        time = iso_from_plaso_timestamp(timestamp)
        artifact_class, entity_type = _classify(event, entity_value)
        findings.append(
            make_tool_finding(
                run_id=run_id,
                tool="plaso",
                tool_version=tool_version,
                source_type=EvidenceSource.TIMELINE,
                artifact_class=artifact_class,
                entity={"type": entity_type, "value": entity_value},
                time=time,
                raw_ref=f"plaso:{input_name}:event={idx}",
                provenance={
                    "adapter": "plaso.jsonl",
                    "input": input_name,
                    "row_index": idx,
                    "parser": event.get("parser"),
                    "data_type": event.get("data_type"),
                    "timestamp_desc": event.get("timestamp_desc"),
                },
                temporal_quality=TemporalQuality.EXACT if time else TemporalQuality.NONE,
            )
        )
    return findings


def adapt_plaso_jsonl_file(
    path: str | Path,
    *,
    run_id: str,
    tool_version: str = "unknown",
) -> list[ToolFinding]:
    p = Path(path)
    events = [
        json.loads(line)
        for line in p.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return adapt_plaso_events(
        events,
        run_id=run_id,
        tool_version=tool_version,
        input_name=str(p),
    )


def _classify(event: dict[str, Any], value: str) -> tuple[str, str]:
    data_type = str(event.get("data_type") or "")
    parser = str(event.get("parser") or "")
    filename = str(event.get("filename") or "")
    if "ld.so.preload" in filename or filename.endswith(".preload") or "preload" in filename.rsplit("/", 1)[-1]:
        return "preload_configuration", "path"
    if filename.endswith(".so") or ".so." in filename:
        return "shared_object", "path"
    if filename.endswith((".service", ".timer", ".socket", ".path", ".mount")):
        return "service_unit_file", "path"
    if "/.bash_history" in filename or filename.startswith("/var/log/"):
        return "shell_history_log_event", "path"
    if data_type.startswith("fs:") or parser == "filestat":
        return "file", "path"
    return "shell_history_log_event", "log_line"
