"""YARA match adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from orchestrator.adapters.common import UNKNOWN_TIME, load_json_or_jsonl, make_tool_finding
from orchestrator.canonical import EvidenceSource, TemporalQuality, ToolFinding


def adapt_yara_matches(
    matches: Iterable[dict[str, Any]],
    *,
    run_id: str,
    tool_version: str = "unknown",
    input_name: str = "yara-matches",
) -> list[ToolFinding]:
    findings: list[ToolFinding] = []
    for idx, match in enumerate(matches, start=1):
        path = match.get("path") or match.get("file")
        rule = match.get("rule")
        if not path or not rule:
            continue
        findings.append(
            make_tool_finding(
                run_id=run_id,
                tool="yara",
                tool_version=tool_version,
                source_type=EvidenceSource.DISK,
                artifact_class="file",
                entity={
                    "type": "path",
                    "value": str(path),
                    "rule": str(rule),
                    "namespace": match.get("namespace"),
                    "tags": list(match.get("tags") or []),
                },
                time=UNKNOWN_TIME,
                raw_ref=f"yara:{input_name}:rule={rule}:path={path}",
                provenance={
                    "adapter": "yara.matches",
                    "input": input_name,
                    "row_index": idx,
                    "meta": dict(match.get("meta") or {}),
                },
                temporal_quality=TemporalQuality.NONE,
            )
        )
    return findings


def adapt_yara_matches_file(
    path: str | Path,
    *,
    run_id: str,
    tool_version: str = "unknown",
) -> list[ToolFinding]:
    p = Path(path)
    data = load_json_or_jsonl(p)
    matches = data if isinstance(data, list) else data.get("matches", [])
    return adapt_yara_matches(
        matches,
        run_id=run_id,
        tool_version=tool_version,
        input_name=str(p),
    )
