"""Shared helpers for canonical tool-output adapters."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from orchestrator.canonical import EvidenceSource, TemporalQuality, ToolFinding, write_jsonl
from orchestrator.forensics.timeutil import epoch_us_to_iso_ms

ADAPTER_VERSION = "canonical-adapters-v1"
UNKNOWN_TIME = "unknown"


def iso_from_epoch(value: Any) -> str | None:
    if value in (None, "", 0, "0"):
        return None
    try:
        return epoch_us_to_iso_ms(int(float(value) * 1_000_000))
    except (TypeError, ValueError, OverflowError):
        return None


def load_json_or_jsonl(path: str | Path) -> Any:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    stripped = text.lstrip()
    if not stripped:
        return []
    if stripped.startswith("[") or stripped.startswith("{"):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def make_tool_finding(
    *,
    run_id: str,
    tool: str,
    tool_version: str = "unknown",
    source_type: EvidenceSource,
    artifact_class: str,
    entity: dict[str, Any],
    raw_ref: str,
    provenance: dict[str, Any],
    time: str | None = None,
    adapter_version: str = ADAPTER_VERSION,
    temporal_quality: TemporalQuality | None = None,
) -> ToolFinding:
    observed_time = time or UNKNOWN_TIME
    quality = temporal_quality or (
        TemporalQuality.EXACT if time else TemporalQuality.NONE
    )
    initial_id = "tf-" + hashlib.sha1(
        "|".join(
            str(x)
            for x in (
                run_id,
                tool,
                source_type.value,
                artifact_class,
                entity.get("type"),
                entity.get("value"),
                raw_ref,
            )
        ).encode("utf-8")
    ).hexdigest()[:12]
    return ToolFinding(
        finding_id=initial_id,
        run_id=run_id,
        tool=tool,
        tool_version=tool_version,
        adapter_version=adapter_version,
        source_type=source_type,
        artifact_class=artifact_class,
        entity=entity,
        time=observed_time,
        raw_ref=raw_ref,
        provenance=provenance,
        temporal_quality=quality,
    )


def assign_tool_finding_ids(findings: Iterable[ToolFinding]) -> list[ToolFinding]:
    items = list(findings)
    items.sort(key=_sort_key)
    for idx, finding in enumerate(items):
        digest = hashlib.sha1(
            "|".join(str(x) for x in _sort_key(finding)).encode("utf-8")
        ).hexdigest()[:10]
        finding.finding_id = f"tf-{idx:06d}-{digest}"
    return items


def write_tool_findings(path: str | Path, findings: Iterable[ToolFinding]) -> Path:
    return write_jsonl(path, assign_tool_finding_ids(findings))


def _sort_key(finding: ToolFinding) -> tuple[Any, ...]:
    return (
        finding.time,
        finding.tool,
        finding.artifact_class,
        str(finding.entity.get("type")),
        str(finding.entity.get("value")),
        finding.raw_ref,
    )
