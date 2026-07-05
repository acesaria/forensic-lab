"""Shared helpers for canonical tool-output adapters."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from orchestrator.canonical import EvidenceSource, TemporalQuality, ToolFinding, write_jsonl
from orchestrator.forensics.timeutil import epoch_us_to_iso_ms, parse_iso_utc

ADAPTER_VERSION = "canonical-adapters-v1"
UNKNOWN_TIME = "unknown"


def filter_findings_to_window(
    findings: Iterable[ToolFinding],
    start_iso: str,
    end_iso: str,
    *,
    always_keep: tuple[EvidenceSource, ...] = (EvidenceSource.MEMORY,),
) -> list[ToolFinding]:
    """Scope time-stamped findings to a case window [start, end].

    Drops findings whose timestamp falls outside the window -- on a full disk
    image this removes baseline files created at image-build time, leaving the
    artifacts created during the run. Event findings are judged on their scalar
    ``time``; object findings (no scalar time, MACB metadata under
    ``entity["timestamps"]``) are kept when *any* of their timestamps falls in
    the window. Findings with no usable timestamp at all, and those from
    always_keep sources (memory is point-in-time, not on a creation timeline),
    are kept regardless.
    """
    lo = parse_iso_utc(start_iso)
    hi = parse_iso_utc(end_iso)
    kept: list[ToolFinding] = []
    for finding in findings:
        if finding.source_type in always_keep:
            kept.append(finding)
            continue
        candidates: list[Any] = [finding.time]
        stamps = finding.entity.get("timestamps")
        if isinstance(stamps, dict):
            candidates.extend(stamps.values())
        epochs: list[float] = []
        for value in candidates:
            if not value or value == UNKNOWN_TIME:
                continue
            try:
                epochs.append(parse_iso_utc(str(value)))
            except ValueError:
                continue
        if not epochs or any(lo <= ts <= hi for ts in epochs):
            kept.append(finding)
    return kept


def iso_from_epoch(value: Any) -> str | None:
    if value in (None, "", 0, "0"):
        return None
    try:
        return epoch_us_to_iso_ms(int(float(value) * 1_000_000))
    except (TypeError, ValueError, OverflowError):
        return None


# Plaso's psort json_line stores a normalized top-level timestamp in
# microseconds since the Unix epoch, but some sources/fixtures use seconds.
# Disambiguate by magnitude: modern epoch-seconds are ~1e9, modern epoch-us are
# ~1e15, so a value at or above this threshold is already microseconds.
_PLASO_US_THRESHOLD = 1_000_000_000_000  # 1e12


def iso_from_plaso_timestamp(value: Any) -> str | None:
    if value in (None, "", 0, "0"):
        return None
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    us = v if abs(v) >= _PLASO_US_THRESHOLD else v * 1_000_000
    try:
        return epoch_us_to_iso_ms(us)
    except (ValueError, OverflowError):
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
    # Untimed findings are normal (METHODOLOGY §10.6): keep None as None so it
    # serializes as null; never default to a sentinel value.
    observed_time = None if time in (None, UNKNOWN_TIME) else time
    quality = temporal_quality or (
        TemporalQuality.EXACT if observed_time else TemporalQuality.NONE
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
        finding.time or "",
        finding.tool,
        finding.artifact_class,
        str(finding.entity.get("type")),
        str(finding.entity.get("value")),
        finding.raw_ref,
    )
