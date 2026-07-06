"""Shared helpers for canonical tool-output adapters."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from orchestrator.canonical import EvidenceSource, ToolFinding, write_jsonl
from orchestrator.forensics.timeutil import epoch_us_to_iso_ms, iso_utc_ms, parse_iso_utc

ADAPTER_VERSION = "canonical-adapters-v1"

_SERVICE_DIRS = (
    "/etc/systemd/",
    "/usr/lib/systemd/",
    "/lib/systemd/",
)
_SERVICE_SUFFIXES = (".service", ".timer", ".socket", ".path", ".mount")


def classify_fs_path(path: str) -> str:
    """Classify a filesystem path using the closed section 5 vocabulary."""
    if "ld.so.preload" in path or path.endswith(".preload"):
        return "preload_configuration"
    if path.endswith(".so") or ".so." in path:
        return "shared_object"
    if "preload" in path.rsplit("/", 1)[-1]:
        return "preload_configuration"
    if any(path.startswith(d) for d in _SERVICE_DIRS) and path.endswith(_SERVICE_SUFFIXES):
        return "service_unit_file"
    return "file"


def case_window_from_command_log(
    log_path, margin_s: float = 600.0
) -> tuple[str, str] | None:
    """Derive [start, end] from the scenario command_log step times, padded by
    a margin. Returns None if the log is missing or has no usable times."""
    if not log_path.is_file():
        return None
    times: list[float] = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        for key in ("started_at", "ended_at"):
            value = row.get(key)
            if value:
                try:
                    times.append(parse_iso_utc(str(value)))
                except ValueError:
                    pass
    if not times:
        return None
    lo = datetime.fromtimestamp(min(times) - margin_s, timezone.utc)
    hi = datetime.fromtimestamp(max(times) + margin_s, timezone.utc)
    return iso_utc_ms(lo), iso_utc_ms(hi)


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
            if not value:
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
) -> ToolFinding:
    # Untimed findings are normal (METHODOLOGY §10.6): time stays None so it
    # serializes as null; never a sentinel value.
    return ToolFinding(
        # placeholder; write_tool_findings/assign_tool_finding_ids assigns the
        # canonical final id.
        finding_id="tf-unassigned",
        run_id=run_id,
        tool=tool,
        tool_version=tool_version,
        adapter_version=adapter_version,
        source_type=source_type,
        artifact_class=artifact_class,
        entity=entity,
        time=time,
        raw_ref=raw_ref,
        provenance=provenance,
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
