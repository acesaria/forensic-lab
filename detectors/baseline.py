"""Clean-baseline known-good filtering of canonical ToolFinding rows.

Consumes ToolFinding rows from an already-acquired clean baseline and drops
run findings whose per-source signature is present in the baseline. It does
not acquire a baseline, manage cache directories, or read ground truth.

Source families are never merged: a disk object is vouched only by an
identical baseline disk object, a timeline event only by an identical
baseline event. Memory rows always pass through — Volatility observations
come from a different boot (pids, addresses, sockets all differ), so row
equality across boots is meaningless.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable

from orchestrator.canonical import EvidenceSource, ToolFinding, load_jsonl, write_jsonl

_log = logging.getLogger(__name__)

_FILTERED_SOURCES = (EvidenceSource.DISK, EvidenceSource.TIMELINE)


def apply_baseline_filter(
    findings: Iterable[ToolFinding],
    baseline_findings_path: str | Path,
    out_dir: str | Path,
    *,
    identity: str,
) -> tuple[Path, dict[str, Any]]:
    """Filter ``findings`` and persist the two filter artifacts in ``out_dir``.

    Writes ``tool_findings_filtered.jsonl`` (rows keep their canonical ids so
    claims still resolve against the unfiltered stream at match time) and
    ``baseline_filter.json``; returns ``(filtered_path, stats)``.
    """
    out_dir = Path(out_dir)
    kept, stats = filter_findings_against_baseline(
        findings,
        load_jsonl(baseline_findings_path, ToolFinding),
        identity=identity,
    )
    filtered_path = write_jsonl(out_dir / "tool_findings_filtered.jsonl", kept)
    (out_dir / "baseline_filter.json").write_text(
        json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return filtered_path, stats


def filter_findings_against_baseline(
    findings: Iterable[ToolFinding],
    baseline_findings: Iterable[ToolFinding],
    *,
    identity: str,
) -> tuple[list[ToolFinding], dict[str, Any]]:
    """Return ``(kept, stats)``: findings minus exact baseline matches.

    ``stats`` records the baseline identity and per-source pre/post counts;
    it is what metrics block C (METHODOLOGY §6) reports as the
    baseline-differencing effect.
    """
    known_good: dict[EvidenceSource, set[tuple]] = {s: set() for s in _FILTERED_SOURCES}
    for row in baseline_findings:
        if row.source_type in known_good:
            known_good[row.source_type].add(_signature(row))
    if not any(known_good.values()):
        _log.warning(
            "baseline '%s' has no disk/timeline rows; nothing will be filtered",
            identity,
        )

    pre: dict[str, int] = {}
    post: dict[str, int] = {}
    kept: list[ToolFinding] = []
    for row in findings:
        source = row.source_type.value
        pre[source] = pre.get(source, 0) + 1
        signatures = known_good.get(row.source_type)
        if signatures is not None and _signature(row) in signatures:
            continue
        post[source] = post.get(source, 0) + 1
        kept.append(row)

    stats = {
        "identity": identity,
        "per_source": {
            source: {"pre": count, "post": post.get(source, 0)}
            for source, count in sorted(pre.items())
        },
    }
    return kept, stats


def _signature(finding: ToolFinding) -> tuple:
    entity = finding.entity
    if finding.source_type is EvidenceSource.TIMELINE:
        return (
            finding.artifact_class,
            entity.get("type"),
            entity.get("value"),
            finding.time,
            entity.get("time_kind"),
        )
    # Disk objects: identity + content fields. atime is excluded on purpose —
    # a benign file merely read during the case window is still the baseline
    # object. Symlinks keep the adapter's "path -> target" value string, so a
    # retargeted link changes signature. ponytail: same-size in-place edits
    # with unchanged mtime/ctime evade this; per-file content hashing if
    # anti-forensics ever enters scope.
    stamps = entity.get("timestamps")
    stamps = stamps if isinstance(stamps, dict) else {}
    return (
        finding.artifact_class,
        entity.get("type"),
        entity.get("value"),
        entity.get("inode"),
        entity.get("mode"),
        entity.get("size"),
        bool(entity.get("deleted")),
        bool(entity.get("reallocated")),
        stamps.get("mtime"),
        stamps.get("ctime"),
        stamps.get("crtime"),
    )
