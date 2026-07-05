"""Conservative clean-baseline comparison for GT-blind detector output.

This module consumes canonical ToolFinding rows from an already-acquired clean
baseline run. It does not acquire a baseline, create cache directories, or read
scenario ground truth.

Per-claim output is exactly what metrics block C (METHODOLOGY §6) reads:
``entity["baseline"] = {"status": <status>, "downgraded": <bool>}``. A claim is
downgraded only when its path is present unchanged in the clean baseline and
every linked finding is timeline-sourced — a conservative benign-noise marker
that never drops the claim.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable

from orchestrator.canonical import DetectionClaim, EvidenceSource, ToolFinding
from orchestrator.canonical.baseline_paths import (
    BASELINE_FILESYSTEM_CLASSES,
    normalize_baseline_path,
)

_log = logging.getLogger(__name__)

BASELINE_NEW = "new_vs_baseline"
BASELINE_CHANGED = "changed_vs_baseline"
BASELINE_PRESENT = "present_in_baseline"
BASELINE_UNKNOWN = "unknown_baseline_status"


@dataclass(frozen=True)
class BaselineComparison:
    identity: str
    status_by_path: dict[str, str]


def compare_path_baseline(
    baseline_findings: Iterable[ToolFinding],
    compromised_findings: Iterable[ToolFinding],
    *,
    identity: str,
) -> BaselineComparison:
    baseline_index = _index_findings(baseline_findings)
    current_index = _index_findings(compromised_findings)
    if current_index and not baseline_index:
        _log.warning(
            "baseline '%s' has no comparable filesystem findings; every path will "
            "be reported as %s",
            identity,
            BASELINE_NEW,
        )
    status_by_path = {
        path: _compare_rows(baseline_index[path], rows)
        if path in baseline_index
        else BASELINE_NEW
        for path, rows in current_index.items()
    }
    return BaselineComparison(identity=identity, status_by_path=status_by_path)


def apply_baseline_to_claims(
    claims: Iterable[DetectionClaim],
    compromised_findings: Iterable[ToolFinding],
    baseline_findings: Iterable[ToolFinding],
    *,
    identity: str,
) -> list[DetectionClaim]:
    findings = list(compromised_findings)
    by_id = {finding.finding_id: finding for finding in findings}
    comparison = compare_path_baseline(baseline_findings, findings, identity=identity)
    out = list(claims)
    for claim in out:
        path = _claim_path(claim)
        status = comparison.status_by_path.get(path, BASELINE_UNKNOWN) if path else BASELINE_UNKNOWN
        claim.entity["baseline"] = {
            "status": status,
            "downgraded": status == BASELINE_PRESENT and _timeline_only(claim, by_id),
        }
    return out


def _timeline_only(claim: DetectionClaim, findings_by_id: dict[str, ToolFinding]) -> bool:
    linked = [findings_by_id[fid] for fid in claim.source_findings if fid in findings_by_id]
    return bool(linked) and {finding.source_type for finding in linked} == {EvidenceSource.TIMELINE}


def _index_findings(findings: Iterable[ToolFinding]) -> dict[str, list[ToolFinding]]:
    out: dict[str, list[ToolFinding]] = {}
    for finding in findings:
        if finding.artifact_class not in BASELINE_FILESYSTEM_CLASSES:
            continue
        path = _finding_path(finding)
        if not path:
            continue
        out.setdefault(path, []).append(finding)
    return out


# Content fields used to decide whether a path's bytes changed against the
# baseline. ``size`` and ``size_bytes`` are the same quantity under two adapter
# names, so they collapse to one logical field; otherwise a baseline that
# records ``size`` never compares against a run that records ``size_bytes`` and a
# genuinely changed file is misreported as present_in_baseline.
_COMPARE_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sha256", ("sha256",)),
    ("size", ("size", "size_bytes")),
)


def _compare_rows(
    baseline_rows: list[ToolFinding],
    current_rows: list[ToolFinding],
) -> str:
    comparable = _comparable_fields(baseline_rows, current_rows)
    if not comparable:
        return BASELINE_PRESENT
    aliases = dict(_COMPARE_FIELDS)
    for current in current_rows:
        for baseline in baseline_rows:
            if all(
                _logical_value(current, aliases[field]) == _logical_value(baseline, aliases[field])
                for field in comparable
            ):
                return BASELINE_PRESENT
    return BASELINE_CHANGED


def _comparable_fields(
    baseline_rows: list[ToolFinding],
    current_rows: list[ToolFinding],
) -> tuple[str, ...]:
    fields: list[str] = []
    for field, aliases in _COMPARE_FIELDS:
        if any(_logical_value(row, aliases) is not None for row in baseline_rows) and any(
            _logical_value(row, aliases) is not None for row in current_rows
        ):
            fields.append(field)
    return tuple(fields)


def _logical_value(finding: ToolFinding, aliases: tuple[str, ...]) -> Any:
    for field in aliases:
        value = _entity_value(finding, field)
        if value not in (None, ""):
            return value
    return None


def _claim_path(claim: DetectionClaim) -> str:
    entity = claim.entity
    direct = normalize_baseline_path(entity.get("path") or entity.get("value"))
    if direct:
        return direct
    for key in ("library", "process", "file", "source"):
        value = entity.get(key)
        if isinstance(value, dict):
            path = normalize_baseline_path(value.get("path") or value.get("value"))
            if path:
                return path
    return ""


def _finding_path(finding: ToolFinding) -> str:
    entity = finding.entity
    return normalize_baseline_path(entity.get("path") or entity.get("value"))


def _entity_value(finding: ToolFinding, field: str) -> Any:
    if field in finding.entity:
        return finding.entity.get(field)
    return finding.provenance.get(field)
