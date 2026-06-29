"""Conservative clean-baseline comparison for GT-blind detector output.

This module consumes canonical ToolFinding rows from an already-acquired clean
baseline run. It does not acquire a baseline, create cache directories, or read
scenario ground truth.
"""

from __future__ import annotations

import logging
from collections import Counter
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
class PathBaselineStatus:
    path: str
    status: str
    compared_fields: tuple[str, ...] = ()
    baseline_record_count: int = 0


@dataclass(frozen=True)
class BaselineComparison:
    identity: str
    baseline_path_count: int
    compromised_path_count: int
    status_by_path: dict[str, PathBaselineStatus]
    status_counts: dict[str, int]


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
    status_by_path: dict[str, PathBaselineStatus] = {}

    for path, current_rows in sorted(current_index.items()):
        baseline_rows = baseline_index.get(path, [])
        if not baseline_rows:
            status_by_path[path] = PathBaselineStatus(
                path=path,
                status=BASELINE_NEW,
                compared_fields=(),
                baseline_record_count=0,
            )
            continue
        status, fields = _compare_rows(baseline_rows, current_rows)
        status_by_path[path] = PathBaselineStatus(
            path=path,
            status=status,
            compared_fields=fields,
            baseline_record_count=len(baseline_rows),
        )

    counts = Counter(row.status for row in status_by_path.values())
    for status in (BASELINE_NEW, BASELINE_CHANGED, BASELINE_PRESENT, BASELINE_UNKNOWN):
        counts.setdefault(status, 0)
    return BaselineComparison(
        identity=identity,
        baseline_path_count=len(baseline_index),
        compromised_path_count=len(current_index),
        status_by_path=status_by_path,
        status_counts=dict(sorted(counts.items())),
    )


def apply_baseline_to_claims(
    claims: Iterable[DetectionClaim],
    compromised_findings: Iterable[ToolFinding],
    baseline_findings: Iterable[ToolFinding],
    *,
    identity: str,
) -> list[DetectionClaim]:
    findings = list(compromised_findings)
    by_id = {finding.finding_id: finding for finding in findings}
    comparison = compare_path_baseline(
        baseline_findings,
        findings,
        identity=identity,
    )
    out: list[DetectionClaim] = []
    for claim in claims:
        path = _claim_path(claim)
        status = comparison.status_by_path.get(path) if path else None
        if status is None:
            out.append(_with_unknown_baseline(claim, comparison))
            continue
        updated = _with_baseline_status(claim, status, comparison)
        if _should_downgrade_present_baseline_candidate(updated, by_id):
            updated = _downgrade_claim(updated)
        out.append(updated)
    return out


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
) -> tuple[str, tuple[str, ...]]:
    comparable = _comparable_fields(baseline_rows, current_rows)
    if not comparable:
        return BASELINE_PRESENT, ()
    aliases = dict(_COMPARE_FIELDS)
    for current in current_rows:
        for baseline in baseline_rows:
            if all(
                _logical_value(current, aliases[field]) == _logical_value(baseline, aliases[field])
                for field in comparable
            ):
                return BASELINE_PRESENT, comparable
    return BASELINE_CHANGED, comparable


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


def _with_baseline_status(
    claim: DetectionClaim,
    status: PathBaselineStatus,
    comparison: BaselineComparison,
) -> DetectionClaim:
    entity = dict(claim.entity)
    entity["baseline"] = {
        "identity": comparison.identity,
        "status": status.status,
        "path": status.path,
        "compared_fields": list(status.compared_fields),
        "baseline_record_count": status.baseline_record_count,
        "baseline_path_count": comparison.baseline_path_count,
        "compromised_path_count": comparison.compromised_path_count,
        "status_counts": comparison.status_counts,
        "filter_action": "none",
    }
    return _replace_claim(claim, entity=entity)


def _with_unknown_baseline(
    claim: DetectionClaim,
    comparison: BaselineComparison,
) -> DetectionClaim:
    entity = dict(claim.entity)
    entity["baseline"] = {
        "identity": comparison.identity,
        "status": BASELINE_UNKNOWN,
        "path": None,
        "compared_fields": [],
        "baseline_record_count": 0,
        "baseline_path_count": comparison.baseline_path_count,
        "compromised_path_count": comparison.compromised_path_count,
        "status_counts": comparison.status_counts,
        "filter_action": "none",
    }
    return _replace_claim(claim, entity=entity)


def _should_downgrade_present_baseline_candidate(
    claim: DetectionClaim,
    findings_by_id: dict[str, ToolFinding],
) -> bool:
    baseline = claim.entity.get("baseline")
    if not isinstance(baseline, dict) or baseline.get("status") != BASELINE_PRESENT:
        return False
    linked = [findings_by_id[fid] for fid in claim.source_findings if fid in findings_by_id]
    if not linked:
        return False
    sources = {finding.source_type for finding in linked}
    return sources == {EvidenceSource.TIMELINE}


def _downgrade_claim(claim: DetectionClaim) -> DetectionClaim:
    capped = min(float(claim.confidence), 0.35)
    if capped >= float(claim.confidence):
        # Confidence already at or below the cap: nothing to downgrade, so leave
        # filter_action='none' rather than inflating candidate_downgrades.
        return claim
    entity = dict(claim.entity)
    baseline = dict(entity.get("baseline") or {})
    baseline["filter_action"] = "confidence_downgraded"
    entity["baseline"] = baseline
    notes = claim.notes
    marker = "baseline_present_timeline_only=confidence_downgraded"
    if marker not in notes:
        notes = f"{notes}; {marker}" if notes else marker
    return _replace_claim(
        claim,
        entity=entity,
        confidence=capped,
        notes=notes,
    )


def _replace_claim(
    claim: DetectionClaim,
    *,
    entity: dict[str, Any],
    confidence: float | None = None,
    notes: str | None = None,
) -> DetectionClaim:
    return DetectionClaim(
        claim_id=claim.claim_id,
        run_id=claim.run_id,
        rule_id=claim.rule_id,
        artifact_class=claim.artifact_class,
        entity=entity,
        confidence=claim.confidence if confidence is None else confidence,
        source_findings=list(claim.source_findings),
        attck=list(claim.attck),
        notes=claim.notes if notes is None else notes,
    )


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
