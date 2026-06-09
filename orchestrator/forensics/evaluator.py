# orchestrator/forensics/evaluator.py
#
# Turns a raw detection report (see ioc_detector.detect_iocs_for_run) into
# per-step metrics for one run, then persists them as
# acquisitions/<run_id>/forensics_report.json.
#
# Each step is scored from its primary artifacts: did at least one survive
# (recovered), which tools saw it (tool_hits), and how well each survived
# (status -> quality, which metrics.py averages into QoR). Across steps the
# evaluator also checks temporal consistency: that the recovered artifacts'
# timestamps respect the attack's step order.

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchestrator.forensics.ioc_detector import (
    DISK_STATUS_PRESENT,
    DISK_STATUS_DELETED_RECOVERED,
    DISK_STATUS_DELETED_ENTRY_ONLY,
)

_log = logging.getLogger(__name__)

_TOOLS = ("sleuthkit", "vol3", "plaso")

# Tool is inferred from artifact_type, not declared in specs.
# The detector already routes on artifact_type; this mapping keeps the
# evaluator consistent with that decision without re-reading spec["tool"].
_ARTIFACT_TYPE_TO_TOOL: dict[str, str] = {
    "disk": "sleuthkit",
    "memory": "vol3",
    "timeline": "plaso",
}

# The single deletion policy: status -> recovery quality, averaged into QoR.
# Content present or fully recovered is worth 1.0; a bare tombstone (entry-only)
# is a weaker trace at 0.5. Memory/timeline only ever yield present/not_found.
STATUS_QUALITY: dict[str, float] = {
    DISK_STATUS_PRESENT: 1.0,
    DISK_STATUS_DELETED_RECOVERED: 1.0,
    DISK_STATUS_DELETED_ENTRY_ONLY: 0.5,
}


def evaluate_run(
    run_id: str,
    scenario_id: str,
    ground_truth: dict[str, Any],
    detection_report: dict[str, Any],
    specs: list[dict[str, Any]],
    acquisitions_dir: Path | None = None,
) -> dict[str, Any]:
    # acquisitions_dir lets callers (tests, a future orchestrator step) point
    # the report somewhere explicit; default keeps the documented layout.
    if acquisitions_dir is None:
        acquisitions_dir = Path("acquisitions") / run_id

    specs_by_step: dict[str, list[dict[str, Any]]] = {}
    for spec in specs:
        specs_by_step.setdefault(spec["step"], []).append(spec)

    report: dict[str, Any] = {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "steps": {},
    }

    detection_steps = detection_report.get("steps", {})
    for step in ground_truth.get("steps", []):
        step_name = step.get("step")
        if step_name is None:
            continue
        step_specs = specs_by_step.get(step_name, [])
        artifacts = detection_steps.get(step_name, {}).get("artifacts", {})
        report["steps"][step_name] = _evaluate_step(step, step_specs, artifacts)

    report["temporal_consistency"] = _temporal_consistency(ground_truth, report["steps"])

    # Specs whose step never appears in ground truth are silently skipped above.
    # Surface them so a step-name typo reads as a coverage gap, not a clean zero.
    # A cleanup-phase spec with no cleanup step is the expected no-op of a
    # run_cleanup=False run, not a gap, so it is excluded; the key is omitted
    # entirely when nothing genuine is unmatched.
    gt_steps = {s.get("step") for s in ground_truth.get("steps", [])}
    has_cleanup_step = "cleanup" in gt_steps
    unmatched = sorted(
        s["id"]
        for s in specs
        if s["step"] not in gt_steps
        and not (s.get("phase") == "cleanup" and not has_cleanup_step)
    )
    if unmatched:
        _log.warning("specs bound to steps absent from ground truth: %s", unmatched)
        report["unmatched_specs"] = unmatched

    _write_report(report, acquisitions_dir)
    return report


def _evaluate_step(
    step: dict[str, Any],
    step_specs: list[dict[str, Any]],
    artifacts: dict[str, Any],
) -> dict[str, Any]:
    primary_specs = [s for s in step_specs if s.get("primary")]

    found_primary: list[str] = []
    missing_primary: list[str] = []
    for spec in primary_specs:
        if artifacts.get(spec["id"], {}).get("found"):
            found_primary.append(spec["id"])
        else:
            missing_primary.append(spec["id"])

    recovered = bool(found_primary)

    # Infer which tool would have produced each detection from artifact_type.
    # The spec no longer carries a "tool" field; artifact_type is the single
    # source of truth for routing (matching how ioc_detector._detect_artifact
    # already dispatches on artifact_type, never on spec["tool"]).
    tool_hits = {tool: False for tool in _TOOLS}
    for spec in step_specs:
        inferred_tool = _ARTIFACT_TYPE_TO_TOOL.get(spec.get("artifact_type", ""))
        if inferred_tool and artifacts.get(spec["id"], {}).get("found"):
            tool_hits[inferred_tool] = True

    notes = _notes(found_primary, missing_primary)

    # Per-artifact breakdown: an empty list means no specs cover this step, while
    # found=False entries mean the detector ran and saw nothing. status carries
    # the disk recovery state; quality is the status-derived recovery quality
    # (0.0 when not found); evidence is the structured provenance from the
    # detector; timestamp (epoch us) feeds the temporal-order check.
    artifact_details = []
    for spec in step_specs:
        detection = artifacts.get(spec["id"], {})
        found = bool(detection.get("found"))
        status = detection.get("status")
        artifact_details.append(
            {
                "id": spec["id"],
                "phase": spec.get("phase", "attack"),
                "primary": bool(spec.get("primary")),
                "artifact_type": spec.get("artifact_type"),
                "tool": _ARTIFACT_TYPE_TO_TOOL.get(
                    spec.get("artifact_type", ""), "unknown"
                ),
                "found": found,
                "status": status,
                "quality": STATUS_QUALITY.get(status, 0.0) if found else 0.0,
                "evidence": detection.get("evidence"),
                "timestamp": detection.get("timestamp"),
            }
        )

    return {
        "technique": _step_technique(step, step_specs),
        "recovered": recovered,
        "tool_hits": tool_hits,
        "notes": notes,
        "artifacts": artifact_details,
    }


def _temporal_consistency(
    ground_truth: dict[str, Any], report_steps: dict[str, Any]
) -> dict[str, Any]:
    # Each step's representative time is the earliest timestamp among its found
    # artifacts (disk filesystem time or timeline event time; memory artifacts
    # have none). The attack ran the steps in ground_truth order, so a faithful
    # acquisition should show those representative times non-decreasing.
    # Comparison uses <= because consecutive steps run seconds apart and can tie;
    # steps with no timestamped artifact are skipped (they cannot order anything).
    per_step: dict[str, str | None] = {}
    ordered_us: list[int] = []
    for step in ground_truth.get("steps", []):
        step_name = step.get("step")
        if step_name is None:
            continue
        artifacts = report_steps.get(step_name, {}).get("artifacts", [])
        stamps = [
            a["timestamp"]
            for a in artifacts
            if a.get("found") and isinstance(a.get("timestamp"), int)
        ]
        if stamps:
            rep = min(stamps)
            per_step[step_name] = _epoch_us_to_iso(rep)
            ordered_us.append(rep)
        else:
            per_step[step_name] = None

    if len(ordered_us) < 2:
        consistent: bool | None = None  # not enough timestamped steps to judge
    else:
        consistent = all(a <= b for a, b in zip(ordered_us, ordered_us[1:]))
    return {"consistent": consistent, "per_step": per_step}


def _epoch_us_to_iso(ts_us: int) -> str:
    return datetime.fromtimestamp(ts_us / 1_000_000, timezone.utc).isoformat()


def _notes(found_primary: list[str], missing_primary: list[str]) -> str:
    found_part = (
        "Found primary artifacts: " + ", ".join(found_primary)
        if found_primary
        else "No primary artifacts found"
    )
    missing_part = "; missing: " + ", ".join(missing_primary) if missing_primary else ""
    return found_part + missing_part


def _step_technique(step: dict[str, Any], step_specs: list[dict[str, Any]]) -> str:
    # Prefer the technique the scenario recorded; fall back to the spec list so
    # steps without a recorded technique (e.g. "cleanup") still get labelled.
    technique = step.get("technique")
    if technique:
        return technique
    for spec in step_specs:
        if spec.get("technique"):
            return spec["technique"]
    return ""


def _write_report(report: dict[str, Any], acquisitions_dir: Path) -> None:
    acquisitions_dir.mkdir(parents=True, exist_ok=True)
    out_path = acquisitions_dir / "forensics_report.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
