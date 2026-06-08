# orchestrator/forensics/evaluator.py
#
# Turns a raw detection report (see ioc_detector.detect_iocs_for_run) into
# per-step metrics for one run, then persists them as
# acquisitions/<run_id>/forensics_report.json.
#
# This first version scores each attack step independently: did at least one
# primary artifact survive, which tools saw it, and how confident are we. No
# cross-step time-ordering checks yet.

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from orchestrator.forensics.ioc_detector import (
    DISK_STATUS_PRESENT,
    DISK_STATUS_DELETED_RECOVERED,
    DISK_STATUS_DELETED_ENTRY_ONLY,
)

_log = logging.getLogger(__name__)

_TOOLS = ("sleuth", "vol3", "plaso")

# Tool is inferred from artifact_type, not declared in specs.
# The detector already routes on artifact_type; this mapping keeps the
# evaluator consistent with that decision without re-reading spec["tool"].
_ARTIFACT_TYPE_TO_TOOL: dict[str, str] = {
    "disk": "sleuth",
    "memory": "vol3",
    "timeline": "plaso",
}

# Disk recovery state scales a found primary's base_weight: an intact file is
# worth its full weight, a recovered deletion less, a tombstone-as-evidence
# (only reachable when a spec opts deleted_entry_only in as found) least.
# Memory/timeline detections have no status and fall through to factor 1.0,
# so their scoring is unchanged.
_STATUS_CONFIDENCE_FACTOR = {
    DISK_STATUS_PRESENT: 1.0,
    DISK_STATUS_DELETED_RECOVERED: 0.7,
    DISK_STATUS_DELETED_ENTRY_ONLY: 0.3,
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

    # Specs whose step never appears in ground truth are silently skipped above.
    # Surface them so a step-name typo reads as a coverage gap, not a clean zero.
    gt_steps = {s.get("step") for s in ground_truth.get("steps", [])}
    unmatched = sorted(s["id"] for s in specs if s["step"] not in gt_steps)
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
    found_weights: list[float] = []
    for spec in primary_specs:
        detection = artifacts.get(spec["id"], {})
        if detection.get("found"):
            found_primary.append(spec["id"])
            factor = _STATUS_CONFIDENCE_FACTOR.get(detection.get("status"), 1.0)
            found_weights.append(float(spec["base_weight"]) * factor)
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

    confidence = _confidence(found_weights)
    notes = _notes(found_primary, missing_primary)

    # Per-artifact breakdown so a zero confidence is explainable: an empty list
    # means no specs cover this step, while found=False entries mean the detector
    # ran and saw nothing. status carries the disk recovery state when present.
    artifact_details = [
        {
            "id": spec["id"],
            "phase": spec.get("phase", "attack"),
            "primary": bool(spec.get("primary")),
            "artifact_type": spec.get("artifact_type"),
            "tool": _ARTIFACT_TYPE_TO_TOOL.get(
                spec.get("artifact_type", ""), "unknown"
            ),
            "found": bool(artifacts.get(spec["id"], {}).get("found")),
            "status": artifacts.get(spec["id"], {}).get("status"),
            "matched_by": artifacts.get(spec["id"], {}).get("matched_by"),
        }
        for spec in step_specs
    ]

    return {
        "technique": _step_technique(step, step_specs),
        "recovered": recovered,
        "tool_hits": tool_hits,
        "confidence": confidence,
        "notes": notes,
        "artifacts": artifact_details,
    }


def _confidence(found_weights: list[float]) -> float:
    # Confidence is the mean base_weight of the primary artifacts that were
    # actually recovered. Recovering more than one primary artifact for a step
    # is corroborating evidence, so add a small fixed boost, capped at 1.0.
    # No found primaries means no confidence.
    if not found_weights:
        return 0.0
    base = sum(found_weights) / len(found_weights)
    if len(found_weights) > 1:
        base += 0.1
    return round(min(base, 1.0), 3)


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
