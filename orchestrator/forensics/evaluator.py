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
from pathlib import Path
from typing import Any

_TOOLS = ("sleuth", "vol3", "plaso")


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
            found_weights.append(float(spec["base_weight"]))
        else:
            missing_primary.append(spec["id"])

    recovered = bool(found_primary)

    tool_hits = {tool: False for tool in _TOOLS}
    for spec in step_specs:
        tool = spec["tool"]
        if tool not in tool_hits:
            continue
        if artifacts.get(spec["id"], {}).get("found"):
            tool_hits[tool] = True

    confidence = _confidence(found_weights)
    notes = _notes(found_primary, missing_primary)

    return {
        "technique": _step_technique(step, step_specs),
        "recovered": recovered,
        "tool_hits": tool_hits,
        "confidence": confidence,
        "notes": notes,
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
    missing_part = (
        "; missing: " + ", ".join(missing_primary) if missing_primary else ""
    )
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
