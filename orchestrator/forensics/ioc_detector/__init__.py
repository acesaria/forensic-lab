# orchestrator/forensics/ioc_detector/__init__.py
#
# Generic IOC detector. Given a run's acquisitions plus a list of ArtifactSpec
# dicts (see artifact_specs.py), it drives the forensics tools and reports, per
# artifact: whether it was found, its disk recovery status, a structured
# `evidence` record (tool/method/locator/match), an optional timestamp, and the
# raw matches that backed the call. Scoring lives in evaluator.py -- this layer
# only reports observations.
#
# One module per tool: sleuthkit.py (disk), volatility.py (memory), plaso.py
# (timeline). artifact_type routes a spec to its tool here; status.py holds the
# shared vocabulary, context.py the per-run resources/caches, recovery.py the
# disk content-recovery chain.

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from orchestrator.forensics.ioc_detector.context import DetectorContext
from orchestrator.forensics.ioc_detector.plaso import detect_timeline, path_timeline_ts
from orchestrator.forensics.ioc_detector.sleuthkit import detect_disk
from orchestrator.forensics.ioc_detector.status import (
    DISK_STATUS_DELETED_ENTRY_ONLY,
    DISK_STATUS_DELETED_RECOVERED,
    DISK_STATUS_NOT_FOUND,
    DISK_STATUS_PRESENT,
    DISK_STATUSES,
    empty_detection,
)
from orchestrator.forensics.ioc_detector.volatility import (
    MEMORY_CATEGORY_PLUGINS,
    detect_memory,
)

# artifact_type -> the tool detector that owns it. Adding a tool/type is one
# entry here plus its module; nothing else dispatches on artifact_type.
_DETECTORS: dict[str, Callable[[dict[str, Any], DetectorContext], dict[str, Any]]] = {
    "disk": detect_disk,
    "memory": detect_memory,
    "timeline": detect_timeline,
}

__all__ = [
    "detect_iocs_for_run",
    "DetectorContext",
    "MEMORY_CATEGORY_PLUGINS",
    "DISK_STATUS_NOT_FOUND",
    "DISK_STATUS_DELETED_ENTRY_ONLY",
    "DISK_STATUS_DELETED_RECOVERED",
    "DISK_STATUS_PRESENT",
    "DISK_STATUSES",
    "empty_detection",
]


def _detect_artifact(spec: dict[str, Any], ctx: DetectorContext) -> dict[str, Any]:
    detector = _DETECTORS.get(spec["artifact_type"])
    return detector(spec, ctx) if detector else empty_detection()


def detect_iocs_for_run(
    run_id: str,
    ground_truth: dict[str, Any],
    specs: list[dict[str, Any]],
    sleuth,
    vol,
    disk_path: Path,
    memory_path: Path,
    distro_id: str,
    timeline_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    ctx = DetectorContext(
        sleuth=sleuth,
        vol=vol,
        disk_path=disk_path,
        memory_path=memory_path,
        distro_id=distro_id,
        timeline_events=timeline_events,
    )

    specs_by_step: dict[str, list[dict[str, Any]]] = {}
    for spec in specs:
        specs_by_step.setdefault(spec["step"], []).append(spec)

    steps_report: dict[str, Any] = {}
    for step in ground_truth.get("steps", []):
        step_name = step.get("step")
        if step_name is None:
            continue
        artifacts: dict[str, Any] = {}
        for spec in specs_by_step.get(step_name, []):
            detection = _detect_artifact(spec, ctx)
            # Disk artifacts carry no inherent time; borrow the filesystem
            # mtime/creation for the recovered path from the Plaso timeline so
            # every disk and timeline artifact shares one epoch-us clock for the
            # evaluator's ordering check. Memory artifacts stay timestampless.
            if (
                spec["artifact_type"] == "disk"
                and detection.get("found")
                and detection.get("evidence")
            ):
                detection["timestamp"] = path_timeline_ts(
                    timeline_events, detection["evidence"]["locator"]
                )
            artifacts[spec["id"]] = detection
        steps_report[step_name] = {"artifacts": artifacts}

    return {"run_id": run_id, "steps": steps_report}
