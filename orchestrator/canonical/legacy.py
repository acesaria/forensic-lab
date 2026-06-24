"""Soft migration from existing gt_manifest.json to canonical run artifacts."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from orchestrator.canonical.io import write_jsonl
from orchestrator.canonical.models import (
    ArtifactExpectation,
    EvidenceSource,
    GroundTruthEvent,
)
from orchestrator.evaluation.contracts.models import GtEvent, GtManifest, Observable
from orchestrator.evaluation.contracts.validate import load_gt_manifest

CANONICAL_EXECUTION_TRUTH = "execution_truth.jsonl"
CANONICAL_ARTIFACT_EXPECTATIONS = "artifact_expectations.jsonl"
CANONICAL_REFERENCE_CONTEXT = "reference_context.json"


def load_legacy_manifest(path: str | Path) -> GtManifest:
    return GtManifest.from_dict(load_gt_manifest(path))


def write_canonical_from_legacy(
    gt_manifest_path: str | Path,
    out_dir: str | Path,
    *,
    acquisition_manifest_path: str | Path | None = None,
    repo_root: str | Path | None = None,
    tool_versions: dict[str, Any] | None = None,
    volatility_symbols: dict[str, Any] | None = None,
) -> dict[str, Path]:
    manifest = load_legacy_manifest(gt_manifest_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    execution_truth = list(execution_truth_from_manifest(manifest))
    expectations = list(artifact_expectations_from_manifest(manifest))
    context = reference_context_from_manifest(
        manifest,
        acquisition_manifest_path=acquisition_manifest_path,
        repo_root=repo_root,
        tool_versions=tool_versions,
        volatility_symbols=volatility_symbols,
    )

    execution_path = write_jsonl(out / CANONICAL_EXECUTION_TRUTH, execution_truth)
    expectations_path = write_jsonl(out / CANONICAL_ARTIFACT_EXPECTATIONS, expectations)
    context_path = out / CANONICAL_REFERENCE_CONTEXT
    context_path.write_text(json.dumps(context, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "execution_truth": execution_path,
        "artifact_expectations": expectations_path,
        "reference_context": context_path,
    }


def execution_truth_from_manifest(manifest: GtManifest) -> list[GroundTruthEvent]:
    return [_truth_event(manifest, event) for event in manifest.events]


def artifact_expectations_from_manifest(manifest: GtManifest) -> list[ArtifactExpectation]:
    out: list[ArtifactExpectation] = []
    for event in manifest.events:
        observables = event.observables or [
            Observable(
                operation="timeline",
                source_tool="tsk",
                entity_type=event.entity.type,
                entity_value=str(event.entity.value),
            )
        ]
        step_id = _step_id(event)
        for idx, observable in enumerate(observables, start=1):
            out.append(
                ArtifactExpectation(
                    ae_id=f"{event.gt_id}:AE{idx}",
                    scenario_id=manifest.scenario_id,
                    step_id=step_id,
                    artifact_class=event.event_class,
                    observable_kind=observable.entity_type,
                    source_eligibility=[_evidence_source(observable.operation, observable.source_tool)],
                    persistence=_persistence_for(event, observable),
                    observability="expected",
                    instance_constraints={
                        "entity_type": observable.entity_type,
                        "entity_value": observable.entity_value,
                        "operation": observable.operation,
                        "source_tool": observable.source_tool,
                        "time_hint": observable.time_hint,
                    },
                    critical=True,
                    attck=[event.technique],
                    notes=f"derived from legacy gt_manifest event {event.gt_id}",
                )
            )
    return out


def reference_context_from_manifest(
    manifest: GtManifest,
    *,
    acquisition_manifest_path: str | Path | None = None,
    repo_root: str | Path | None = None,
    tool_versions: dict[str, Any] | None = None,
    volatility_symbols: dict[str, Any] | None = None,
) -> dict[str, Any]:
    acquisition = _load_json_file(acquisition_manifest_path)
    return {
        "schema": "forensic-lab.reference_context.v1",
        "run_id": manifest.run_id,
        "scenario_id": manifest.scenario_id,
        "guest": {
            "distro": manifest.distro,
            "kernel": None,
            "timezone": manifest.timezone,
            "hostname": None,
            "user": "labuser",
        },
        "acquisition": {
            "method": acquisition.get("disk_acquisition_mode"),
            "disk_preparation": acquisition.get("disk_preparation"),
            "created_at": acquisition.get("created_at"),
            "memory_image": _image_context(acquisition.get("memory_image")),
            "disk_image": _image_context(acquisition.get("disk_image")),
        },
        "tool_versions": tool_versions or {},
        "volatility": volatility_symbols or {"symbols": None, "profile": None},
        "git_commit": _git_commit(repo_root),
        "legacy": {
            "gt_manifest": True,
            "random_seed": manifest.random_seed,
            "cleanup": manifest.cleanup,
        },
    }


def _truth_event(manifest: GtManifest, event: GtEvent) -> GroundTruthEvent:
    return GroundTruthEvent(
        run_id=manifest.run_id,
        scenario_id=manifest.scenario_id,
        step_id=_step_id(event),
        event_type=event.event_class,
        object_type=event.entity.type,
        object_identity=str(event.entity.value),
        action=_action_for(event.event_class),
        actor="attacker",
        time=event.ts_utc,
        evidence_basis=_event_sources(event),
        attck=[event.technique],
        details={"legacy_gt_id": event.gt_id, **event.details},
    )


def _event_sources(event: GtEvent) -> list[EvidenceSource]:
    sources = {
        _evidence_source(obs.operation, obs.source_tool)
        for obs in event.observables
    }
    if not sources:
        sources = {_source_from_expected(src) for src in event.expected_sources}
    return sorted(sources, key=lambda s: s.value) or [EvidenceSource.UNKNOWN]


def _evidence_source(operation: str, source_tool: str | None = None) -> EvidenceSource:
    if operation == "memory_analysis" or source_tool == "vol3":
        return EvidenceSource.MEMORY
    if operation == "timeline" or source_tool in ("plaso", "plaso_sigma"):
        return EvidenceSource.TIMELINE
    if operation in ("deleted_file", "content_scan") or source_tool in ("tsk", "yara"):
        return EvidenceSource.DISK
    if source_tool in ("syslog", "journal"):
        return EvidenceSource.LOG
    return EvidenceSource.UNKNOWN


def _source_from_expected(value: str) -> EvidenceSource:
    if "memory" in value:
        return EvidenceSource.MEMORY
    if "log" in value:
        return EvidenceSource.LOG
    if "disk" in value or "fs" in value:
        return EvidenceSource.DISK
    return EvidenceSource.UNKNOWN


def _step_id(event: GtEvent) -> str:
    step = event.details.get("step")
    return str(step) if step else event.gt_id


def _action_for(event_class: str) -> str:
    if event_class.endswith("_created"):
        return "create"
    if event_class.endswith("_deleted"):
        return "delete"
    if event_class.endswith("_modified"):
        return "modify"
    if event_class == "process_exec":
        return "execute"
    if event_class == "network_connection":
        return "connect"
    if event_class == "persistence_installed":
        return "install_persistence"
    return event_class


def _persistence_for(event: GtEvent, observable: Observable) -> str:
    if observable.operation == "memory_analysis":
        return "volatile"
    if event.event_class == "file_deleted":
        return "deleted"
    return "unknown"


def _load_json_file(path: str | Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _image_context(obj: Any) -> dict[str, Any] | None:
    if not isinstance(obj, dict):
        return None
    return {
        "path": obj.get("path"),
        "tool": obj.get("tool"),
        "sha256": obj.get("sha256"),
        "size_bytes": obj.get("size_bytes"),
        "segments": obj.get("segments"),
        "virtual_size_bytes": obj.get("virtual_size_bytes"),
        "ewf_size_bytes": obj.get("ewf_size_bytes"),
    }


def _git_commit(repo_root: str | Path | None) -> str | None:
    if repo_root is None:
        return None
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(repo_root),
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout.strip() if res.returncode == 0 else None
