"""Runtime context and recorders for declarative scenarios."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchestrator.canonical import (
    ArtifactExpectation,
    EvidenceSource,
    GroundTruthEvent,
    append_jsonl,
    write_jsonl,
)
from orchestrator.scenarios.executors import ScenarioExecutor


class RunContext:
    def __init__(
        self,
        *,
        run_id: str,
        scenario_id: str,
        out_dir: str | Path,
        executor: ScenarioExecutor,
        parameters: dict[str, Any] | None = None,
        repo_root: str | Path | None = None,
    ) -> None:
        self.run_id = run_id
        self.scenario_id = scenario_id
        self.out_dir = Path(out_dir)
        self.work_dir = self.out_dir / "work"
        self.executor = executor
        self.parameters = parameters or {}
        self.repo_root = Path(repo_root) if repo_root is not None else None
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.command_log_path = self.out_dir / "command_log.jsonl"
        self.execution_truth_path = self.out_dir / "execution_truth.jsonl"
        self.artifact_expectations_path = self.out_dir / "artifact_expectations.jsonl"
        self.reference_context_path = self.out_dir / "reference_context.json"
        self._artifact_counter = 0

    def now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def render(self, value: Any) -> Any:
        values = {
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "out_dir": str(self.out_dir),
            "work_dir": str(self.work_dir),
            **self.parameters,
        }
        if isinstance(value, str):
            return value.format_map(_SafeFormat(values))
        if isinstance(value, list):
            return [self.render(v) for v in value]
        if isinstance(value, dict):
            return {k: self.render(v) for k, v in value.items()}
        return value

    def log_step(self, row: dict[str, Any]) -> None:
        row = {"run_id": self.run_id, "scenario_id": self.scenario_id, **row}
        with self.command_log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    def record_truth(self, step_id: str, data: dict[str, Any]) -> GroundTruthEvent:
        rendered = self.render(data)
        record = GroundTruthEvent(
            run_id=self.run_id,
            scenario_id=self.scenario_id,
            step_id=step_id,
            event_type=rendered["event_type"],
            object_type=rendered["object_type"],
            object_identity=str(rendered["object_identity"]),
            action=rendered["action"],
            actor=rendered.get("actor", "attacker"),
            time=rendered.get("time") or self.now(),
            evidence_basis=[EvidenceSource(x) for x in rendered.get("evidence_basis", ["unknown"])],
            attck=[str(x) for x in rendered.get("attck", [])],
            details=dict(rendered.get("details") or {}),
        )
        append_jsonl(self.execution_truth_path, record)
        return record

    def record_artifact(self, step_id: str, data: dict[str, Any]) -> ArtifactExpectation:
        record = self._artifact_record(step_id, data)
        append_jsonl(self.artifact_expectations_path, record)
        return record

    def write_artifact_expectations(self, rows: list[dict[str, Any]]) -> None:
        records = [
            self._artifact_record(str(row.get("step_id") or "scenario"), row)
            for row in rows
        ]
        write_jsonl(self.artifact_expectations_path, records)

    def _artifact_record(self, step_id: str, data: dict[str, Any]) -> ArtifactExpectation:
        self._artifact_counter += 1
        rendered = self.render(data)
        return ArtifactExpectation(
            ae_id=rendered.get("ae_id") or f"{step_id}:AE{self._artifact_counter}",
            scenario_id=self.scenario_id,
            step_id=rendered.get("step_id") or step_id,
            artifact_class=rendered["artifact_class"],
            observable_kind=rendered["observable_kind"],
            source_eligibility=[
                EvidenceSource(x) for x in rendered.get("source_eligibility", ["unknown"])
            ],
            persistence=rendered.get("persistence", "unknown"),
            observability=rendered.get("observability", "expected"),
            instance_constraints=dict(rendered.get("instance_constraints") or {}),
            critical=bool(rendered.get("critical", False)),
            attck=[str(x) for x in rendered.get("attck", [])],
            notes=str(rendered.get("notes") or ""),
        )

    def write_reference_context(
        self,
        *,
        acquisition_method: str = "none",
        guest: dict[str, Any] | None = None,
        acquisition: dict[str, Any] | None = None,
        tool_versions: dict[str, Any] | None = None,
        volatility: dict[str, Any] | None = None,
    ) -> None:
        guest_block = {
            "distro": None,
            "kernel": None,
            "timezone": "UTC",
            "hostname": None,
            "user": None,
        }
        guest_block.update(guest or {})
        acquisition_block = {
            "method": acquisition_method,
            "disk_preparation": None,
            "created_at": None,
            "memory_image": None,
            "disk_image": None,
        }
        acquisition_block.update(acquisition or {})
        data = {
            "schema": "forensic-lab.reference_context.v1",
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "guest": guest_block,
            "acquisition": acquisition_block,
            "tool_versions": tool_versions or {},
            "volatility": volatility or {"symbols": None, "profile": None},
            "git_commit": _git_commit(self.repo_root),
        }
        self.reference_context_path.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


class _SafeFormat(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def _git_commit(repo_root: Path | None) -> str | None:
    if repo_root is None:
        return None
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout.strip() if res.returncode == 0 else None
