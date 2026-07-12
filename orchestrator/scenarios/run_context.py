"""Runtime context and recorders for declarative scenarios."""

from __future__ import annotations

import getpass
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

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
        prerequisites: dict[str, Any] | None = None,
        scenario_variant: str | None = None,
        distro: str | None = None,
        profile: str | None = None,
        required_privilege: str | None = None,
        repo_root: str | Path | None = None,
        internet_on: Callable[[], None] | None = None,
        internet_off: Callable[[], None] | None = None,
    ) -> None:
        self.run_id = run_id
        self.scenario_id = scenario_id
        self.out_dir = Path(out_dir)
        self.work_dir = self.out_dir / "work"
        self.executor = executor
        self.parameters = parameters or {}
        self.prerequisites = prerequisites or {}
        self.scenario_variant = scenario_variant
        self.distro = distro
        self.profile = profile
        self.required_privilege = required_privilege or "scenario-defined"
        self.repo_root = Path(repo_root) if repo_root is not None else None
        self.internet_on = internet_on
        self.internet_off = internet_off
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.out_dir / "manifest.json"
        self.command_log_path = self.out_dir / "command_log.jsonl"
        self.started_at = self.now()
        self.ended_at: str | None = None
        self.final_status = "running"
        self.execution_user = getpass.getuser()
        self.guest: dict[str, Any] = {}
        self.steps: list[dict[str, Any]] = []
        self.facts: list[dict[str, Any]] = []
        self.outputs: dict[str, Any] = {
            "command_log": str(self.command_log_path),
            "acquisition": {},
            "raw_analysis": {},
        }
        self._acquisition_manifest: dict[str, Any] = {}
        self._write_manifest()

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

    def record_fact(self, step_id: str, data: dict[str, Any]) -> dict[str, Any]:
        rendered = self.render(data)
        fact = {
            "step_id": str(step_id),
            "time": rendered.get("time") or self.now(),
            "fact_type": str(rendered.get("fact_type") or rendered.get("event_type") or "fact"),
        }
        for key in ("actor", "action"):
            if rendered.get(key) is not None:
                fact[key] = rendered[key]
        if rendered.get("object_type") or rendered.get("object_identity"):
            fact["subject"] = {
                "type": rendered.get("object_type"),
                "identity": str(rendered.get("object_identity")),
            }
        if rendered.get("evidence_basis"):
            fact["evidence_basis"] = [str(item) for item in rendered.get("evidence_basis") or []]
        if rendered.get("attck"):
            fact["attck"] = [str(item) for item in rendered.get("attck") or []]
        if rendered.get("details"):
            fact["details"] = dict(rendered.get("details") or {})
        self.facts.append(fact)
        self._write_manifest()
        return fact

    def record_step_status(
        self,
        *,
        step_id: str,
        step_type: str,
        status: str,
        started_at: str,
        ended_at: str,
        error: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        row = {
            "step_id": step_id,
            "type": step_type,
            "status": status,
            "started_at": started_at,
            "ended_at": ended_at,
        }
        if error:
            row["error"] = error
        for key, value in (metadata or {}).items():
            if value is not None:
                row[key] = value
        self.steps.append(row)
        self._write_manifest()

    def finalize(self, status: str, *, error: str | None = None) -> None:
        self.final_status = status
        self.ended_at = self.now()
        if error:
            self.outputs["error"] = error
        self._write_manifest()

    def mark_prevented(self, reason: str, *, step_id: str | None = None) -> None:
        self.final_status = "prevented"
        self.record_fact(
            step_id or "scenario",
            {
                "fact_type": "scenario_prevented",
                "action": "prevent",
                "actor": "platform",
                "details": {"reason": reason},
            },
        )

    def update_environment(
        self,
        *,
        guest: dict[str, Any] | None = None,
        distro: str | None = None,
        profile: str | None = None,
        execution_user: str | None = None,
    ) -> None:
        if guest:
            self.guest.update(guest)
        if distro is not None:
            self.distro = distro
        if profile is not None:
            self.profile = profile
        if execution_user:
            self.execution_user = execution_user
        self._write_manifest()

    def record_acquisition_outputs(self, acquisition_manifest_path: str | Path) -> None:
        path = Path(acquisition_manifest_path)
        manifest = json.loads(path.read_text(encoding="utf-8"))
        self._acquisition_manifest = manifest
        self.outputs["acquisition"] = {
            "manifest": str(path),
            "memory_image": _image_path(manifest.get("memory_image")),
            "disk_image": _image_path(manifest.get("disk_image")),
        }
        self._write_manifest()

    def record_raw_analysis_outputs(self, analysis_dir: str | Path) -> None:
        analysis = Path(analysis_dir)
        outputs = {
            "volatility_json": analysis / "vol3.json",
            "tsk_bodyfile": analysis / "bodyfile",
            "plaso_storage": analysis / "timeline.plaso",
            "plaso_jsonl": analysis / "timeline.jsonl",
        }
        self.outputs["raw_analysis"] = {
            name: str(path) for name, path in outputs.items() if path.exists()
        }
        self._write_manifest()

    def _write_manifest(self) -> None:
        data = {
            "schema": "forensic-lab.run_manifest",
            "version": 1,
            "run_id": self.run_id,
            "scenario": {
                "id": self.scenario_id,
                "variant": self.scenario_variant,
            },
            "platform": {
                "distro": self.distro,
                "profile": self.profile,
            },
            "repository": {
                "commit": _git_commit(self.repo_root),
            },
            "timestamps": {
                "started_at": self.started_at,
                "ended_at": self.ended_at,
            },
            "execution": {
                "user": self.execution_user,
                "required_privilege": self.required_privilege,
            },
            "parameters": self._important_parameters(),
            "steps": self.steps,
            "facts": self.facts,
            "status": self.final_status,
            "outputs": self.outputs,
        }
        if self.guest:
            data["guest"] = self.guest
        if self._acquisition_manifest:
            data.update(_acquisition_compat_fields(self._acquisition_manifest))
        self.manifest_path.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _important_parameters(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in sorted(self.parameters.items())
            if isinstance(value, (str, int, float, bool)) or value is None
        }


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


def _image_path(obj: Any) -> str | None:
    if not isinstance(obj, dict):
        return None
    value = obj.get("path")
    return str(value) if value else None


def _acquisition_compat_fields(manifest: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "created_at": manifest.get("created_at"),
        "disk_acquisition_mode": manifest.get("disk_acquisition_mode"),
        "disk_preparation": manifest.get("disk_preparation"),
    }
    for key in ("memory_image", "disk_image"):
        if isinstance(manifest.get(key), dict):
            fields[key] = manifest[key]
    return {key: value for key, value in fields.items() if value is not None}
