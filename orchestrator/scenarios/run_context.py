"""Runtime context and recorders for declarative scenarios."""

from __future__ import annotations

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
        distro: str | None = None,
        profile: str = "vanilla",
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
        self.distro = distro
        self.profile = profile
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
        self.guest: dict[str, Any] = {}
        self.artifacts: dict[str, str] = {
            "command_log": self._relative_path(self.command_log_path),
        }
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

    def finalize(self, status: str) -> None:
        self.final_status = status
        self.ended_at = self.now()
        self._write_manifest()

    def update_environment(
        self,
        *,
        guest: dict[str, Any] | None = None,
        distro: str | None = None,
        profile: str | None = None,
    ) -> None:
        if guest:
            self.guest.update(guest)
        if distro is not None:
            self.distro = distro
        if profile is not None:
            self.profile = profile
        self._write_manifest()

    def record_acquisition_output(self, acquisition_manifest_path: str | Path) -> None:
        self.artifacts["acquisition_manifest"] = self._relative_path(
            Path(acquisition_manifest_path)
        )
        self._write_manifest()

    def record_raw_analysis_output(self, status_path: str | Path) -> None:
        self.artifacts["raw_extraction_status"] = self._relative_path(
            Path(status_path)
        )
        self._write_manifest()

    def _write_manifest(self) -> None:
        data = {
            "schema": "forensic-lab.run_manifest",
            "version": 2,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "platform": {
                "distro_id": self.distro,
                "guest_os": self.guest.get("distro"),
                "kernel": self.guest.get("kernel"),
                "timezone": self.guest.get("timezone"),
                "profile": self.profile,
            },
            "repository": {
                "commit": _git_commit(self.repo_root),
            },
            "timestamps": {
                "started_at": self.started_at,
                "ended_at": self.ended_at,
            },
            "status": self.final_status,
            "artifacts": dict(sorted(self.artifacts.items())),
        }
        self.manifest_path.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _relative_path(self, path: Path) -> str:
        return str(path.resolve().relative_to(self.out_dir.resolve()))


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
