"""Load scenario.yml plus optional expected_observables.yml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ScenarioPlan:
    scenario_id: str
    path: Path
    steps: list[dict[str, Any]]
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    prerequisites: dict[str, Any] = field(default_factory=dict)
    attck: list[str] = field(default_factory=list)
    expected_observables: list[dict[str, Any]] = field(default_factory=list)
    hooks_path: Path | None = None

    @property
    def root(self) -> Path:
        return self.path.parent

    @property
    def files_dir(self) -> Path:
        return self.root / "files"


def load_scenario_plan(path: str | Path) -> ScenarioPlan:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    scenario_id = data.get("scenario_id")
    if not scenario_id:
        raise ValueError(f"{p}: missing scenario_id")
    steps = data.get("steps") or []
    if not isinstance(steps, list):
        raise ValueError(f"{p}: steps must be a list")

    expected = list(data.get("expected_observables") or [])
    expected_file = data.get("expected_observables_file", "expected_observables.yml")
    expected_path = p.parent / expected_file
    if expected_path.is_file():
        expected_data = yaml.safe_load(expected_path.read_text(encoding="utf-8")) or {}
        expected.extend(expected_data.get("artifact_expectations") or expected_data.get("expected_observables") or [])

    hooks = data.get("hooks", "steps.py")
    hooks_path = p.parent / hooks if hooks else None
    if hooks_path is not None and not hooks_path.is_file():
        hooks_path = None

    return ScenarioPlan(
        scenario_id=str(scenario_id),
        path=p,
        description=str(data.get("description") or ""),
        parameters=_load_parameters(data),
        prerequisites=dict(data.get("prerequisites") or {}),
        attck=[str(x) for x in data.get("attck") or []],
        steps=steps,
        expected_observables=expected,
        hooks_path=hooks_path,
    )


def _load_parameters(data: dict[str, Any]) -> dict[str, Any]:
    parameters: dict[str, Any] = {}
    for key in ("paths", "variables", "parameters"):
        block = data.get(key) or {}
        if not isinstance(block, dict):
            raise ValueError(f"{key} must be a mapping when present")
        parameters.update(block)
    return _render_parameter_values(parameters)


def _render_parameter_values(parameters: dict[str, Any]) -> dict[str, Any]:
    rendered = dict(parameters)
    for _ in range(8):
        next_rendered = {
            key: _render_value(value, rendered)
            for key, value in rendered.items()
        }
        if next_rendered == rendered:
            return next_rendered
        rendered = next_rendered
    return rendered


def _render_value(value: Any, parameters: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return value.format_map(_SafeFormat(parameters))
    if isinstance(value, list):
        return [_render_value(item, parameters) for item in value]
    if isinstance(value, dict):
        return {key: _render_value(item, parameters) for key, item in value.items()}
    return value


class _SafeFormat(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"
