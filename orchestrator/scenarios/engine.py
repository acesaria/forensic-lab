"""Minimal YAML + Python-hook scenario engine."""

from __future__ import annotations

import importlib.util
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from orchestrator.scenarios.executors import LocalExecutor, ScenarioExecutor
from orchestrator.scenarios.loader import ScenarioPlan, load_scenario_plan
from orchestrator.scenarios.run_context import RunContext


class ScenarioStepError(RuntimeError):
    pass


def run_scenario(
    scenario_yml: str | Path,
    *,
    out_dir: str | Path | None = None,
    run_id: str | None = None,
    executor: ScenarioExecutor | None = None,
    repo_root: str | Path | None = None,
) -> RunContext:
    plan = load_scenario_plan(scenario_yml)
    run_id = run_id or _run_id(plan)
    out = Path(out_dir) if out_dir is not None else plan.root / "runs" / run_id
    ctx = RunContext(
        run_id=run_id,
        scenario_id=plan.scenario_id,
        out_dir=out,
        executor=executor or LocalExecutor(),
        parameters=plan.parameters,
        repo_root=repo_root,
    )
    hooks = _load_hooks(plan)
    ctx.write_reference_context()
    for row in plan.expected_observables:
        ctx.record_artifact(str(row.get("step_id") or "scenario"), row)
    for step in plan.steps:
        _run_step(ctx, plan, hooks, step)
    return ctx


def _run_step(
    ctx: RunContext,
    plan: ScenarioPlan,
    hooks: dict[str, Callable[[RunContext, dict[str, Any]], Any]],
    step: dict[str, Any],
) -> None:
    step_id = str(step.get("id") or step.get("step_id") or "")
    if not step_id:
        raise ScenarioStepError("scenario step is missing id")
    step_type = str(step.get("type") or "shell")
    started = ctx.now()
    try:
        if step_type == "shell":
            _step_shell(ctx, step)
        elif step_type == "upload":
            _step_upload(ctx, plan, step)
        elif step_type == "python":
            _step_python(ctx, hooks, step)
        elif step_type == "sleep":
            time.sleep(float(step.get("seconds", 1)))
        elif step_type == "record":
            pass
        else:
            raise ScenarioStepError(f"{step_id}: unsupported step type {step_type!r}")
        _record_step_truth(ctx, step_id, step)
        _record_step_artifacts(ctx, step_id, step)
        ctx.log_step(
            {
                "step_id": step_id,
                "type": step_type,
                "status": "success",
                "started_at": started,
                "ended_at": ctx.now(),
            }
        )
    except Exception as exc:
        ctx.log_step(
            {
                "step_id": step_id,
                "type": step_type,
                "status": "failure",
                "started_at": started,
                "ended_at": ctx.now(),
                "error": str(exc),
            }
        )
        if not step.get("continue_on_error", False):
            raise ScenarioStepError(f"{step_id} failed: {exc}") from exc


def _step_shell(ctx: RunContext, step: dict[str, Any]) -> None:
    command = ctx.render(step.get("command") or "")
    if not command:
        raise ScenarioStepError("shell step missing command")
    result = ctx.executor.run(command, timeout=int(step.get("timeout", 120)))
    if result.exit_code != 0:
        raise ScenarioStepError(
            f"command exited {result.exit_code}: {(result.stderr or result.stdout).strip()}"
        )


def _step_upload(ctx: RunContext, plan: ScenarioPlan, step: dict[str, Any]) -> None:
    src = step.get("src")
    dest = step.get("dest")
    if not src or not dest:
        raise ScenarioStepError("upload step requires src and dest")
    local = plan.root / str(src)
    if not local.is_file():
        raise ScenarioStepError(f"upload source not found: {local}")
    ctx.executor.put(local, str(ctx.render(dest)))


def _step_python(
    ctx: RunContext,
    hooks: dict[str, Callable[[RunContext, dict[str, Any]], Any]],
    step: dict[str, Any],
) -> None:
    func_name = step.get("function")
    if not func_name:
        raise ScenarioStepError("python step missing function")
    func = hooks.get(str(func_name))
    if func is None:
        raise ScenarioStepError(f"python hook not found: {func_name}")
    func(ctx, step)


def _record_step_truth(ctx: RunContext, step_id: str, step: dict[str, Any]) -> None:
    truth = step.get("truth")
    if not truth:
        return
    rows = truth if isinstance(truth, list) else [truth]
    for row in rows:
        ctx.record_truth(step_id, row)


def _record_step_artifacts(ctx: RunContext, step_id: str, step: dict[str, Any]) -> None:
    artifacts = step.get("artifact_expectations") or []
    rows = artifacts if isinstance(artifacts, list) else [artifacts]
    for row in rows:
        ctx.record_artifact(step_id, row)


def _load_hooks(plan: ScenarioPlan) -> dict[str, Callable[[RunContext, dict[str, Any]], Any]]:
    if plan.hooks_path is None:
        return {}
    spec = importlib.util.spec_from_file_location(
        f"scenario_hooks_{plan.scenario_id}",
        plan.hooks_path,
    )
    if spec is None or spec.loader is None:
        return {}
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {
        name: value
        for name, value in vars(module).items()
        if callable(value) and not name.startswith("_")
    }


def _run_id(plan: ScenarioPlan) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{plan.scenario_id}_{ts}"
