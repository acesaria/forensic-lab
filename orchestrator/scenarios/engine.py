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
from orchestrator.core.provenance import excerpt


class ScenarioStepError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        metadata: dict[str, Any] | None = None,
        prevented: bool = False,
    ) -> None:
        super().__init__(message)
        self.metadata = metadata or {}
        self.prevented = prevented


def run_scenario(
    scenario_yml: str | Path,
    *,
    out_dir: str | Path | None = None,
    run_id: str | None = None,
    executor: ScenarioExecutor | None = None,
    repo_root: str | Path | None = None,
    distro: str | None = None,
    profile: str | None = None,
    baseline: dict[str, str] | None = None,
    internet_on: Callable[[], None] | None = None,
    internet_off: Callable[[], None] | None = None,
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
        prerequisites=plan.prerequisites,
        distro=distro,
        profile=profile or "vanilla",
        baseline=baseline,
        repo_root=repo_root,
        internet_on=internet_on,
        internet_off=internet_off,
    )
    hooks = _load_hooks(plan)
    try:
        for step in plan.steps:
            _run_step(ctx, plan, hooks, step)
    except ScenarioStepError as exc:
        ctx.finalize("prevented" if exc.prevented else "failed")
        raise
    if ctx.final_status == "running":
        ctx.finalize("completed")
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
    metadata: dict[str, Any] = {}
    try:
        if step_type == "shell":
            metadata = _step_shell(ctx, step)
        elif step_type == "upload":
            _step_upload(ctx, plan, step)
        elif step_type == "python":
            _step_python(ctx, hooks, step)
        elif step_type == "sleep":
            time.sleep(float(step.get("seconds", 1)))
        else:
            raise ScenarioStepError(f"{step_id}: unsupported step type {step_type!r}")
        ended = ctx.now()
        ctx.log_step(
            {
                "step_id": step_id,
                "type": step_type,
                "status": "success",
                "started_at": started,
                "ended_at": ended,
                **metadata,
            }
        )
    except Exception as exc:
        ended = ctx.now()
        exc_metadata = getattr(exc, "metadata", {})
        status = "prevented" if getattr(exc, "prevented", False) else "failed"
        ctx.log_step(
            {
                "step_id": step_id,
                "type": step_type,
                "status": "failure",
                "started_at": started,
                "ended_at": ended,
                "error": str(exc),
                **exc_metadata,
            }
        )
        if not step.get("continue_on_error", False):
            if isinstance(exc, ScenarioStepError):
                raise
            raise ScenarioStepError(f"{step_id} failed: {exc}") from exc


def _step_shell(ctx: RunContext, step: dict[str, Any]) -> dict[str, Any]:
    command = ctx.render(step.get("command") or "")
    if not command:
        raise ScenarioStepError("shell step missing command")
    result = ctx.executor.run(command, timeout=int(step.get("timeout", 120)))
    metadata = {
        "command": command,
        "exit_code": result.exit_code,
        "stdout_excerpt": excerpt(result.stdout),
        "stderr_excerpt": excerpt(result.stderr),
    }
    if result.exit_code != 0:
        raise ScenarioStepError(
            f"command exited {result.exit_code}: {(result.stderr or result.stdout).strip()}",
            metadata=metadata,
        )
    return metadata


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
