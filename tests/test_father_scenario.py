import importlib.util
import json
from pathlib import Path

import pytest

from orchestrator.scenarios.executors import LocalExecutor
from orchestrator.scenarios.loader import load_scenario_plan
from orchestrator.scenarios.run_context import RunContext


SCENARIO = Path("scenarios/userland_father_ldpreload/scenario.yml")


def test_userland_father_refuses_local_execution(tmp_path: Path):
    module, plan = _load_steps()
    ctx = RunContext(
        run_id="father-local-refusal",
        scenario_id=plan.scenario_id,
        out_dir=tmp_path / "out",
        executor=LocalExecutor(),
        parameters=plan.parameters,
        prerequisites=plan.prerequisites,
        repo_root=Path.cwd(),
    )

    with pytest.raises(RuntimeError, match="VM-backed SSH executor"):
        module.prepare_father_source(ctx, plan.steps[0])

    assert not ctx.command_log_path.exists()


def test_run_manifest_records_only_concise_father_operational_facts(tmp_path: Path):
    facts = {
        "deployed_files": ["/guest/father.so", "/etc/ld.so.preload"],
        "preload_activation": {"mode": "system-wide"},
        "affected_pids": [101, 102, 103],
        "privilege_used": "sudo -n to effective UID 0",
        "validation_result": {"status": "passed"},
    }
    ctx = RunContext(
        run_id="father-facts",
        scenario_id="userland_father_ldpreload",
        out_dir=tmp_path,
        executor=LocalExecutor(),
    )

    ctx.record_scenario_facts(facts)

    manifest = json.loads(ctx.manifest_path.read_text(encoding="utf-8"))
    assert manifest["scenario_facts"] == facts
    assert "facts" not in manifest


def _load_steps():
    plan = load_scenario_plan(SCENARIO)
    spec = importlib.util.spec_from_file_location("father_steps", plan.hooks_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module, plan
