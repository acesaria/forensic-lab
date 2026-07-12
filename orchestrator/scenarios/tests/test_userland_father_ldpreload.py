import json
from pathlib import Path

from orchestrator.scenarios.executors import LocalExecutor
from orchestrator.scenarios.loader import load_scenario_plan
from orchestrator.scenarios.run_context import RunContext


SCENARIO = Path("scenarios/scenarios/userland_father_ldpreload/scenario.yml")
FATHER_ARCHIVE = Path("scenarios/scenarios/userland_father_ldpreload/files/father-upstream-4eb2712.tar")
FATHER_LOCK = Path("scenarios/scenarios/userland_father_ldpreload/father.lock.yml")
FAKE_FATHER_SOURCE = Path("scenarios/scenarios/userland_father_ldpreload/files/father_lab_preload.c")


def test_userland_father_scenario_plan_without_expected_observables():
    plan = load_scenario_plan(SCENARIO)

    assert plan.scenario_id == "userland_father_ldpreload"
    assert [step["id"] for step in plan.steps] == [
        "prepare_father_source",
        "configure_father",
        "build_father_rootkit",
        "install_preload_rootkit",
        "trigger_accept_hook_capability",
        "observe_file_hiding_effect",
        "record_postconditions",
    ]
    header_packages = {
        item["ubuntu_package"]
        for item in plan.prerequisites["father_build"]["headers"]
    }
    assert {"libpam0g-dev", "libgcrypt20-dev"} <= header_packages
    assert "expected_observables" not in SCENARIO.read_text(encoding="utf-8")
    assert not (SCENARIO.parent / "expected_observables.yml").exists()


def test_fake_father_source_is_not_present():
    assert not FAKE_FATHER_SOURCE.exists()
    assert FATHER_ARCHIVE.is_file()
    assert FATHER_LOCK.is_file()


def test_userland_father_non_network_steps_build_real_archive(tmp_path: Path):
    module, plan = _load_steps()
    params = _test_params(plan, tmp_path / "remote")

    ctx = RunContext(
        run_id="father-test",
        scenario_id=plan.scenario_id,
        out_dir=tmp_path / "out",
        executor=LocalExecutor(),
        parameters=params,
        prerequisites=plan.prerequisites,
        repo_root=Path.cwd(),
    )

    for step in plan.steps:
        if step["id"] == "trigger_accept_hook_capability":
            continue
        getattr(module, step["function"])(ctx, step)

    manifest = json.loads(ctx.manifest_path.read_text(encoding="utf-8"))
    facts = manifest["facts"]
    fact_types = {fact["fact_type"] for fact in facts}

    assert fact_types >= {
        "father_source_referenced",
        "father_run_copy_configured",
        "father_rootkit_built",
        "father_preload_installed",
        "father_file_hiding_observed",
        "postconditions_recorded",
    }
    source_fact = next(fact for fact in facts if fact["fact_type"] == "father_source_referenced")
    assert source_fact["details"]["run_local_configuration_only"] is True
    assert source_fact["details"]["capability"] == "father_source_provenance"
    assert source_fact["details"]["upstream_archive_sha256"] == (
        "90e440a2ff8264a3f39c5c2b63ee7b8def9b85f87a7b79c666bfb46f25a2c125"
    )
    build_fact = next(fact for fact in facts if fact["fact_type"] == "father_rootkit_built")
    assert build_fact["details"]["build_command"] == "make father"
    assert build_fact["details"]["capability"] == "ld_preload_installation"
    assert all("capability" in fact["details"] for fact in facts)
    command_rows = [
        json.loads(line)
        for line in ctx.command_log_path.read_text(encoding="utf-8").splitlines()
    ]
    assert any(row.get("actor") == "attacker" for row in command_rows)
    assert any(row.get("actor") == "lab" for row in command_rows)
    assert any(row.get("record_type") == "attacker_command" for row in command_rows)
    assert any(row.get("record_type") == "measurement" for row in command_rows)
    assert any(row.get("record_type") == "prerequisite" for row in command_rows)
    assert Path(params["upstream_archive_path"]).is_file()
    assert Path(params["father_config_path"]).is_file()
    assert Path(params["father_built_library_path"]).is_file()
    assert Path(params["installed_library_path"]).is_file()
    assert Path(params["preload_artifact_path"]).read_text().strip() == params["installed_library_path"]
    assert Path(params["hidden_file_path"]).is_file()


def _load_steps():
    import importlib.util

    plan = load_scenario_plan(SCENARIO)
    spec = importlib.util.spec_from_file_location("father_steps", plan.hooks_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module, plan


def _test_params(plan, root: Path) -> dict:
    import importlib.util

    params = dict(plan.parameters)
    params["root"] = str(root)
    params["source_dir"] = str(root / "source")
    params["config_dir"] = str(root / "config")
    params["lib_dir"] = str(root / "lib")
    params["run_dir"] = str(root / "run")
    params["observed_dir"] = str(root / "observed_files")
    params["process_duration_seconds"] = 1

    spec = importlib.util.spec_from_file_location("father_steps_for_params", plan.hooks_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.resolve_parameters(params)
