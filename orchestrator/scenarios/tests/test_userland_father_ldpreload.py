import json
from pathlib import Path

import pytest

from orchestrator.scenarios.executors import LocalExecutor
from orchestrator.scenarios.loader import load_scenario_plan
from orchestrator.scenarios.run_context import RunContext


SCENARIO = Path("scenarios/scenarios/userland_father_ldpreload/scenario.yml")
SCENARIO_DIR = SCENARIO.parent
FATHER_ARCHIVE = SCENARIO_DIR / "files/father-upstream-4eb2712.tar"
FATHER_LOCK = SCENARIO_DIR / "father.lock.yml"
ACTIVATION_HELPER = SCENARIO_DIR / "files/activate_system_preload.py"
FAKE_FATHER_SOURCE = SCENARIO_DIR / "files/father_lab_preload.c"
OLD_ACCEPT_LISTENER = SCENARIO_DIR / "files/father_accept_listener.py"


def test_userland_father_system_preload_plan_has_no_expected_observables():
    plan = load_scenario_plan(SCENARIO)

    assert plan.scenario_id == "userland_father_ldpreload"
    assert [step["id"] for step in plan.steps] == [
        "prepare_father_source",
        "configure_father",
        "build_father_rootkit",
        "install_activate_and_validate",
    ]
    assert plan.parameters["installed_library_path"] == (
        "/usr/local/lib/forensic-lab/father/selinux.so.3"
    )
    assert plan.parameters["preload_config_path"] == "/etc/ld.so.preload"
    assert plan.parameters["preload_hide_token"] != "ld.so.preload"
    header_packages = {
        item["ubuntu_package"]
        for item in plan.prerequisites["father_build"]["headers"]
    }
    assert {"libpam0g-dev", "libgcrypt20-dev"} <= header_packages
    assert "expected_observables" not in SCENARIO.read_text(encoding="utf-8")
    assert not (SCENARIO_DIR / "expected_observables.yml").exists()


def test_father_uses_pinned_upstream_assets_without_old_wrapper():
    assert FATHER_ARCHIVE.is_file()
    assert FATHER_LOCK.is_file()
    assert ACTIVATION_HELPER.is_file()
    assert not FAKE_FATHER_SOURCE.exists()
    assert not OLD_ACCEPT_LISTENER.exists()


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
    import importlib.util

    plan = load_scenario_plan(SCENARIO)
    spec = importlib.util.spec_from_file_location("father_steps", plan.hooks_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module, plan
