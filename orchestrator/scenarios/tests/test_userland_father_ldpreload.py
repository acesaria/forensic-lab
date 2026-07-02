import json
from pathlib import Path

from detectors.engine import run_detectors, write_detection_claims
from matcher.engine import run_matcher_files
from orchestrator.canonical import (
    ArtifactExpectation,
    GroundTruthEvent,
    ToolFinding,
    load_jsonl,
    write_jsonl,
)
from orchestrator.scenarios.executors import LocalExecutor
from orchestrator.scenarios.loader import load_scenario_plan
from orchestrator.scenarios.run_context import RunContext


SCENARIO = Path("attacks/scenarios/userland_father_ldpreload/scenario.yml")
FATHER_ARCHIVE = Path("attacks/scenarios/userland_father_ldpreload/files/father-upstream-4eb2712.tar")
FATHER_LOCK = Path("attacks/scenarios/userland_father_ldpreload/father.lock.yml")
FAKE_FATHER_SOURCE = Path("attacks/scenarios/userland_father_ldpreload/files/father_lab_preload.c")


def test_userland_father_scenario_plan_and_expectations():
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
    expectations = plan.expected_observables
    classes = {row["artifact_class"] for row in expectations}
    assert {
        "preload_configuration",
        "shared_object",
        "library_mapping",
        "process_socket_correlation",
    } <= classes
    assert "deleted_file_candidate" not in classes
    critical = {row["ae_id"] for row in expectations if row.get("critical")}
    assert {
        "AE-father-built-rk-so",
        "AE-father-installed-library",
        "AE-father-ldpreload-activation",
        "AE-father-hooked-listener-process",
        "AE-father-mapped-shared-object",
        "AE-father-accept-hook-session",
        "AE-father-shell-session-process",
    } <= critical
    assert "AE-father-run-config" not in critical


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
    ctx.write_reference_context()
    for row in plan.expected_observables:
        ctx.record_artifact(str(row.get("step_id") or "scenario"), row)

    for step in plan.steps:
        if step["id"] == "trigger_accept_hook_capability":
            continue
        getattr(module, step["function"])(ctx, step)

    truth = load_jsonl(ctx.execution_truth_path, GroundTruthEvent)
    expectations = load_jsonl(ctx.artifact_expectations_path, ArtifactExpectation)

    assert {event.event_type for event in truth} >= {
        "father_source_referenced",
        "father_run_copy_configured",
        "father_rootkit_built",
        "father_preload_installed",
        "father_file_hiding_observed",
        "postconditions_recorded",
    }
    source_event = next(event for event in truth if event.event_type == "father_source_referenced")
    assert source_event.details["run_local_configuration_only"] is True
    assert source_event.details["capability"] == "father_source_provenance"
    assert source_event.details["upstream_archive_sha256"] == (
        "90e440a2ff8264a3f39c5c2b63ee7b8def9b85f87a7b79c666bfb46f25a2c125"
    )
    build_event = next(event for event in truth if event.event_type == "father_rootkit_built")
    assert build_event.details["build_command"] == "make father"
    assert build_event.details["capability"] == "ld_preload_installation"
    assert all("capability" in event.details for event in truth)
    command_rows = [
        json.loads(line)
        for line in ctx.command_log_path.read_text(encoding="utf-8").splitlines()
    ]
    assert any(row.get("actor") == "attacker" for row in command_rows)
    assert any(row.get("actor") == "lab" for row in command_rows)
    assert any(row.get("record_type") == "attacker_command" for row in command_rows)
    assert any(row.get("record_type") == "measurement" for row in command_rows)
    assert any(row.get("record_type") == "prerequisite" for row in command_rows)
    assert any(exp.artifact_class == "preload_configuration" for exp in expectations)
    assert Path(params["upstream_archive_path"]).is_file()
    assert Path(params["father_config_path"]).is_file()
    assert Path(params["father_built_library_path"]).is_file()
    assert Path(params["installed_library_path"]).is_file()
    assert Path(params["preload_artifact_path"]).read_text().strip() == params["installed_library_path"]
    assert Path(params["hidden_file_path"]).is_file()


def test_userland_father_cached_pipeline_reaches_detectors_and_matcher(tmp_path: Path):
    plan = load_scenario_plan(SCENARIO)
    params = _test_params(plan, tmp_path / "remote")

    ctx = RunContext(
        run_id="father-cached-pipeline",
        scenario_id=plan.scenario_id,
        out_dir=tmp_path / "out",
        executor=LocalExecutor(),
        parameters=params,
        prerequisites=plan.prerequisites,
        repo_root=Path.cwd(),
    )
    ctx.write_reference_context()
    for row in plan.expected_observables:
        ctx.record_artifact(str(row.get("step_id") or "scenario"), row)

    pid = "4321"
    findings_path = tmp_path / "tool_findings.jsonl"
    findings = [
        _finding("tf-preload", "disk", "preload_configuration", params["preload_artifact_path"]),
        _finding("tf-shared-object", "disk", "shared_object", params["installed_library_path"]),
        _finding("tf-process", "memory", "process", "python3", pid=pid),
        _finding("tf-library-map", "memory", "library_mapping", params["installed_library_path"], pid=pid),
        _finding(
            "tf-socket",
            "memory",
            "socket",
            "198.51.100.2:54321",
            pid=pid,
            remote={"address": "198.51.100.2", "port": 54321},
        ),
    ]
    write_jsonl(findings_path, findings)

    claims_path = tmp_path / "detection_claims.jsonl"
    claims = run_detectors(findings)
    write_detection_claims(claims_path, claims)
    rule_ids = {claim.rule_id for claim in claims}

    assert "flab.filesystem.ld_preload_configuration" in rule_ids
    assert "flab.filesystem.suspicious_shared_object" in rule_ids
    assert "flab.memory.process_library_correlation" in rule_ids
    assert "flab.memory.process_socket_correlation" in rule_ids
    assert "flab.filesystem.deleted_artifact_cleanup" not in rule_ids

    result = run_matcher_files(
        expectations_path=ctx.artifact_expectations_path,
        tool_findings_path=findings_path,
        detection_claims_path=claims_path,
        out_dir=tmp_path / "score",
        time_window_s=120,
    )

    assert result["matches_path"].is_file()
    assert result["metrics_path"].is_file()
    assert result["report_path"].is_file()
    assert result["metrics"]["counts"]["tp"] >= 3
    assert result["metrics"]["critical_recall"]["recall"] > 0


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


def _finding(
    finding_id: str,
    source_type: str,
    artifact_class: str,
    value: str,
    *,
    pid: str | None = None,
    deleted: bool = False,
    remote: dict | None = None,
) -> ToolFinding:
    entity_type = {
        "process": "process",
        "socket": "socket",
    }.get(artifact_class, "path")
    entity = {"type": entity_type, "value": value}
    if pid is not None:
        entity["pid"] = pid
    if deleted:
        entity["deleted"] = True
    if remote:
        entity["remote"] = remote
    if artifact_class == "process":
        entity["argv"] = [value, "father_accept_listener.py"]
    return ToolFinding(
        finding_id=finding_id,
        run_id="father-cached-pipeline",
        tool="fixture",
        tool_version="test",
        adapter_version="test",
        source_type=source_type,
        artifact_class=artifact_class,
        entity=entity,
        time="2026-06-18T10:00:00Z",
        raw_ref=f"fixture:{finding_id}",
        provenance={"fixture": "userland_father_ldpreload"},
    )
