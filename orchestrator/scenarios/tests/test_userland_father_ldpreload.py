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


def test_userland_father_scenario_plan_and_expectations():
    plan = load_scenario_plan(SCENARIO)

    assert plan.scenario_id == "userland_father_ldpreload"
    assert [step["id"] for step in plan.steps] == [
        "prepare_sample",
        "deploy_library",
        "modify_preload_config",
        "start_benign_process",
        "observe_or_mark_hiding_feature",
        "partial_cleanup",
    ]
    expectations = plan.expected_observables
    classes = {row["artifact_class"] for row in expectations}
    assert {"preload_configuration", "shared_object", "library_mapping", "deleted_file_candidate"} <= classes
    critical = {row["ae_id"] for row in expectations if row.get("critical")}
    assert {
        "AE-father-shared-object",
        "AE-father-preload-config",
        "AE-father-benign-process",
        "AE-father-library-mapping",
        "AE-father-cleanup-deleted-marker",
    } <= critical


def test_userland_father_hooks_emit_canonical_truth_and_expectations(tmp_path: Path):
    import importlib.util

    plan = load_scenario_plan(SCENARIO)
    spec = importlib.util.spec_from_file_location("father_steps", plan.hooks_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    root = tmp_path / "remote"
    params = {
        key: str(root / Path(str(value)).name)
        for key, value in plan.parameters.items()
        if str(value).startswith("/tmp/")
    }
    params.update(plan.parameters)
    params["remote_root"] = str(root)
    params["upstream_archive_path"] = str(root / "source" / "father-upstream-4eb2712.tar")
    params["source_path"] = str(root / "source" / "father_lab_preload.c")
    params["metadata_path"] = str(root / "source" / "father_sample.lock.yml")
    params["library_path"] = str(root / "lib" / "libfather_lab_preload.so")
    params["preload_config_path"] = str(root / "etc" / "ld.so.preload.lab")
    params["process_cwd"] = str(root / "run")
    params["process_stdout_path"] = str(root / "run" / "benign_process.out")
    params["process_pid_path"] = str(root / "run" / "benign_process.pid")
    params["hiding_marker_path"] = str(root / "markers" / "hiding_feature_marker.txt")
    params["cleanup_marker_path"] = str(root / "markers" / "transient_cleanup_marker.txt")
    params["process_duration_seconds"] = 1

    ctx = RunContext(
        run_id="father-test",
        scenario_id=plan.scenario_id,
        out_dir=tmp_path / "out",
        executor=LocalExecutor(),
        parameters=params,
        repo_root=Path.cwd(),
    )
    ctx.write_reference_context()
    for row in plan.expected_observables:
        ctx.record_artifact(str(row.get("step_id") or "scenario"), row)

    for step in plan.steps:
        getattr(module, step["function"])(ctx, step)

    truth = load_jsonl(ctx.execution_truth_path, GroundTruthEvent)
    expectations = load_jsonl(ctx.artifact_expectations_path, ArtifactExpectation)

    assert {event.event_type for event in truth} >= {
        "sample_prepared",
        "library_deployed",
        "preload_config_modified",
        "benign_process_started",
        "library_observed_in_process",
        "hiding_feature_demonstrated_or_marked",
        "partial_cleanup",
    }
    sample_event = next(event for event in truth if event.event_type == "sample_prepared")
    assert sample_event.details["vendored_original_source"] is True
    assert sample_event.details["executed_original_source"] is False
    assert sample_event.details["upstream_archive_sha256"] == (
        "90e440a2ff8264a3f39c5c2b63ee7b8def9b85f87a7b79c666bfb46f25a2c125"
    )
    assert any(exp.artifact_class == "preload_configuration" for exp in expectations)
    assert Path(params["upstream_archive_path"]).is_file()
    assert Path(params["library_path"]).is_file()
    assert Path(params["preload_config_path"]).read_text().strip() == params["library_path"]
    assert not Path(params["cleanup_marker_path"]).exists()


def test_userland_father_cached_pipeline_reaches_detectors_and_matcher(tmp_path: Path):
    import importlib.util

    plan = load_scenario_plan(SCENARIO)
    spec = importlib.util.spec_from_file_location("father_steps", plan.hooks_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    root = tmp_path / "remote"
    params = dict(plan.parameters)
    params["remote_root"] = str(root)
    params["upstream_archive_path"] = str(root / "source" / "father-upstream-4eb2712.tar")
    params["source_path"] = str(root / "source" / "father_lab_preload.c")
    params["metadata_path"] = str(root / "source" / "father_sample.lock.yml")
    params["library_path"] = str(root / "lib" / "libfather_lab_preload.so")
    params["preload_config_path"] = str(root / "etc" / "ld.so.preload.lab")
    params["process_cwd"] = str(root / "run")
    params["process_stdout_path"] = str(root / "run" / "benign_process.out")
    params["process_pid_path"] = str(root / "run" / "benign_process.pid")
    params["hiding_marker_path"] = str(root / "markers" / "hiding_feature_marker.txt")
    params["cleanup_marker_path"] = str(root / "markers" / "transient_cleanup_marker.txt")
    params["process_duration_seconds"] = 1

    ctx = RunContext(
        run_id="father-cached-pipeline",
        scenario_id=plan.scenario_id,
        out_dir=tmp_path / "out",
        executor=LocalExecutor(),
        parameters=params,
        repo_root=Path.cwd(),
    )
    ctx.write_reference_context()
    for row in plan.expected_observables:
        ctx.record_artifact(str(row.get("step_id") or "scenario"), row)
    for step in plan.steps:
        getattr(module, step["function"])(ctx, step)

    truth = load_jsonl(ctx.execution_truth_path, GroundTruthEvent)
    process_event = next(event for event in truth if event.event_type == "benign_process_started")
    pid = process_event.details["pid"]

    findings_path = tmp_path / "tool_findings.jsonl"
    findings = [
        _finding("tf-preload", "disk", "preload_configuration", params["preload_config_path"]),
        _finding("tf-shared-object", "disk", "shared_object", params["library_path"]),
        _finding("tf-process", "memory", "process", "/bin/sleep", pid=pid),
        _finding("tf-library-map", "memory", "library_mapping", params["library_path"], pid=pid),
        _finding(
            "tf-deleted-marker",
            "timeline",
            "deleted_file_candidate",
            params["cleanup_marker_path"],
            deleted=True,
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
    assert "flab.filesystem.deleted_artifact_cleanup" in rule_ids

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
    assert result["metrics"]["counts"]["tp"] >= 4
    assert result["metrics"]["critical_recall"]["recall"] > 0


def _finding(
    finding_id: str,
    source_type: str,
    artifact_class: str,
    value: str,
    *,
    pid: str | None = None,
    deleted: bool = False,
) -> ToolFinding:
    entity = {"type": "process" if artifact_class == "process" else "path", "value": value}
    if pid is not None:
        entity["pid"] = pid
    if deleted:
        entity["deleted"] = True
    if artifact_class == "process":
        entity["argv"] = [value, "1"]
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
