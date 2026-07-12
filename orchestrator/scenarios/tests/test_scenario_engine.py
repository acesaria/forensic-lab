import json
from pathlib import Path
import subprocess

import pytest

from orchestrator.scenarios import run_scenario
from orchestrator.scenarios.engine import ScenarioStepError
from orchestrator.scenarios.executors import SSHClientExecutor
from orchestrator.forensics.dumper import Dumper


def test_scenario_manifest_records_completed_and_failed_steps(tmp_path: Path):
    scenario = Path("scenarios/scenarios/toy_file_creation/scenario.yml")

    ctx = run_scenario(
        scenario,
        out_dir=tmp_path,
        run_id="toy-run",
        repo_root=Path.cwd(),
    )

    assert ctx.manifest_path.is_file()
    assert ctx.command_log_path.is_file()
    assert not (tmp_path / "execution_truth.jsonl").exists()
    assert not (tmp_path / "artifact_expectations.jsonl").exists()

    command_rows = [
        json.loads(line)
        for line in ctx.command_log_path.read_text(encoding="utf-8").splitlines()
    ]
    manifest = json.loads(ctx.manifest_path.read_text(encoding="utf-8"))

    assert [row["status"] for row in command_rows] == ["success", "success"]
    assert (ctx.work_dir / "toy.txt").read_text(encoding="utf-8")
    assert manifest["schema"] == "forensic-lab.run_manifest"
    assert manifest["run_id"] == "toy-run"
    assert manifest["scenario"]["id"] == "toy_file_creation"
    assert manifest["status"] == "completed"
    assert [step["status"] for step in manifest["steps"]] == ["completed", "completed"]
    assert [fact["fact_type"] for fact in manifest["facts"]] == ["file_observed"]

    analysis_dir = tmp_path / "analysis"
    analysis_dir.mkdir()
    (analysis_dir / "bodyfile").write_text("0|/toy|0|0|0|0|0|0|0|0|0\n", encoding="utf-8")
    status_path = analysis_dir / "raw_extraction_status.json"
    status_path.write_text("{}", encoding="utf-8")
    ctx.record_raw_analysis_outputs(
        analysis_dir,
        status={"tsk": {"status": "completed", "row_count": 1}},
        status_path=status_path,
    )
    manifest = json.loads(ctx.manifest_path.read_text(encoding="utf-8"))
    raw_analysis = manifest["outputs"]["raw_analysis"]
    assert raw_analysis["files"]["tsk_bodyfile"] == str(analysis_dir / "bodyfile")
    assert raw_analysis["status"]["tsk"]["status"] == "completed"
    assert raw_analysis["status_manifest"] == str(status_path)

    failing = tmp_path / "failing.yml"
    failing.write_text(
        "\n".join(
            [
                "scenario_id: failing_scenario",
                "steps:",
                "  - id: fail_command",
                "    type: shell",
                "    command: \"printf 'broken stderr' >&2; exit 7\"",
                "",
            ]
        ),
        encoding="utf-8",
    )
    failed_out = tmp_path / "failed-out"

    with pytest.raises(ScenarioStepError):
        run_scenario(
            failing,
            out_dir=failed_out,
            run_id="failed-run",
            repo_root=Path.cwd(),
        )

    failed_manifest = json.loads((failed_out / "manifest.json").read_text(encoding="utf-8"))
    failed_log = [
        json.loads(line)
        for line in (failed_out / "command_log.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert failed_manifest["status"] == "failed"
    assert failed_manifest["steps"][0]["status"] == "failed"
    assert failed_manifest["steps"][0]["exit_code"] == 7
    assert "broken stderr" in failed_manifest["steps"][0]["stderr_excerpt"]
    assert failed_log[0]["exit_code"] == 7
    assert "broken stderr" in failed_log[0]["stderr_excerpt"]


def test_ewfverify_failure_is_preserved_and_fails_acquisition_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    first_segment = tmp_path / "evidence.E01"

    def fake_run(command, **_kwargs):
        if command == ["ewfverify", "-V"]:
            return subprocess.CompletedProcess(command, 0, "ewfverify 20140813\n", "")
        return subprocess.CompletedProcess(
            command, 3, "verification stdout\n", "verification stderr\n"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    segments = [
        {"path": str(first_segment), "size_bytes": 4, "sha256": "a" * 64},
        {
            "path": str(tmp_path / "evidence.E02"),
            "size_bytes": 3,
            "sha256": "b" * 64,
        },
    ]

    with pytest.raises(RuntimeError, match="ewfverify failed"):
        Dumper._run_ewfverify(
            object.__new__(Dumper),
            first_segment,
            str(tmp_path / "evidence"),
            segment_metadata=segments,
        )

    status = json.loads(
        (tmp_path / "ewfverify_status.json").read_text(encoding="utf-8")
    )
    assert status["status"] == "failed"
    assert status["acquisition_status"] == "failed"
    assert status["exit_status"] == 3
    assert status["stdout"] == "verification stdout\n"
    assert status["stderr"] == "verification stderr\n"
    assert status["segments"] == segments


def test_ssh_client_executor_adapts_existing_ssh_client_api():
    class FakeSSH:
        def __init__(self):
            self.commands = []
            self.uploads = []

        def run(self, command, timeout=300):
            self.commands.append((command, timeout))
            return 0, "ok", ""

        def put(self, local, remote):
            self.uploads.append((local, remote))

    fake = FakeSSH()
    executor = SSHClientExecutor(fake)

    result = executor.run("true", timeout=7)
    executor.put(Path("local.txt"), "/tmp/lab/remote.txt")

    assert result.exit_code == 0
    assert result.stdout == "ok"
    assert fake.commands == [("true", 7), ("mkdir -p /tmp/lab", 30)]
    assert fake.uploads == [(Path("local.txt"), "/tmp/lab/remote.txt")]
