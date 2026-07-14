import json
from pathlib import Path

import pytest

from orchestrator.scenarios import run_scenario
from orchestrator.scenarios.engine import ScenarioStepError
from orchestrator.scenarios.executors import SSHClientExecutor


def test_scenario_manifest_is_minimal_and_command_log_keeps_step_results(tmp_path: Path):
    scenario = Path("scenarios/toy_file_creation/scenario.yml")

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
    assert manifest["version"] == 2
    assert manifest["run_id"] == "toy-run"
    assert manifest["scenario_id"] == "toy_file_creation"
    assert manifest["status"] == "completed"
    assert manifest["platform"]["profile"] == "vanilla"
    assert manifest["artifacts"] == {"command_log": "command_log.jsonl"}
    assert not {"parameters", "steps", "facts", "outputs"} & manifest.keys()

    analysis_dir = tmp_path / "analysis"
    analysis_dir.mkdir()
    status_path = analysis_dir / "raw_extraction_status.json"
    status_path.write_text("{}", encoding="utf-8")
    dumps_dir = tmp_path / "dumps"
    dumps_dir.mkdir()
    acquisition_path = dumps_dir / "acquisition.json"
    acquisition_path.write_text("{}", encoding="utf-8")
    ctx.record_acquisition_output(acquisition_path)
    ctx.record_raw_analysis_output(status_path)
    manifest = json.loads(ctx.manifest_path.read_text(encoding="utf-8"))
    assert manifest["artifacts"] == {
        "acquisition_manifest": "dumps/acquisition.json",
        "command_log": "command_log.jsonl",
        "raw_extraction_status": "analysis/raw_extraction_status.json",
    }

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
    assert "steps" not in failed_manifest
    assert failed_log[0]["exit_code"] == 7
    assert "broken stderr" in failed_log[0]["stderr_excerpt"]


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
