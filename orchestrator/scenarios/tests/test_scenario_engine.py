import json
from pathlib import Path
import subprocess

import pytest

from orchestrator.scenarios import run_scenario
from orchestrator.scenarios.engine import ScenarioStepError
from orchestrator.scenarios.executors import SSHClientExecutor
from orchestrator.forensics.dumper import Dumper
from orchestrator.forensics.extract import extract_plugins
from orchestrator.forensics.pipeline_config import reported_version


def test_scenario_manifest_is_minimal_and_command_log_keeps_step_results(tmp_path: Path):
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


def test_ewfverify_calculated_sha256_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    first_segment = tmp_path / "evidence.E01"
    digest = "c" * 64

    def fake_run(command, **_kwargs):
        if command == ["ewfverify", "-V"]:
            return subprocess.CompletedProcess(command, 0, "ewfverify 20240506\n", "")
        return subprocess.CompletedProcess(
            command,
            0,
            f"SHA256 hash calculated over data:\t{digest}\n",
            "",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    status = Dumper._run_ewfverify(
        object.__new__(Dumper), first_segment, str(tmp_path / "evidence")
    )

    assert status["status"] == "completed"
    assert status["calculated_sha256"] == digest

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "", ""),
    )
    with pytest.raises(RuntimeError, match="did not report a calculated SHA-256"):
        Dumper._run_ewfverify(
            object.__new__(Dumper), first_segment, str(tmp_path / "evidence")
        )


def test_volatility_failure_is_distinct_from_successful_zero_results():
    class FakeVolatility:
        def run_plugin(self, _memory, _distro, plugin, **kwargs):
            invocation = kwargs["invocation"]
            if plugin == "failed.plugin":
                invocation.update({"status": "failed", "exit_status": 2})
                raise RuntimeError("plugin failed")
            invocation.update(
                {
                    "status": "completed",
                    "exit_status": 0,
                    "result": "zero_results",
                    "row_count": 0,
                }
            )
            return []

    errors = {}
    invocations = {}
    rows = extract_plugins(
        FakeVolatility(),
        Path("memory.raw"),
        "ubuntu-22.04",
        plugins=("empty.plugin", "failed.plugin"),
        errors=errors,
        invocations=invocations,
    )

    assert rows == {"empty.plugin": [], "failed.plugin": None}
    assert invocations["empty.plugin"]["row_count"] == 0
    assert invocations["empty.plugin"]["error"] is None
    assert invocations["failed.plugin"]["exit_status"] == 2
    assert invocations["failed.plugin"]["error"] == "plugin failed"
    assert errors == {"failed.plugin": "plugin failed"}


def test_volatility_version_parser_accepts_no_plugin_output(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        "orchestrator.forensics.pipeline_config.command_output",
        lambda *_args, **_kwargs: "usage: vol.py [...]\nVolatility 3 Framework 2.28.0",
    )

    assert reported_version("volatility3", {"volatility3": "/opt/vol3"}) == "2.28.0"


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
