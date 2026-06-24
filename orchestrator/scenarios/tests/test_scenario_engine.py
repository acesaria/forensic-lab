import json
from pathlib import Path

from orchestrator.canonical import ArtifactExpectation, GroundTruthEvent, load_jsonl
from orchestrator.scenarios import run_scenario
from orchestrator.scenarios.executors import SSHClientExecutor


def test_toy_file_creation_scenario_outputs_canonical_files(tmp_path: Path):
    scenario = Path("attacks/scenarios/toy_file_creation/scenario.yml")

    ctx = run_scenario(
        scenario,
        out_dir=tmp_path,
        run_id="toy-run",
        repo_root=Path.cwd(),
    )

    assert ctx.command_log_path.is_file()
    assert ctx.execution_truth_path.is_file()
    assert ctx.artifact_expectations_path.is_file()
    assert ctx.reference_context_path.is_file()

    command_rows = [
        json.loads(line)
        for line in ctx.command_log_path.read_text(encoding="utf-8").splitlines()
    ]
    truth = load_jsonl(ctx.execution_truth_path, GroundTruthEvent)
    expectations = load_jsonl(ctx.artifact_expectations_path, ArtifactExpectation)
    context = json.loads(ctx.reference_context_path.read_text(encoding="utf-8"))

    assert [row["status"] for row in command_rows] == ["success", "success"]
    assert (ctx.work_dir / "toy.txt").read_text(encoding="utf-8")
    assert [row.step_id for row in truth] == ["create_toy_file", "verify_toy_file"]
    assert expectations[0].artifact_class == "toy_text_file"
    assert context["run_id"] == "toy-run"
    assert context["scenario_id"] == "toy_file_creation"


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
