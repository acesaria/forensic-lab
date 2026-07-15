from contextlib import contextmanager
import json
from pathlib import Path

import pytest

from orchestrator.core.orchestrator import ForensicOrchestrator
from orchestrator.core.paths import ProjectPaths
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


def test_declarative_experiment_preserves_vm_and_acquisition_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    events = []
    scenario_call = {}

    class FakeSSH:
        def run(self, _command, timeout=30):
            return 0, "kernel=6.8.0-test\n", ""

    class FakeVM:
        def __init__(self):
            self.state = "off"

        def revert_to_baseline(self, _distro_id):
            events.append("baseline_revert")

        def start_vm(self, _vm_name):
            self.state = "on"
            events.append("vm_start")

        def wait_ssh_ready(self, _vm_name, **_kwargs):
            assert self.state == "on"
            events.append("ssh_ready")

        @contextmanager
        def open_ssh(self, _vm_name):
            assert self.state == "on"
            yield FakeSSH()

        def internet_off(self, _vm_name, **_kwargs):
            pass

        def internet_on(self, _vm_name):
            pass

        def get_disk_path(self, _vm_name):
            assert self.state == "on"
            return tmp_path / "fake-vm.qcow2"

        def shutdown_vm(self, _vm_name):
            assert self.state == "on"
            self.state = "off"
            events.append("vm_shutdown")

    fake_vm = FakeVM()

    class FakeDumper:
        def run_dir(self, run_id):
            return tmp_path / "evidence" / run_id

        def acquire_memory(self, _vm_name, _output_path):
            assert fake_vm.state == "on"
            events.append("memory_acquisition")
            return {"kind": "memory"}

        def acquire_disk(self, _source_path, _output_path):
            assert fake_vm.state == "off"
            events.append("disk_acquisition")
            return {"kind": "disk"}

        def write_manifest(self, run_id, _scenario_id, _memory_meta, _disk_meta):
            path = tmp_path / "evidence" / run_id / "acquisition.json"
            path.parent.mkdir(parents=True)
            path.write_text("{}\n", encoding="utf-8")
            return str(path)

    class FakeContext:
        def update_environment(self, **_kwargs):
            pass

        def record_acquisition_output(self, path):
            assert Path(path).is_file()
            events.append("acquisition_manifest")

        def record_raw_analysis_output(self, path):
            pass

    def fake_run_scenario(_scenario_yml, **kwargs):
        assert fake_vm.state == "on"
        events.append("scenario")
        scenario_call.update(distro=kwargs["distro"], profile=kwargs["profile"])
        ctx = FakeContext()
        ctx.final_status = "completed"
        ctx.manifest_path = Path(kwargs["out_dir"]) / "manifest.json"
        return ctx

    def fake_raw_extraction(
        _run_id,
        _distro_id,
        manifest_path,
        _analysis_dir,
        **_kwargs,
    ):
        assert fake_vm.state == "off"
        assert Path(manifest_path).is_file()
        events.append("raw_extraction")
        return {
            "volatility": {"status": "completed"},
            "tsk": {"status": "completed"},
            "plaso": {"status": "completed"},
        }

    paths = ProjectPaths(
        repo_root=Path.cwd(),
        shared_dir=tmp_path / "shared",
        state_dir=tmp_path / "state",
        ssh_key=tmp_path / "id_lab",
        ssh_pub_key=tmp_path / "id_lab.pub",
    )
    orchestrator = ForensicOrchestrator(
        fake_vm, FakeDumper(), object(), object(), paths, {}, {}
    )
    monkeypatch.setattr(
        "orchestrator.core.orchestrator.run_scenario", fake_run_scenario
    )
    monkeypatch.setattr(orchestrator, "_produce_raw_outputs", fake_raw_extraction)

    orchestrator.run_declarative_experiment(
        "ubuntu-22.04",
        "toy_file_creation",
        {"scenario_yml": "scenarios/toy_file_creation/scenario.yml"},
    )

    lifecycle = [
        "baseline_revert",
        "vm_start",
        "ssh_ready",
        "scenario",
        "memory_acquisition",
        "vm_shutdown",
        "disk_acquisition",
        "acquisition_manifest",
        "raw_extraction",
    ]
    assert [event for event in events if event in lifecycle] == lifecycle
    assert scenario_call == {"distro": "ubuntu-22.04", "profile": "vanilla"}
    assert fake_vm.state == "off"
