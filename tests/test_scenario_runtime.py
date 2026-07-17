from contextlib import contextmanager
import hashlib
import json
from pathlib import Path

import pytest

from orchestrator.core.orchestrator import ForensicOrchestrator
from orchestrator.core.paths import ProjectPaths
from orchestrator.core.ssh_client import SSHClient
from orchestrator.scenarios import run_scenario
from orchestrator.scenarios.engine import ScenarioStepError
from orchestrator.scenarios.executors import SSHClientExecutor


def test_scenario_manifest_is_minimal_and_command_log_keeps_step_results(tmp_path: Path):
    scenario = Path("scenarios/toy_file_creation/scenario.yml")
    baseline = {
        "vm_name": "lab-ubuntu-22.04",
        "snapshot": "baseline",
        "snapshot_created_at": "2026-07-13T08:15:00Z",
    }

    ctx = run_scenario(
        scenario,
        out_dir=tmp_path,
        run_id="toy-run",
        repo_root=Path.cwd(),
        baseline=baseline,
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
    assert manifest["baseline"] == baseline
    assert manifest["artifacts"] == {"command_log": "command_log.jsonl"}
    assert not {"parameters", "steps", "facts", "outputs"} & manifest.keys()
    scenario_ended_at = manifest["timestamps"]["ended_at"]
    assert scenario_ended_at is not None
    assert manifest["timestamps"]["full_run_ended_at"] is None

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
    ctx.finalize_full_run()
    manifest = json.loads(ctx.manifest_path.read_text(encoding="utf-8"))
    assert manifest["artifacts"] == {
        "acquisition_manifest": "dumps/acquisition.json",
        "command_log": "command_log.jsonl",
        "raw_extraction_status": "analysis/raw_extraction_status.json",
    }
    assert manifest["timestamps"]["ended_at"] == scenario_ended_at
    assert manifest["timestamps"]["full_run_ended_at"] is not None

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
            self.terminal_commands = []
            self.uploads = []

        def run(self, command, timeout=300):
            self.commands.append((command, timeout))
            return 0, "ok", ""

        def put(self, local, remote):
            self.uploads.append((local, remote))

        def run_in_terminal(self, command, timeout=300):
            self.terminal_commands.append((command, timeout))
            return 4, "terminal transcript"

    fake = FakeSSH()
    executor = SSHClientExecutor(fake)

    result = executor.run("true", timeout=7)
    terminal_result = executor.run_in_terminal("bash /tmp/run.sh", timeout=9)
    executor.put(Path("local.txt"), "/tmp/lab/remote.txt")

    assert result.exit_code == 0
    assert result.stdout == "ok"
    assert terminal_result.exit_code == 4
    assert terminal_result.stdout == "terminal transcript"
    assert fake.commands == [("true", 7), ("mkdir -p /tmp/lab", 30)]
    assert fake.terminal_commands == [("bash /tmp/run.sh", 9)]
    assert fake.uploads == [(Path("local.txt"), "/tmp/lab/remote.txt")]


def test_ssh_client_run_in_terminal_uses_interactive_bash_and_returns_status():
    class FakeChannel:
        def __init__(self):
            self.closed = False

        def recv_exit_status(self):
            return 7

        def close(self):
            self.closed = True

    class FakeFile:
        def __init__(self, channel, data=b""):
            self.channel = channel
            self.data = data
            self.writes = []
            self.closed = False

        def write(self, data):
            self.writes.append(data)

        def flush(self):
            pass

        def read(self):
            return self.data

        def close(self):
            self.closed = True

    class FakeParamikoClient:
        def __init__(self):
            self.calls = []
            self.channel = FakeChannel()
            self.stdin = FakeFile(self.channel)
            self.stdout = FakeFile(self.channel, b"combined terminal transcript\r\n")
            self.stderr = FakeFile(self.channel)

        def exec_command(self, command, *, get_pty, timeout):
            self.calls.append((command, get_pty, timeout))
            return self.stdin, self.stdout, self.stderr

    fake = FakeParamikoClient()
    client = SSHClient("192.0.2.1", "lab", Path("/tmp/test-key"))
    client._client = fake

    code, transcript = client.run_in_terminal("bash /tmp/run.sh", timeout=9)

    assert (code, transcript) == (7, "combined terminal transcript\r\n")
    assert fake.calls == [("/bin/bash -i", True, 9)]
    assert fake.stdin.writes == ["bash /tmp/run.sh\nexit\n"]
    assert fake.stdin.closed and fake.stdout.closed and fake.stderr.closed
    assert fake.channel.closed


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

        def snapshot_created_at(self, vm_name, snapshot_name):
            assert vm_name == "lab-ubuntu-22.04"
            assert snapshot_name == "baseline"
            return "2026-07-13T08:15:00Z"

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
            assert Path(path).is_file()
            events.append("raw_status_recorded")

        def finalize_full_run(self):
            events.append("full_run_ended")

    def fake_run_scenario(_scenario_yml, **kwargs):
        assert fake_vm.state == "on"
        assert kwargs["baseline"] == {
            "vm_name": "lab-ubuntu-22.04",
            "snapshot": "baseline",
            "snapshot_created_at": "2026-07-13T08:15:00Z",
        }
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
        "raw_status_recorded",
        "full_run_ended",
    ]
    assert [event for event in events if event in lifecycle] == lifecycle
    assert scenario_call == {"distro": "ubuntu-22.04", "profile": "vanilla"}
    assert fake_vm.state == "off"

    events.clear()
    orchestrator.run_declarative_experiment(
        "ubuntu-22.04",
        "toy_file_creation",
        {"scenario_yml": "scenarios/toy_file_creation/scenario.yml"},
        acquire=False,
    )
    assert [event for event in events if event in lifecycle] == [
        "baseline_revert",
        "vm_start",
        "ssh_ready",
        "scenario",
        "full_run_ended",
    ]
    assert fake_vm.state == "on"


def test_raw_volatility_status_records_resolved_isf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    isf_contents = b'{"symbols": "test"}\n'
    isf_path = tmp_path / "ubuntu_6.8.0-test.json"
    isf_path.write_bytes(isf_contents)

    class FakeVolatility:
        resolve_calls = 0

        def resolve_isf(self, distro_id, kernel_release=None):
            assert (distro_id, kernel_release) == ("ubuntu-22.04", "6.8.0-test")
            self.resolve_calls += 1
            return isf_path

        def run_plugin(self, _memory, _distro, _plugin, **kwargs):
            assert kwargs["isf_path"] == isf_path.resolve()
            kwargs["invocation"].update(
                status="completed", result="zero_results", row_count=0
            )
            return []

    class FakeOrchestrator:
        repo_root = tmp_path
        _vol_runner = FakeVolatility()
        _sleuth_runner = object()
        _raw_tools = {}

    acquisition_path = tmp_path / "acquisition.json"
    acquisition_path.write_text(
        '{"memory_image":{"path":"memory.raw"},'
        '"disk_image":{"path":"disk.E01"}}',
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "orchestrator.core.orchestrator.reported_version",
        lambda *_args, **_kwargs: "test-version",
    )

    status = ForensicOrchestrator._produce_raw_outputs(
        FakeOrchestrator(),
        "test-run",
        "ubuntu-22.04",
        str(acquisition_path),
        tmp_path,
        kernel_release="6.8.0-test",
    )

    resolved_isf = isf_path.resolve()
    assert FakeOrchestrator._vol_runner.resolve_calls == 1
    assert status["volatility"]["isf"] == {
        "path": str(resolved_isf),
        "sha256": hashlib.sha256(isf_contents).hexdigest(),
    }
    assert all(
        "isf" not in invocation
        for invocation in status["volatility"]["invocations"].values()
    )
