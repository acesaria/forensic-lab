from contextlib import contextmanager
import hashlib
import json
from pathlib import Path

import pytest

from orchestrator.core.orchestrator import ForensicOrchestrator
from orchestrator.core.paths import ProjectPaths


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
        "userland_father_ldpreload",
        {"scenario_yml": "scenarios/userland_father_ldpreload/scenario.yml"},
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
        "userland_father_ldpreload",
        {"scenario_yml": "scenarios/userland_father_ldpreload/scenario.yml"},
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
