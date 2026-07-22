import hashlib
import json
from contextlib import nullcontext
from pathlib import Path

import pytest

from orchestrator.core.orchestrator import ForensicOrchestrator


@pytest.mark.parametrize(
    (
        "scenario_id",
        "acquire",
        "failure_phase",
        "expected_shutdowns",
        "expect_facts",
        "expected_vm_state",
    ),
    [
        ("interactive_shell", True, "acquisition", 0, False, "on"),
        ("interactive_shell", False, None, 0, False, "on"),
        ("userland_father_ldpreload", False, None, 1, True, "off"),
        ("userland_father_ldpreload", False, "scenario", 1, False, "off"),
        ("userland_father_ldpreload", True, "acquisition", 1, True, "off"),
        ("userland_father_ldpreload_cleanup", True, None, 0, True, "off"),
        ("interactive_shell", False, "scenario", 0, False, "on"),
        ("interactive_shell", True, None, 0, False, "off"),
        ("userland_father_ldpreload", True, "raw_extraction", 0, True, "off"),
    ],
)
def test_explicit_scenarios_preserve_lifecycle_differences(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario_id: str,
    acquire: bool,
    failure_phase: str | None,
    expected_shutdowns: int,
    expect_facts: bool,
    expected_vm_state: str,
):
    error = RuntimeError(f"{failure_phase} failed")
    facts = {"validated": True}
    events = []
    father_socket = None

    class FakeSocket:
        closed = False

        def close(self):
            if self.closed:
                return
            events.append("backdoor close")
            self.closed = True

    class FakeVMManager:
        state = "off"
        shutdowns = 0

        def snapshot_created_at(self, *_args):
            return "2026-07-22T00:00:00.000Z"

        def open_ssh(self, *_args):
            assert self.state == "on"
            return nullcontext(object())

        def internet_off(self, *_args, **_kwargs):
            pass

        def shutdown_vm(self, *_args):
            if father_socket is not None:
                assert father_socket.closed
            events.append("shutdown")
            self.shutdowns += 1
            self.state = "off"

    fake_vm = FakeVMManager()

    class FakePaths:
        experiments_dir = tmp_path

    class FakeOrchestrator:
        repo_root = tmp_path
        _paths = FakePaths()
        vm_manager = fake_vm
        acquisition_path = None

        def _reset_lab(self, _distro_id):
            fake_vm.state = "on"
            return "lab-ubuntu-22.04"

        def _guest_facts(self, _ssh):
            return {"distro": "Ubuntu", "kernel": "test", "timezone": "UTC"}

        def _run_acquisition(
            self, _vm_name, run_id, _scenario_id, *, before_shutdown=None
        ):
            assert fake_vm.state == "on"
            if father_socket is not None:
                assert not father_socket.closed
            else:
                assert before_shutdown is None
            events.append("memory")
            if failure_phase == "acquisition":
                raise error
            if before_shutdown is not None:
                before_shutdown()
            events.append("shutdown")
            path = tmp_path / run_id / "dumps" / "acquisition.json"
            path.parent.mkdir(parents=True)
            path.write_text("{}\n", encoding="utf-8")
            fake_vm.state = "off"
            self.acquisition_path = str(path)
            return self.acquisition_path

        def _extract_raw_outputs(self, run_id, *_args, **_kwargs):
            assert fake_vm.state == "off"
            if failure_phase == "raw_extraction":
                raise error
            path = tmp_path / run_id / "analysis" / "raw_extraction_status.json"
            path.parent.mkdir(parents=True)
            path.write_text("{}\n", encoding="utf-8")
            return {
                "volatility": {"status": "completed"},
                "tsk": {"status": "completed"},
                "plaso": {"status": "completed"},
            }, path

    def fake_interactive(*_args, **_kwargs):
        if failure_phase == "scenario" and scenario_id == "interactive_shell":
            raise error
        return []

    def fake_father(*_args, **kwargs):
        nonlocal father_socket
        assert kwargs["scenario_id"] == scenario_id
        if failure_phase == "scenario":
            raise error
        father_socket = FakeSocket()
        return facts, father_socket.close

    monkeypatch.setattr(
        "orchestrator.core.orchestrator.command_output", lambda *_args: "test-commit"
    )
    monkeypatch.setattr(
        "orchestrator.core.orchestrator.run_interactive_shell", fake_interactive
    )
    monkeypatch.setattr("orchestrator.core.orchestrator.run_father", fake_father)

    orchestrator = FakeOrchestrator()
    if failure_phase:
        with pytest.raises(RuntimeError) as raised:
            ForensicOrchestrator.run_experiment(
                orchestrator,
                "ubuntu-22.04",
                scenario_id,
                acquire=acquire,
            )
        assert raised.value is error
        result = None
    else:
        result = ForensicOrchestrator.run_experiment(
            orchestrator,
            "ubuntu-22.04",
            scenario_id,
            acquire=acquire,
        )

    manifest_path = next(tmp_path.glob("*/manifest.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert fake_vm.shutdowns == expected_shutdowns
    assert manifest["acquisition_requested"] is acquire
    assert manifest["repository"]["commit"] == "test-commit"
    assert manifest["artifacts"]["command_log"] == "command_log.jsonl"
    assert manifest["artifacts"]["terminal_transcript"] == "terminal_transcript.txt"
    assert ("scenario_facts" in manifest) is expect_facts
    if expect_facts:
        assert manifest["scenario_facts"] == facts
    if failure_phase:
        assert manifest["status"] == "failed"
        assert manifest["failed_phase"] == failure_phase
        assert manifest["timestamps"]["run_ended_at"]
    else:
        assert manifest["status"] == "completed"
        if acquire:
            assert result == orchestrator.acquisition_path
            assert (
                manifest["artifacts"]["acquisition_manifest"]
                == "dumps/acquisition.json"
            )
            assert (
                manifest["artifacts"]["raw_extraction_status"]
                == "analysis/raw_extraction_status.json"
            )
        else:
            assert result is None
            assert "acquisition_manifest" not in manifest["artifacts"]
            assert "raw_extraction_status" not in manifest["artifacts"]
    if failure_phase in ("acquisition", "raw_extraction"):
        assert manifest["scenario_status"] == "completed"
    if failure_phase == "acquisition":
        assert "acquisition_manifest" not in manifest["artifacts"]
        assert "raw_extraction_status" not in manifest["artifacts"]
    elif failure_phase == "raw_extraction":
        assert (
            manifest["artifacts"]["acquisition_manifest"]
            == "dumps/acquisition.json"
        )
        assert "raw_extraction_status" not in manifest["artifacts"]
    if father_socket is not None:
        assert father_socket.closed
        assert events.index("backdoor close") < events.index("shutdown")
        if acquire:
            assert events.index("memory") < events.index("backdoor close")
    assert fake_vm.state == expected_vm_state


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
