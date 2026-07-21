import hashlib
import json
from contextlib import nullcontext
from pathlib import Path

import pytest

from orchestrator.core.orchestrator import ForensicOrchestrator


def test_acquisition_failure_marks_run_failed_after_completed_scenario(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    error = RuntimeError("acquisition failed")

    class FakeVMManager:
        def snapshot_created_at(self, *_args):
            return "2026-07-21T00:00:00.000Z"

        def open_ssh(self, *_args):
            return nullcontext(object())

        def internet_off(self, *_args, **_kwargs):
            pass

    class FakePaths:
        experiments_dir = tmp_path

    class FakeOrchestrator:
        repo_root = tmp_path
        _paths = FakePaths()
        vm_manager = FakeVMManager()

        def _reset_lab(self, _distro_id):
            return "lab-ubuntu-22.04"

        def _guest_facts(self, _ssh):
            return {"distro": "Ubuntu", "kernel": "test", "timezone": "UTC"}

        def _run_acquisition(self, *_args):
            raise error

    monkeypatch.setattr(
        "orchestrator.core.orchestrator.command_output", lambda *_args: "test-commit"
    )
    monkeypatch.setattr(
        "orchestrator.core.orchestrator.run_interactive_shell",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(RuntimeError) as raised:
        ForensicOrchestrator._run_interactive_shell_experiment(
            FakeOrchestrator(), "ubuntu-22.04", acquire=True
        )

    manifest_path = next(tmp_path.glob("*/manifest.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert raised.value is error
    assert manifest["status"] == "failed"
    assert manifest["scenario_status"] == "completed"
    assert manifest["acquisition_requested"] is True
    assert manifest["failed_phase"] == "acquisition"
    assert manifest["timestamps"]["scenario_ended_at"]
    assert manifest["timestamps"]["run_ended_at"]
    assert "acquisition_manifest" not in manifest["artifacts"]
    assert "raw_extraction_status" not in manifest["artifacts"]


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
