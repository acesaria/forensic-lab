import hashlib
from pathlib import Path

import pytest

from orchestrator.core.orchestrator import ForensicOrchestrator


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
