import hashlib
import json
from contextlib import nullcontext
from pathlib import Path

import pytest

from orchestrator.core.orchestrator import ForensicOrchestrator
from orchestrator.core.provenance import file_sha256
from scenarios.kernel_diamorphine import runner as diamorphine


@pytest.fixture
def prebuilt_caches(tmp_path: Path) -> dict[str, tuple[Path, list[Path]]]:
    caches = {}
    for scenario_id, filenames in (
        ("userland_father_ldpreload", ("rk.so",)),
        ("kernel_diamorphine", ("diamorphine.ko",)),
        ("ptrace_fa", ("shellcode_inject_fa", "victim")),
    ):
        cache = tmp_path / "prebuilt/ubuntu-22.04" / scenario_id
        cache.mkdir(parents=True)
        artifacts = []
        for filename in filenames:
            artifact = cache / filename
            artifact.write_bytes(f"test {filename}".encode())
            artifacts.append(artifact)
        build_meta = {
            "artifacts": [
                {
                    "filename": artifact.name,
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }
                for artifact in artifacts
            ],
            "target": {
                "distro_id": "ubuntu-22.04",
                "image_checksum": "test-image",
            },
            "source": {},
        }
        if scenario_id == "kernel_diamorphine":
            build_meta["target"]["kernel"] = "test"
            build_meta["recipe"] = {
                "sha256": file_sha256(diamorphine.BUILD_SCRIPT)
            }
            build_meta["source"]["compatibility_patch_sha256"] = file_sha256(
                diamorphine.COMPATIBILITY_PATCH
            )
        (cache / "build.json").write_text(json.dumps(build_meta), encoding="utf-8")
        caches[scenario_id] = cache, artifacts
    return caches


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
        ("ptrace_fa", False, None, 1, True, "off"),
        ("ptrace_fa", False, "scenario", 1, False, "off"),
        ("ptrace_fa", True, None, 0, True, "off"),
        ("ptrace_fa", True, "acquisition", 1, True, "off"),
        ("kernel_diamorphine", False, None, 1, True, "off"),
        ("kernel_diamorphine", False, "scenario", 1, False, "off"),
        ("kernel_diamorphine", True, "acquisition", 1, True, "off"),
    ],
)
def test_explicit_scenarios_preserve_lifecycle_differences(
    tmp_path: Path,
    prebuilt_caches: dict[str, tuple[Path, list[Path]]],
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
    cleanup_socket = None
    build_scenario = (
        "userland_father_ldpreload"
        if scenario_id.startswith("userland_father")
        else scenario_id
    )
    cache, artifacts = prebuilt_caches.get(build_scenario, (None, []))

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
            if cleanup_socket is not None:
                assert cleanup_socket.closed
            events.append("shutdown")
            self.shutdowns += 1
            self.state = "off"

    fake_vm = FakeVMManager()

    class FakePaths:
        experiments_dir = tmp_path
        shared_dir = tmp_path

    class FakeOrchestrator:
        repo_root = tmp_path
        _paths = FakePaths()
        vm_manager = fake_vm
        acquisition_path = None

        _prebuilt_cache_dir = ForensicOrchestrator._prebuilt_cache_dir
        _display = ForensicOrchestrator._display
        _resolve_prebuilt_input = ForensicOrchestrator._resolve_prebuilt_input
        _stage_run_inputs = ForensicOrchestrator._stage_run_inputs

        def _reset_lab(self, _distro_id):
            fake_vm.state = "on"
            return "lab-ubuntu-22.04"

        def _guest_facts(self, _ssh):
            return {"distro": "Ubuntu", "kernel": "test", "timezone": "UTC"}

        def _run_acquisition(
            self, _vm_name, run_id, _scenario_id, *, before_shutdown=None
        ):
            assert fake_vm.state == "on"
            if cleanup_socket is not None:
                assert not cleanup_socket.closed
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
            return self.acquisition_path, path, path

    def fake_interactive(*_args, **_kwargs):
        if failure_phase == "scenario" and scenario_id == "interactive_shell":
            raise error
        return []

    def fake_father(*_args, **kwargs):
        nonlocal cleanup_socket
        assert kwargs["scenario_id"] == scenario_id
        if failure_phase == "scenario":
            raise error
        cleanup_socket = FakeSocket()
        return facts, cleanup_socket.close

    def fake_ptrace_fa(*_args, **_kwargs):
        nonlocal cleanup_socket
        if failure_phase == "scenario":
            raise error
        cleanup_socket = FakeSocket()
        return facts, cleanup_socket.close

    def fake_diamorphine(*_args, **_kwargs):
        nonlocal cleanup_socket
        if failure_phase == "scenario":
            raise error
        cleanup_socket = FakeSocket()
        return facts, cleanup_socket.close

    monkeypatch.setattr(
        "orchestrator.core.orchestrator.command_output", lambda *_args: "test-commit"
    )
    monkeypatch.setattr(
        "orchestrator.core.orchestrator.load_profile",
        lambda *_: {"image": {"checksum": "test-image"}},
    )
    monkeypatch.setattr(
        "orchestrator.core.orchestrator.run_interactive_shell", fake_interactive
    )
    monkeypatch.setattr("orchestrator.core.orchestrator.father.run_father", fake_father)
    monkeypatch.setattr(
        "orchestrator.core.orchestrator.ptrace.run_ptrace_fa", fake_ptrace_fa
    )
    monkeypatch.setattr(
        "orchestrator.core.orchestrator.diamorphine.run_diamorphine",
        fake_diamorphine,
    )

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
    if build_scenario in prebuilt_caches and not failure_phase:
        assert cache is not None
        staged = manifest["inputs"][0]
        assert (
            manifest_path.parent / staged["build_json"]["path"]
        ).read_bytes() == (cache / "build.json").read_bytes()
        assert [item["sha256"] for item in staged["artifacts"]] == [
            hashlib.sha256(artifact.read_bytes()).hexdigest()
            for artifact in artifacts
        ]
        assert staged["build_json"]["sha256"] == hashlib.sha256(
            (cache / "build.json").read_bytes()
        ).hexdigest()
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
        else:
            assert result is None
            assert "acquisition_manifest" not in manifest["artifacts"]
    if failure_phase == "acquisition":
        assert manifest["scenario_status"] == "completed"
    if failure_phase == "acquisition":
        assert "acquisition_manifest" not in manifest["artifacts"]
    if cleanup_socket is not None:
        assert cleanup_socket.closed
        assert events.index("backdoor close") < events.index("shutdown")
        if acquire:
            assert events.index("memory") < events.index("backdoor close")
    assert fake_vm.state == expected_vm_state


@pytest.mark.parametrize(
    "scenario_id",
    ("userland_father_ldpreload", "ptrace_fa", "kernel_diamorphine"),
)
def test_prebuilt_missing_does_not_reset_victim(tmp_path: Path, scenario_id: str):
    resets = []

    class FakeOrchestrator:
        vm_manager = object()
        _paths = type("Paths", (), {"experiments_dir": tmp_path})()

        def _resolve_prebuilt_input(self, _distro_id, _scenario_id, _filenames):
            return None

        def _reset_lab(self, _distro_id):
            resets.append(True)

    with pytest.raises(RuntimeError, match=r"\.venv/bin/python cli\.py build"):
        ForensicOrchestrator.run_experiment(
            FakeOrchestrator(),
            "ubuntu-22.04",
            scenario_id,
        )
    assert not resets and not any(tmp_path.iterdir())


def test_father_wrong_image_does_not_reset_victim(
    tmp_path: Path,
    prebuilt_caches: dict[str, tuple[Path, list[Path]]],
    monkeypatch: pytest.MonkeyPatch,
):
    resets = []

    class FakePaths:
        experiments_dir = tmp_path / "experiments"
        shared_dir = tmp_path

    class FakeOrchestrator:
        repo_root = tmp_path
        vm_manager = object()
        _paths = FakePaths()

        _prebuilt_cache_dir = ForensicOrchestrator._prebuilt_cache_dir
        _display = ForensicOrchestrator._display
        _resolve_prebuilt_input = ForensicOrchestrator._resolve_prebuilt_input

        def _reset_lab(self, _distro_id):
            resets.append(True)

    monkeypatch.setattr(
        "orchestrator.core.orchestrator.load_profile",
        lambda *_: {"image": {"checksum": "another-image"}},
    )

    with pytest.raises(RuntimeError, match="targets another image"):
        ForensicOrchestrator.run_experiment(
            FakeOrchestrator(),
            "ubuntu-22.04",
            "userland_father_ldpreload",
        )
    assert not resets and not FakePaths.experiments_dir.exists()
