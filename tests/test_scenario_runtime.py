import hashlib
import json
import re
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import call, MagicMock

import pytest

from orchestrator.core.orchestrator import ForensicOrchestrator
from orchestrator.core.provenance import file_sha256
from scenarios.kernel_diamorphine import runner as diamorphine
from scenarios.kernel_ebpf_badbpf import runner as badbpf
from scenarios.ptrace_fa import runner as ptrace
from scenarios.userland_father_ldpreload import runner as father


@pytest.fixture
def prebuilt_caches(tmp_path: Path) -> dict[str, tuple[Path, list[Path]]]:
    caches = {}
    for scenario_id, filenames in (
        ("userland_father_ldpreload", ("rk.so",)),
        ("kernel_diamorphine", ("diamorphine.ko",)),
        ("kernel_ebpf_badbpf", badbpf.ARTIFACT_NAMES),
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
        elif scenario_id == "kernel_ebpf_badbpf":
            source = badbpf.verify_source()
            build_meta["target"]["kernel"] = "test"
            build_meta["recipe"] = badbpf.build_recipe()
            build_meta["source"].update(
                archive_sha256=source["archive_sha256"],
                xcrypto_sha256=source["xcrypto_sha256"],
            )
        (cache / "build.json").write_text(json.dumps(build_meta), encoding="utf-8")
        caches[scenario_id] = cache, artifacts
    return caches


def test_diamorphine_runner_owns_builder_mechanics(tmp_path: Path):
    ssh = MagicMock()
    ssh.run_checked.return_value = "builder output"
    source = {"commit": "pinned-commit"}

    artifact, stdout = diamorphine.build(ssh, tmp_path, source)

    assert artifact == tmp_path / diamorphine.ARTIFACT_NAME
    assert stdout == "builder output"
    assert ssh.put.call_args_list == [
        call(diamorphine.ARCHIVE, "/tmp/diamorphine-upstream-af494fa.tar"),
        call(diamorphine.BUILD_SCRIPT, "/tmp/diamorphine-build.sh"),
        call(
            diamorphine.COMPATIBILITY_PATCH,
            "/tmp/diamorphine-compatibility.patch",
        ),
    ]
    ssh.run_checked.assert_called_once_with(
        "bash /tmp/diamorphine-build.sh /tmp/diamorphine-upstream-af494fa.tar "
        "/tmp/diamorphine-compatibility.patch /tmp/diamorphine-build",
        timeout=1800,
    )
    ssh.get.assert_called_once_with(
        "/tmp/diamorphine-build/Diamorphine-pinned-commit/diamorphine.ko",
        artifact,
    )
    assert diamorphine.build_recipe() == {
        "sha256": file_sha256(diamorphine.BUILD_SCRIPT)
    }
    facts = {
        "kernel": " kernel ",
        "vermagic": " vermagic ",
        "syscall_dispatch": " x64 ",
    }
    assert diamorphine.build_target(facts) == {
        key: value.strip() for key, value in facts.items()
    }
    with pytest.raises(RuntimeError, match="kernel, vermagic, syscall_dispatch"):
        diamorphine.build_target({})


def test_badbpf_runner_owns_current_builder_recipe(tmp_path: Path):
    ssh = MagicMock()
    ssh.run_checked.return_value = "STEP done\nFACT kernel=test-kernel"
    source = {
        "archive_filename": "badbpf.tar.gz",
        "archive_sha256": "archive-hash",
        "xcrypto_sha256": "xcrypto-hash",
    }

    artifacts, stdout = badbpf.build(ssh, tmp_path, source)

    assert artifacts == tuple(tmp_path / name for name in badbpf.ARTIFACT_NAMES)
    assert stdout == "STEP done\nFACT kernel=test-kernel"
    assert ssh.put.call_args_list == [
        call(badbpf.ROOT / "files/badbpf.tar.gz", "/tmp/badbpf-upstream.tar.gz"),
        call(badbpf.BUILD_SCRIPT, "/tmp/badbpf-build.sh"),
        call(badbpf.XCRYPTO_SOURCE, "/tmp/xcrypto.c"),
    ]
    ssh.run_checked.assert_called_once_with(
        "bash /tmp/badbpf-build.sh /tmp/badbpf-upstream.tar.gz "
        "/tmp/badbpf-build /tmp/xcrypto.c",
        timeout=1800,
    )
    assert ssh.get.call_args_list == [
        call(f"/tmp/badbpf-build/artifacts/{name}", artifact)
        for name, artifact in zip(badbpf.ARTIFACT_NAMES, artifacts, strict=True)
    ]
    record = {
        "recipe": badbpf.build_recipe(),
        "source": {
            "archive_sha256": "archive-hash",
            "xcrypto_sha256": "xcrypto-hash",
        },
    }
    assert badbpf.build_record_is_current(record, source)
    record["recipe"]["sha256"] = "stale"
    assert not badbpf.build_record_is_current(record, source)
    assert badbpf.build_target({"kernel": " test-kernel "}) == {
        "kernel": "test-kernel"
    }
    with pytest.raises(RuntimeError, match="reported no kernel"):
        badbpf.build_target({})


def test_kernel_detection_failure_still_shuts_down_lab():
    orchestrator = object.__new__(ForensicOrchestrator)
    orchestrator.vm_manager = MagicMock()
    error = RuntimeError("SSH unavailable")
    orchestrator.vm_manager.wait_ssh_ready.side_effect = error

    with pytest.raises(RuntimeError) as raised:
        orchestrator._detect_kernel_release("lab-ubuntu-22.04")

    assert raised.value is error
    orchestrator.vm_manager.shutdown_vm.assert_called_once_with(
        "lab-ubuntu-22.04"
    )


def test_diamorphine_uses_direct_tmp_reconnaissance_note(tmp_path: Path, monkeypatch):
    ssh = MagicMock()
    terminal = ssh.open_terminal.return_value
    terminal.transcript = "transcript"
    survey = (
        "hostname=lab-debian-13\n"
        "kernel=test-kernel\n"
        "identity=uid=1000(labuser) gid=1000(labuser)"
    )
    outputs = [
        "test-kernel",
        "0",
        "",
        survey,
        f"{diamorphine.RECON_DIRECTORY_NAME}\n",
        f"{diamorphine.RECON_NOTE_NAME}\n",
        "",
        "",
        "",
        survey,
        "pid=123\nbefore_uid=1000\nbefore=user\nafter_uid=0\nafter=root",
        "Module Size Used by",
    ]
    results = [MagicMock(combined_output=output) for output in outputs]
    run_command = MagicMock(side_effect=results)
    monkeypatch.setattr(diamorphine, "run_logged_command", run_command)
    artifact = tmp_path / diamorphine.ARTIFACT_NAME
    artifact.write_bytes(b"module")

    facts, _cleanup = diamorphine.run_diamorphine(
        ssh,
        tmp_path / "transcript.txt",
        command_log_path=tmp_path / "command_log.jsonl",
        artifact_path=artifact,
        build_record={"target": {"kernel": "test-kernel"}},
    )

    commands = [item.args[2] for item in run_command.call_args_list]
    assert diamorphine.RECON_PARENT == "/tmp"
    assert "mkdir -p -- /tmp/diamorphine_secret_dir" in commands
    assert any(
        "recon_hostname=$(uname -n)" in command
        and "recon_kernel=$(uname -r)" in command
        and "| tee -- /tmp/diamorphine_secret_dir/" in command
        for command in commands
    )
    note = "cat -- /tmp/diamorphine_secret_dir/diamorphine_secret_file.txt"
    assert commands.count(note) == 1
    assert facts["reconnaissance_note_validated"] is True
    assert facts["reconnaissance_parent_path"] == "/tmp"


def test_father_victim_commands_use_direct_tmp(tmp_path: Path, monkeypatch):
    ssh = MagicMock()
    terminal = ssh.open_terminal.return_value
    terminal.transcript = "transcript"
    listing = f"-rw-r--r-- 1 labuser labuser 0 {father.HIDDEN_FILE_NAME}"
    outputs = {
        father.LIST_HIDDEN_DIR: [listing, "total 0"],
    }
    default = iter(["ubuntu-22.04 x86_64"] + [""] * 20)

    def fake_run(_terminal, _log, command, **_kwargs):
        queue = outputs.get(command)
        output = queue.pop(0) if queue else next(default)
        return MagicMock(combined_output=output)

    run_command = MagicMock(side_effect=fake_run)
    monkeypatch.setattr(father, "run_logged_command", run_command)
    monkeypatch.setattr(
        father, "_validate_backdoor", lambda _ssh: (MagicMock(), {"client_port": 54321})
    )

    _facts, _cleanup = father.run_father(
        ssh,
        tmp_path / "transcript.txt",
        command_log_path=tmp_path / "command_log.jsonl",
        artifact_path=tmp_path / father.ARTIFACT_NAME,
        build_record={"target": {"distro_id": "ubuntu-22.04", "arch": "x86_64"}},
    )

    assert father.VICTIM_ARTIFACT == "/tmp/rk.so"
    assert father.HIDDEN_DIR == "/tmp"
    ssh.put.assert_called_once_with(tmp_path / father.ARTIFACT_NAME, "/tmp/rk.so")
    commands = [item.args[2] for item in run_command.call_args_list]
    assert f"touch /tmp/{father.HIDDEN_FILE_NAME}" in commands
    assert "ls -la -- /tmp" in commands
    assert "rm -f -- /tmp/rk.so" in commands
    blob = "\n".join([*commands, father.VICTIM_ARTIFACT])
    assert "forensic-lab" not in blob
    assert "mkdir" not in blob
    assert not re.findall(r"/tmp/[\w.\-]+/", blob)


def test_ptrace_victim_commands_use_direct_tmp(tmp_path: Path, monkeypatch):
    ssh = MagicMock()
    terminal = ssh.open_terminal.return_value
    terminal.transcript = "transcript"
    outputs = iter(
        [
            "ubuntu-22.04 x86_64",
            "",
            "",
            "",
            "labuser",
            "[1] 123\n123",
            "",
            "alive",
        ]
    )
    run_command = MagicMock(
        side_effect=lambda *_args, **_kwargs: MagicMock(
            combined_output=next(outputs)
        )
    )
    monkeypatch.setattr(ptrace, "run_logged_command", run_command)
    monkeypatch.setattr(ptrace, "_open_listener", lambda: MagicMock())
    monkeypatch.setattr(
        ptrace,
        "_accept_reverse_shell",
        lambda _listener, identity: (identity, MagicMock()),
    )

    facts, _cleanup = ptrace.run_ptrace_fa(
        ssh,
        tmp_path / "transcript.txt",
        command_log_path=tmp_path / "command_log.jsonl",
        artifact_paths=tuple(tmp_path / name for name in ptrace.ARTIFACT_NAMES),
        build_record={"target": {"distro_id": "ubuntu-22.04", "arch": "x86_64"}},
    )

    assert facts["victim_pid"] == 123
    assert ptrace.VICTIM_ROOT == "/tmp"
    assert ptrace.VICTIM_ARTIFACTS == (
        "/tmp/ptrace_fa-shellcode_inject_fa",
        "/tmp/ptrace_fa-victim",
    )
    assert ssh.put.call_args_list == [
        call(tmp_path / name, remote)
        for name, remote in zip(
            ptrace.ARTIFACT_NAMES, ptrace.VICTIM_ARTIFACTS, strict=True
        )
    ]
    commands = [item.args[2] for item in run_command.call_args_list]
    assert (
        "install -m 0755 /tmp/ptrace_fa-shellcode_inject_fa /tmp/shellcode_inject_fa"
        in commands
    )
    assert "install -m 0755 /tmp/ptrace_fa-victim /tmp/victim" in commands
    assert "cd /tmp" in commands
    blob = "\n".join([*commands, *ptrace.VICTIM_ARTIFACTS])
    assert "forensic-lab" not in blob
    assert "mkdir" not in blob
    assert not re.findall(r"/tmp/[\w.\-]+/", blob)


def test_ptrace_runner_owns_builder_mechanics(tmp_path: Path):
    ssh = MagicMock()
    ssh.run_checked.side_effect = ["", "builder output"]

    artifacts, stdout = ptrace.build(ssh, tmp_path)

    assert artifacts == tuple(tmp_path / name for name in ptrace.ARTIFACT_NAMES)
    assert stdout == "builder output"
    assert ssh.run_checked.call_args_list == [
        call(
            "rm -rf /tmp/ptrace-fa-source && mkdir -p "
            "/tmp/ptrace-fa-source/src /tmp/ptrace-fa-source/common"
        ),
        call(
            "bash /tmp/ptrace-fa-build.sh /tmp/ptrace-fa-source "
            "/tmp/ptrace-fa-build "
            "0xc0,0xa8,0x64,0x01,0x66,0x68,0x11,0x5c",
            timeout=1800,
        ),
    ]
    assert ssh.put.call_args_list == [
        *[
            call(
                ptrace.FILES_DIR / name,
                f"/tmp/ptrace-fa-source/{name}",
            )
            for name in ptrace.SOURCE_FILES
        ],
        call(ptrace.BUILD_SCRIPT, "/tmp/ptrace-fa-build.sh"),
    ]
    assert ssh.get.call_args_list == [
        call(f"/tmp/ptrace-fa-build/{name}", artifact)
        for name, artifact in zip(ptrace.ARTIFACT_NAMES, artifacts, strict=True)
    ]
    assert ptrace.build_source() == {
        "files": {
            name: file_sha256(ptrace.FILES_DIR / name) for name in ptrace.SOURCE_FILES
        }
    }
    assert ptrace.build_recipe() == {
        "sha256": file_sha256(ptrace.BUILD_SCRIPT),
        "target_hex": "0xc0,0xa8,0x64,0x01,0x66,0x68,0x11,0x5c",
    }


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
        ("interactive_shell", False, "scenario", 0, False, "on"),
        ("interactive_shell", True, None, 0, False, "off"),
        ("ptrace_fa", False, None, 1, True, "off"),
        ("ptrace_fa", False, "scenario", 1, False, "off"),
        ("ptrace_fa", True, None, 0, True, "off"),
        ("ptrace_fa", True, "acquisition", 1, True, "off"),
        ("kernel_diamorphine", False, None, 1, True, "off"),
        ("kernel_diamorphine", False, "scenario", 1, False, "off"),
        ("kernel_diamorphine", True, "acquisition", 1, True, "off"),
        ("kernel_ebpf_badbpf", False, None, 1, True, "off"),
        ("kernel_ebpf_badbpf", False, "scenario", 1, False, "off"),
        ("kernel_ebpf_badbpf", True, "acquisition", 1, True, "off"),
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
    build_scenario = scenario_id
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

    def fake_father(*_args, **_kwargs):
        nonlocal cleanup_socket
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

    def fake_badbpf(*_args, **_kwargs):
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
    monkeypatch.setattr(
        "orchestrator.core.orchestrator.badbpf.run_badbpf", fake_badbpf
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
    (
        "userland_father_ldpreload",
        "ptrace_fa",
        "kernel_diamorphine",
        "kernel_ebpf_badbpf",
    ),
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


def test_father_records_the_established_connection(
    monkeypatch: pytest.MonkeyPatch,
):
    response = MagicMock()
    response.__iter__.side_effect = (
        iter((b"Enjoy the shell!\n",)),
        iter((b"\x1b[0muid=0(root) gid=1337 groups=1337\n",)),
    )
    client = MagicMock()
    client.getsockname.return_value = "192.168.100.1", father.SOURCE_PORT
    client.getpeername.return_value = "192.168.100.41", 22
    client.makefile.return_value.__enter__.return_value = response
    monkeypatch.setattr(
        father.socket,
        "create_connection",
        lambda *_args, **_kwargs: client,
    )
    ssh = type("SSH", (), {"host": "192.168.100.41", "port": 22})()

    connected, facts = father._validate_backdoor(ssh)

    assert connected is client
    assert facts == {
        "client_address": "192.168.100.1",
        "client_port": 54321,
        "server_address": "192.168.100.41",
        "server_port": 22,
    }
    assert client.sendall.call_args_list == [call(father.SHELL_PASSWORD), call(b"id\n")]
