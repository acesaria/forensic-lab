import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from orchestrator.core.paths import ProjectPaths
from orchestrator.core.provenance import command_output
from orchestrator.forensics.dumper import Dumper


def test_memory_dump_precreates_readable_user_file_without_sudo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    paths = ProjectPaths(
        repo_root=tmp_path,
        shared_dir=tmp_path / "shared",
        state_dir=tmp_path / "state",
        ssh_key=tmp_path / "ssh_key",
        ssh_pub_key=tmp_path / "ssh_key.pub",
    )
    dumper = Dumper(paths)
    dest = tmp_path / "run" / "dumps" / "memory" / "mem.raw"
    payload = b"memory image"
    commands = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        if command == ["virsh", "--version"]:
            return subprocess.CompletedProcess(command, 0, "10.0.0\n", "")
        assert dest.exists()
        assert dest.stat().st_mode & 0o777 == 0o600
        dest.write_bytes(payload)
        return subprocess.CompletedProcess(command, 0, "dumped\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    metadata = dumper.acquire_memory("lab-vm", dest)

    digest = hashlib.sha256(payload).hexdigest()
    assert dest.read_bytes() == payload
    assert metadata["sha256"] == digest
    assert metadata["verified"] is False
    assert all(command[0] != "sudo" for command in commands)
    # virsh_dump_status.json is a failure sidecar only; a successful run
    # leaves no status file, but does leave a checkable hashes.txt.
    assert not (dest.parent / "virsh_dump_status.json").exists()
    assert (dest.parent / "hashes.txt").read_text(encoding="utf-8") == (
        f"{digest}  {dest.name}\n"
    )


def test_ewfverify_failure_is_preserved(
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

    with pytest.raises(RuntimeError, match="ewfverify failed"):
        Dumper._run_ewfverify(
            object.__new__(Dumper),
            first_segment,
            str(tmp_path / "evidence"),
            segment_metadata=[],
        )

    status = json.loads(
        (tmp_path / "ewfverify_status.json").read_text(encoding="utf-8")
    )
    assert status["status"] == "failed"
    assert status["exit_status"] == 3
    assert status["stdout"] == "verification stdout\n"
    assert status["stderr"] == "verification stderr\n"


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
    verification = Dumper._run_ewfverify(
        object.__new__(Dumper),
        first_segment,
        str(tmp_path / "evidence"),
        segment_metadata=[],
    )

    assert verification["calculated_sha256"] == digest
    # ewfverify_status.json is a failure sidecar only; a successful verify
    # leaves no status file.
    assert not (tmp_path / "ewfverify_status.json").exists()

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 0, "no hash here\n", ""
        ),
    )
    with pytest.raises(RuntimeError, match="ewfverify failed"):
        Dumper._run_ewfverify(
            object.__new__(Dumper),
            first_segment,
            str(tmp_path / "evidence"),
            segment_metadata=[],
        )


def test_provenance_output_failures_remain_distinguishable(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        "orchestrator.core.provenance.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["probe"], 2, "version stdout", "version stderr"
        ),
    )
    assert command_output(["probe"], allow_nonzero=True) == (
        "version stdout\nversion stderr"
    )


def test_qemu_virtual_size_requires_positive_integer(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        "orchestrator.forensics.dumper.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["qemu-img"], 0, '{"format": "qcow2"}', "qemu diagnostic"
        ),
    )

    with pytest.raises(RuntimeError, match="positive integer virtual-size") as exc:
        Dumper._qemu_virtual_size(Path("evidence.qcow2"))

    assert "qemu diagnostic" in str(exc.value)
