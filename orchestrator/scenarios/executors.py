"""Small executors used by the declarative scenario engine."""

from __future__ import annotations

import posixpath
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


@runtime_checkable
class ScenarioExecutor(Protocol):
    def run(self, command: str, timeout: int = 120) -> CommandResult:
        ...

    def put(self, local: Path, remote: str) -> None:
        ...


class LocalExecutor:
    """Executor for safe local tests and toy scenarios.

    Production VM execution can pass an adapter around SSHClient with the same
    run/put methods.
    """

    def __init__(self, cwd: str | Path | None = None) -> None:
        self.cwd = Path(cwd) if cwd is not None else None

    def run(self, command: str, timeout: int = 120) -> CommandResult:
        result = subprocess.run(
            command,
            shell=True,
            cwd=self.cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return CommandResult(result.returncode, result.stdout, result.stderr)

    def put(self, local: Path, remote: str) -> None:
        dest = Path(remote)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(local, dest)


class SSHClientExecutor:
    """Adapter around orchestrator.core.ssh_client.SSHClient.

    The scenario engine depends only on ScenarioExecutor, so VM-backed runs can
    reuse the existing SSH client without coupling the loader/runtime to VM
    lifecycle code.
    """

    def __init__(self, ssh_client) -> None:
        self.ssh_client = ssh_client

    def run(self, command: str, timeout: int = 120) -> CommandResult:
        exit_code, stdout, stderr = self.ssh_client.run(command, timeout=timeout)
        return CommandResult(exit_code, stdout, stderr)

    def run_in_terminal(self, command: str, timeout: int = 120) -> CommandResult:
        exit_code, transcript = self.ssh_client.run_in_terminal(
            command, timeout=timeout
        )
        return CommandResult(exit_code, transcript, "")

    def put(self, local: Path, remote: str) -> None:
        parent = posixpath.dirname(remote)
        if parent:
            code, _out, err = self.ssh_client.run(
                f"mkdir -p {shlex.quote(parent)}",
                timeout=30,
            )
            if code != 0:
                raise RuntimeError(f"failed to create remote directory {parent}: {err}")
        self.ssh_client.put(local, remote)
