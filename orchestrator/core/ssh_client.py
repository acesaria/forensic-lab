"""
orchestrator/core/ssh_client.py

Thin paramiko wrapper for communicating with lab VMs.
Handles connection, command execution, and file transfer.

Keeps things simple: one connection per SSHClient instance,
called by vm_manager and orchestrator only.
"""

import re
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, TextIO, Tuple

import paramiko

from orchestrator.core import console


@dataclass(frozen=True)
class TerminalCommandResult:
    command: str
    combined_output: str
    exit_code: int


class SSHTerminal:
    """One interactive PTY shell used for several commands."""

    _CONTROL_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

    def __init__(
        self,
        channel: paramiko.Channel,
        output: TextIO | None,
        timeout: int,
    ) -> None:
        self._channel = channel
        self._output = output
        self._timeout = timeout
        self._transcript: list[str] = []
        token = secrets.token_hex(8)
        self._prompt = f"__FORENSIC_LAB_{token}__"
        self._prompt_re = re.compile(re.escape(self._prompt) + r"(\d+)__ ")

        # Observe the stock prompt first. It signals readiness but contains no
        # per-command status, so replace only PS1 with a status-bearing prompt.
        self._read_until_idle(timeout)
        self._send(f"PS1='{self._prompt}$?__ '")
        self._read_until_prompt(timeout)

    @property
    def transcript(self) -> str:
        return "".join(self._transcript)

    def run(self, command: str, timeout: int | None = None) -> TerminalCommandResult:
        if "\n" in command or "\r" in command:
            raise ValueError("terminal command must be one line")
        if self._channel.closed:
            raise RuntimeError("interactive terminal is closed")

        self._display(f"$ {command}\n", prompt=True)
        self._send(command)
        raw, exit_code = self._read_until_prompt(timeout or self._timeout)
        normalized = self._CONTROL_RE.sub("", raw)
        normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
        prompt = self._prompt_re.search(normalized)
        assert prompt is not None
        before_prompt = normalized[: prompt.start()]
        _echo, separator, combined_output = before_prompt.partition("\n")
        if not separator:
            combined_output = ""
        result = TerminalCommandResult(
            command=command,
            combined_output=combined_output.strip("\n"),
            exit_code=exit_code,
        )
        if result.combined_output:
            self._display(f"{result.combined_output}\n")
        if result.exit_code != 0:
            self._display(f"[exit {result.exit_code}]\n")
        return result

    def close(self) -> None:
        if self._channel.closed:
            return
        self._send("exit")
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            if self._channel.recv_ready():
                self._receive()
                continue
            if self._channel.exit_status_ready() or self._channel.closed:
                self._channel.close()
                return
            time.sleep(0.02)
        self._channel.close()
        raise TimeoutError("interactive shell did not exit normally")

    def _send(self, line: str) -> None:
        self._channel.sendall((line + "\n").encode())

    def _receive(self) -> str:
        text = self._channel.recv(4096).decode(errors="replace")
        return text

    def _display(self, text: str, *, prompt: bool = False) -> None:
        self._transcript.append(text)
        if self._output is not None:
            self._output.write(console.format_terminal(text, prompt=prompt))
            self._output.flush()

    def _read_until_idle(self, timeout: int, idle: float = 0.4) -> str:
        started = time.monotonic()
        last_data: float | None = None
        received = ""
        while time.monotonic() - started < timeout:
            if self._channel.recv_ready():
                received += self._receive()
                last_data = time.monotonic()
                continue
            if last_data is not None and time.monotonic() - last_data >= idle:
                return received
            if self._channel.closed:
                break
            time.sleep(0.02)
        raise TimeoutError("interactive shell did not present its initial prompt")

    def _read_until_prompt(self, timeout: int) -> tuple[str, int]:
        deadline = time.monotonic() + timeout
        received = ""
        while time.monotonic() < deadline:
            if self._channel.recv_ready():
                received += self._receive()
                match = self._prompt_re.search(received)
                if match is not None:
                    return received, int(match.group(1))
                continue
            if self._channel.closed:
                break
            time.sleep(0.02)
        raise TimeoutError(
            "interactive command did not return to the shell prompt; "
            f"buffered output: {received[-500:]!r}"
        )

    def __enter__(self) -> "SSHTerminal":
        return self

    def __exit__(self, *_) -> None:
        self.close()


class SSHClient:
    def __init__(
        self,
        ip: str,
        user: str,
        key_path: Path,
        port: int = 22,
    ) -> None:
        self._ip = ip
        self._user = user
        # key_path is already absolute -- normalization happens in load_config().
        self._key_path = key_path
        self._port = port
        self._client: Optional[paramiko.SSHClient] = None

    @property
    def host(self) -> str:
        return self._ip

    @property
    def port(self) -> int:
        return self._port

    def connect(self, timeout: int = 30) -> None:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self._ip,
            username=self._user,
            key_filename=str(self._key_path),
            port=self._port,
            timeout=timeout,
            banner_timeout=timeout,
        )
        self._client = client

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def run(
        self,
        cmd: str,
        timeout: int = 300,
    ) -> Tuple[int, str, str]:
        """
        Run a command on the remote VM.
        Returns (exit_code, stdout, stderr).
        """
        if self._client is None:
            raise RuntimeError("SSHClient not connected")

        _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        return exit_code, stdout.read().decode(), stderr.read().decode()

    def run_checked(
        self,
        cmd: str,
        timeout: int = 120,
    ) -> str:
        """
        Run a command and raise on non-zero exit.
        Returns stdout as string.
        """
        code, out, err = self.run(cmd, timeout=timeout)
        if code != 0:
            raise RuntimeError(
                f"Command failed (exit {code}): {cmd}\n{err.strip()}"
            )
        return out.strip()

    def open_terminal(
        self,
        timeout: int = 300,
        output: TextIO | None = sys.stdout,
    ) -> SSHTerminal:
        """Open one PTY-backed login shell for multiple commands."""
        if self._client is None:
            raise RuntimeError("SSHClient not connected")
        channel = self._client.invoke_shell(term="xterm", width=240, height=60)
        return SSHTerminal(channel, output, timeout)

    def put(self, local: Path, remote: str) -> None:
        """Upload a local file to the VM via SFTP."""
        if self._client is None:
            raise RuntimeError("SSHClient not connected")
        sftp = self._client.open_sftp()
        try:
            sftp.put(str(local), remote)
        finally:
            sftp.close()

    def get(self, remote: str, local: Path) -> None:
        """Download a file from the VM via SFTP."""
        if self._client is None:
            raise RuntimeError("SSHClient not connected")
        sftp = self._client.open_sftp()
        try:
            sftp.get(remote, str(local))
        finally:
            sftp.close()

    def __enter__(self) -> "SSHClient":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()
