"""
orchestrator/core/ssh_client.py

Thin paramiko wrapper for communicating with lab VMs.
Handles connection, command execution, and file transfer.

Keeps things simple: one connection per SSHClient instance,
called by vm_manager and orchestrator only.
"""

from pathlib import Path
from typing import Optional, Tuple

import paramiko


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

    def run_in_terminal(self, cmd: str, timeout: int = 300) -> Tuple[int, str]:
        """Type one command into interactive Bash and return status + transcript."""
        if self._client is None:
            raise RuntimeError("SSHClient not connected")
        if "\n" in cmd:
            raise ValueError("terminal command must be one line")

        stdin, stdout, stderr = self._client.exec_command(
            "/bin/bash -i",
            get_pty=True,
            timeout=timeout,
        )
        channel = stdout.channel
        try:
            stdin.write(f"{cmd}\nexit\n")
            stdin.flush()
            transcript = stdout.read().decode(errors="replace")
            exit_code = channel.recv_exit_status()
            return exit_code, transcript
        finally:
            stdin.close()
            stdout.close()
            stderr.close()
            channel.close()

    def stream_command_to_file(
        self, cmd: str, dest: Path, timeout: int = 3600
    ) -> int:
        """Run cmd on the VM and stream its raw stdout into dest.

        Returns the number of bytes written; raises on a non-zero remote exit.
        Reads in chunks so a large binary stream (e.g. a live disk image piped
        from dd) is never buffered in memory the way run() would. The remote
        command should keep stderr quiet (e.g. dd status=none) so the channel
        carries only payload bytes; stderr is drained at the end for diagnostics.
        """
        if self._client is None:
            raise RuntimeError("SSHClient not connected")
        _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        channel = stdout.channel
        written = 0
        with open(dest, "wb") as fh:
            for chunk in iter(lambda: stdout.read(4 * 1024 * 1024), b""):
                fh.write(chunk)
                written += len(chunk)
        err = stderr.read().decode(errors="replace").strip()
        code = channel.recv_exit_status()
        if code != 0:
            raise RuntimeError(f"remote command failed (exit {code}): {cmd}\n{err}")
        return written

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
