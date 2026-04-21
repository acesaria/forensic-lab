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
        key_path: str,
        port: int = 22,
    ) -> None:
        self._ip = ip
        self._user = user
        self._key_path = str(Path(key_path).expanduser())
        self._port = port
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self, timeout: int = 30) -> None:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self._ip,
            username=self._user,
            key_filename=self._key_path,
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
        timeout: int = 120,
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
