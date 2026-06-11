"""
orchestrator/core/ssh_client.py

Thin paramiko wrapper for communicating with lab VMs.
Handles connection, command execution, and file transfer.

Keeps things simple: one connection per SSHClient instance,
called by vm_manager and orchestrator only.
"""

import re
import time
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
        # Optional persistent interactive (PTY) shell. Distinct from run(), which
        # is one-shot exec_command. The interactive shell exists so an attacker's
        # commands are typed into a real login shell and recorded in
        # ~/.bash_history -- a forensic artifact a non-interactive exec never
        # produces. Reverse-shell launch deliberately stays on run() (no PTY) so
        # the backgrounded job survives channel close.
        self._shell: Optional[paramiko.Channel] = None

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
        if self._shell is not None:
            self.close_shell()
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

    # ------------------------------------------------------------------
    # Interactive (PTY) shell. Used by attack scenarios so typed commands
    # land in ~/.bash_history; not used for control-plane SFTP/exec calls.
    # The mechanism is deliberately vanilla and low-footprint: open a stock
    # interactive shell, type the commands, and let bash auto-save history on
    # exit. No PS1/PROMPT_COMMAND/HISTTIMEFORMAT scaffolding, so the on-disk
    # ~/.bash_history is exactly what stock bash writes (an undated command
    # list -- the default-config artifact a forensic examiner would find).
    # ------------------------------------------------------------------

    # Strips terminal control sequences from captured output.
    _ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
    # A trailing default bash prompt line ends with "$ " (or "# " for root).
    _PROMPT_RE = re.compile(r"[\$#]\s*$")

    def open_shell(self, timeout: int = 30) -> None:
        """Open a stock interactive login shell on the VM.

        No environment is altered: bash uses its default HISTFILE/HISTSIZE/
        HISTCONTROL and saves history on exit. A wide PTY avoids line-wrapping
        the echoed command, which run_shell strips when capturing output.
        """
        if self._client is None:
            raise RuntimeError("SSHClient not connected")
        chan = self._client.invoke_shell(width=240, height=60)
        chan.settimeout(timeout)
        self._shell = chan
        # Consume the login banner / MOTD / first prompt so the first run_shell
        # starts on a clean buffer.
        self._read_until_idle(timeout=timeout)

    def run_shell(self, cmd: str, timeout: int = 60) -> Tuple[int, str]:
        """Run a command in the interactive shell. Returns (exit_code, output).

        The command is sent verbatim (a multi-line atomic runs line by line,
        exactly as an attacker would paste it) and recorded in ~/.bash_history.
        Output is read until the channel goes idle, then the echoed command and
        the trailing prompt are stripped. The exit status is NOT captured in
        this vanilla mode (probing it would add a typed command); the returned
        code is always 0, so callers that gate on it treat interactive steps as
        succeeding and rely on downstream artifacts for verification.
        """
        if self._shell is None:
            raise RuntimeError("interactive shell not open")
        self._shell.send(cmd + "\n")
        raw = self._read_until_idle(timeout=timeout)
        return 0, self._clean(raw, cmd)

    def close_shell(self) -> None:
        """Send exit so bash saves ~/.bash_history on logout, then close.

        Draining until the channel reports closed gives the save-on-exit write
        time to land before the channel drops, so the history artifact survives
        even on a partial run.
        """
        if self._shell is None:
            return
        try:
            self._shell.send("exit\n")
            self._drain_until_closed(cap=1.0)
        finally:
            self._shell.close()
            self._shell = None

    def _read_until_idle(self, timeout: int = 60, idle: float = 0.5) -> str:
        # Accumulate until no new bytes arrive for `idle` seconds. With terminal
        # echo on, even a no-output command produces the echoed line plus the
        # next prompt, so the buffer is never empty before quiescence.
        assert self._shell is not None
        buf = ""
        last = None
        start = time.time()
        while True:
            if self._shell.recv_ready():
                buf += self._shell.recv(4096).decode(errors="replace")
                last = time.time()
            elif last is not None and time.time() - last >= idle:
                return buf
            elif time.time() - start > timeout:
                raise TimeoutError(
                    f"interactive read timed out; buffered: {buf[-500:]!r}"
                )
            else:
                time.sleep(0.05)

    def _clean(self, raw: str, sent: str) -> str:
        # Drop the echoed command (the prompt may be prefixed on the same line,
        # so match the line that ENDS with the command's last line) and the
        # trailing prompt; return the command's own output.
        text = self._ANSI_RE.sub("", raw).replace("\r\n", "\n").replace("\r", "\n")
        lines = text.split("\n")
        last_sent = sent.split("\n")[-1].strip()
        start = 0
        for idx, line in enumerate(lines):
            if last_sent and line.rstrip().endswith(last_sent):
                start = idx + 1
                break
        body = lines[start:]
        while body and (not body[-1].strip() or self._PROMPT_RE.search(body[-1])):
            body.pop()
        return "\n".join(body).strip()

    def _drain_until_closed(self, cap: float = 1.0) -> None:
        if self._shell is None:
            return
        end = time.time() + cap
        while time.time() < end:
            if self._shell.recv_ready():
                if not self._shell.recv(4096):
                    return
            elif self._shell.exit_status_ready():
                return
            else:
                time.sleep(0.05)

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
