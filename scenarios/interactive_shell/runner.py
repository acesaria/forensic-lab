"""Explicit scenario runner for one interactive SSH terminal."""

from __future__ import annotations

from pathlib import Path

from orchestrator.core.ssh_client import SSHClient, TerminalCommandResult
from scenarios.command_log import run_logged_command


SCENARIO_ID = "interactive_shell"
SCENARIO_DIR = "/tmp/forensic-lab/interactive_shell"
ARTIFACT_FILE = f"{SCENARIO_DIR}/artifact.txt"
EXPECTED_FAILURE = "interactive_shell_command_that_does_not_exist"
COMMANDS = (
    'echo "Bash PID: $BASHPID"',
    'echo "Normal terminal output"',
    EXPECTED_FAILURE,
    'echo "Bash PID after failure: $BASHPID"',
    f"mkdir -p {SCENARIO_DIR}",
    f'echo "Interactive shell artifact" > {ARTIFACT_FILE}',
    f"cat {ARTIFACT_FILE}",
)


def run_interactive_shell(
    ssh: SSHClient,
    transcript_path: Path,
    *,
    command_log_path: Path | None = None,
) -> list[TerminalCommandResult]:
    results: list[TerminalCommandResult] = []
    terminal = ssh.open_terminal()
    try:
        with terminal:
            for command in COMMANDS:
                result = run_logged_command(
                    terminal,
                    command_log_path,
                    command,
                    expect_failure=command == EXPECTED_FAILURE,
                )
                results.append(result)
    finally:
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path.write_text(terminal.transcript, encoding="utf-8")
    return results
