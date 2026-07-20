"""Explicit scenario runner for one interactive SSH terminal."""

from __future__ import annotations

from pathlib import Path

from orchestrator.core.ssh_client import SSHClient, TerminalCommandResult
from scenarios.command_log import log_command, utc_now


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
    run_id: str | None = None,
) -> list[TerminalCommandResult]:
    results: list[TerminalCommandResult] = []
    terminal = ssh.open_terminal()
    try:
        with terminal:
            for index, command in enumerate(COMMANDS, start=1):
                started_at = utc_now()
                try:
                    result = terminal.run(command)
                except Exception as exc:
                    log_command(
                        command_log_path,
                        run_id,
                        SCENARIO_ID,
                        index,
                        command,
                        started_at,
                        status="failure",
                        error=str(exc),
                    )
                    raise

                results.append(result)
                expected_failure = command == EXPECTED_FAILURE
                status = "success"
                if expected_failure and result.exit_code != 0:
                    status = "tolerated_failure"
                elif result.exit_code != 0 or expected_failure:
                    status = "failure"
                log_command(
                    command_log_path,
                    run_id,
                    SCENARIO_ID,
                    index,
                    command,
                    started_at,
                    status=status,
                    result=result,
                )
                if status == "failure":
                    raise RuntimeError(
                        f"unexpected command result ({result.exit_code}): {command}"
                    )
    finally:
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        transcript_path.write_text(terminal.transcript, encoding="utf-8")
    return results
