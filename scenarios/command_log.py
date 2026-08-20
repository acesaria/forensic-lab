"""Append-only logging for commands run by explicit scenario runners."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path

from orchestrator.core.provenance import utc_now
from orchestrator.core.ssh_client import SSHTerminal, TerminalCommandResult


def run_logged_command(
    terminal: SSHTerminal,
    path: Path | None,
    command: str,
    *,
    timeout: int | None = None,
    expect_failure: bool = False,
) -> TerminalCommandResult:
    """Run and record one terminal command, raising on an unexpected result."""
    try:
        result = terminal.run(command, timeout=timeout)
    except Exception as exc:
        _append_record(
            path,
            {
                "operation": "terminal",
                "recorded_at": utc_now(),
                "status": "failure",
                "command": command,
                "error": str(exc),
            },
        )
        raise

    if expect_failure:
        status = "tolerated_failure" if result.exit_code != 0 else "failure"
    else:
        status = "success" if result.exit_code == 0 else "failure"
    row = {
        "operation": "terminal",
        "recorded_at": utc_now(),
        "status": status,
        "command": command,
        "exit_code": result.exit_code,
    }
    _append_record(path, row)
    if status == "failure":
        raise RuntimeError(
            f"unexpected command result ({result.exit_code}): {command}"
        )
    return result


def record_operation(
    path: Path | None,
    operation: str,
    *,
    error: str | None = None,
) -> None:
    """Record one non-terminal scenario operation."""
    row = {
        "operation": operation,
        "recorded_at": utc_now(),
        "status": "failure" if error is not None else "success",
    }
    if error is not None:
        row["error"] = error
    _append_record(path, row)


@dataclass(frozen=True)
class CommandLog:
    """
    One scenario's terminal bound to its append-only record.

    A runner builds this once and passes it instead of threading the terminal
    and the log path separately through every phase. It only binds the pair;
    the recording itself stays in the two functions above.
    """

    terminal: SSHTerminal
    path: Path | None

    def run(
        self,
        command: str,
        *,
        timeout: int = 180,
        expect_failure: bool = False,
    ) -> TerminalCommandResult:
        return run_logged_command(
            self.terminal,
            self.path,
            command,
            timeout=timeout,
            expect_failure=expect_failure,
        )

    def note(self, operation: str, *, error: str | None = None) -> None:
        record_operation(self.path, operation, error=error)

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        """Bracket one scenario phase with append-only start/end timestamps."""
        self.note(f"phase_{name}_start")
        try:
            yield
        finally:
            self.note(f"phase_{name}_end")


def _append_record(path: Path | None, row: dict[str, object]) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
