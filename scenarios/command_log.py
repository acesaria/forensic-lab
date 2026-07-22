"""Append-only logging for commands run by explicit scenario runners."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

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
                "recorded_at": _utc_now(),
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
        "recorded_at": _utc_now(),
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
        "recorded_at": _utc_now(),
        "status": "failure" if error is not None else "success",
    }
    if error is not None:
        row["error"] = error
    _append_record(path, row)


def _append_record(path: Path | None, row: dict[str, object]) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
