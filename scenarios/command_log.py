"""Append-only logging for commands run by explicit scenario runners."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from orchestrator.core.ssh_client import TerminalCommandResult


def log_command(
    path: Path | None,
    run_id: str | None,
    scenario_id: str,
    index: int,
    command: str,
    started_at: str,
    *,
    status: str,
    result: TerminalCommandResult | None = None,
    error: str | None = None,
) -> None:
    if path is None:
        return
    row = {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "step_id": f"command_{index:02d}",
        "type": "terminal",
        "command": command,
        "combined_output": result.combined_output if result else "",
        "exit_code": result.exit_code if result else None,
        "status": status,
        "started_at": started_at,
        "ended_at": utc_now(),
    }
    if error is not None:
        row["error"] = error
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
