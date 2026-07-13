"""Small shared helpers for forensic provenance records."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_result(
    command: list[str],
    result: subprocess.CompletedProcess[str],
    *,
    include_stdout: bool = True,
    **extra: Any,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "command": command,
        "status": "completed" if result.returncode == 0 else "failed",
        "exit_status": result.returncode,
        "stderr": result.stderr or "",
        **extra,
    }
    if include_stdout or result.returncode != 0:
        record["stdout"] = result.stdout or ""
    return record


def command_output(
    command: list[str],
    *,
    allow_nonzero: bool = False,
    timeout: int = 30,
) -> str | None:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 and not allow_nonzero:
        return None
    output = "\n".join(
        stream.strip()
        for stream in (result.stdout, result.stderr)
        if stream and stream.strip()
    )
    return output or None


def excerpt(text: str, limit: int = 1200) -> str:
    value = (text or "").strip()
    return value if len(value) <= limit else value[: limit - 3] + "..."
