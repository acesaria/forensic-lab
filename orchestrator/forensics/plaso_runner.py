# orchestrator/forensics/plaso_runner.py
#
# Thin wrapper around Plaso (log2timeline + psort).
# No classes, no state -- just plain functions called by the evaluator.
# Filtering and querying happen downstream; this module only produces and
# loads the JSON-line timeline.
#
# TODO: extundelete is intentionally NOT implemented for scenario_01. It may
# be added later only as an advanced deleted-file recovery demonstration,
# particularly to show journal-aware recovery on ext4. Out of scope for the
# generic Plaso pipeline.

import json
import logging
import shutil
import subprocess
from pathlib import Path

_log = logging.getLogger(__name__)


def resolve_binary(name_or_path: str) -> str:
    resolved = shutil.which(name_or_path) or name_or_path
    if not Path(resolved).is_file():
        raise FileNotFoundError(
            f"Plaso binary not found: {name_or_path!r}. "
            "Install plaso or add it to PATH."
        )
    return resolved


def default_linux_filter() -> Path:
    # Stable default so callers (probe, evaluator) don't hardcode relative paths.
    return Path(__file__).resolve().parent / "filters" / "linux_common.yaml"


def verify_plaso_inputs(
    log2timeline_bin: str = "log2timeline",
    psort_bin: str = "psort",
    file_filter: Path | None = None,
) -> None:
    # Cheap pre-flight: catch missing binaries or a typo in a filter path
    # BEFORE kicking off a multi-minute log2timeline run. Safe to call from
    # setup/probe paths.
    resolve_binary(log2timeline_bin)
    resolve_binary(psort_bin)
    if file_filter is not None and not file_filter.is_file():
        raise FileNotFoundError(
            f"Plaso file filter not found: {file_filter}. "
            "Expected a YAML filter alongside the runner."
        )


def run_log2timeline(
    disk_path: Path,
    storage_path: Path,
    parsers: str = "text/bash_history, text/syslog, text/syslog_traditional, systemd_journal, filestat",
    log2timeline_bin: str = "log2timeline",
    partitions: str = "all",
    file_filter: Path | None = None,
) -> dict:
    binary = resolve_binary(log2timeline_bin)
    storage_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        binary,
        "--parsers",
        parsers,
        "--hashers",
        "none",
        "--partitions",
        partitions,
    ]
    if file_filter is not None:
        if not file_filter.is_file():
            raise FileNotFoundError(f"Plaso file filter not found: {file_filter}")
        cmd += ["--file-filter", str(file_filter)]
    cmd += ["--storage-file", str(storage_path), str(disk_path)]

    _log.debug("log2timeline: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"log2timeline failed for {disk_path.name}:\n"
            f"{result.stderr.strip() or '(no output)'}"
        )

    return {
        "command": cmd,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "storage_path": str(storage_path),
        "disk_path": str(disk_path),
        "parsers": parsers,
        "file_filter": str(file_filter) if file_filter is not None else None,
    }


def run_psort(
    storage_path: Path,
    output_path: Path,
    psort_bin: str = "psort",
) -> dict:
    binary = resolve_binary(psort_bin)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [binary, "-o", "json_line", "-w", str(output_path), str(storage_path)]
    _log.debug("psort: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"psort failed for {storage_path.name}:\n"
            f"{result.stderr.strip() or '(no output)'}"
        )

    return {
        "command": cmd,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "storage_path": str(storage_path),
        "output_path": str(output_path),
        "format": "json_line",
    }


def read_timeline(output_path: Path) -> list[dict]:
    events: list[dict] = []
    with output_path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"invalid JSON in {output_path} at line {lineno}: {exc}"
                ) from exc
            if isinstance(entry, dict):
                events.append(entry)
    return events


def run_timeline(
    disk_path: Path,
    storage_path: Path,
    output_path: Path,
    parsers: str = "bash,syslog,linux_os_log",
    log2timeline_bin: str = "log2timeline",
    psort_bin: str = "psort",
    file_filter: Path | None = None,
) -> dict:
    log2timeline_result = run_log2timeline(
        disk_path=disk_path,
        storage_path=storage_path,
        parsers=parsers,
        log2timeline_bin=log2timeline_bin,
        file_filter=file_filter,
    )
    psort_result = run_psort(
        storage_path=storage_path,
        output_path=output_path,
        psort_bin=psort_bin,
    )
    events = read_timeline(output_path)
    return {
        "log2timeline": log2timeline_result,
        "psort": psort_result,
        "events": events,
    }
