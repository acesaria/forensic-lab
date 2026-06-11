# orchestrator/evaluation/extract/plaso.py
#
# Plaso extraction wrapper (Phase 3.1 step 1). Reuses the in-tree, tested
# plaso_runner (log2timeline + psort -o json_line) and returns normalized
# JSON-L events. Extraction is GT-blind by construction; the detector consumes
# the events without any planted value.

from __future__ import annotations

from pathlib import Path
from typing import Any

from orchestrator.forensics.plaso_runner import (
    default_linux_filter,
    read_timeline,
    run_log2timeline,
    run_psort,
    verify_plaso_inputs,
)


def extract_timeline(
    disk_path: Path,
    storage_path: Path,
    timeline_path: Path,
    *,
    parsers: str | None = None,
    file_filter: Path | None = None,
) -> list[dict[str, Any]]:
    if file_filter is None:
        file_filter = default_linux_filter()
    verify_plaso_inputs(file_filter=file_filter)
    kwargs: dict[str, Any] = {
        "disk_path": disk_path,
        "storage_path": storage_path,
        "file_filter": file_filter,
    }
    if parsers:
        kwargs["parsers"] = parsers
    run_log2timeline(**kwargs)
    run_psort(storage_path=storage_path, output_path=timeline_path)
    return read_timeline(timeline_path)


def load_cached_timeline(timeline_path: Path) -> list[dict[str, Any]]:
    return read_timeline(timeline_path)
