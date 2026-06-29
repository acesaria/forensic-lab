"""Shared filesystem-path helpers for clean-baseline comparison."""

from __future__ import annotations

import posixpath
from typing import Any

BASELINE_FILESYSTEM_CLASSES = {
    "deleted_file_candidate",
    "file",
    "preload_configuration",
    "service_unit_file",
    "shared_object",
    "shell_history_log_event",
}


def normalize_baseline_path(value: Any) -> str:
    text = str(value or "").strip()
    if not text or not text.startswith("/"):
        return ""
    if " -> " in text:
        return ""
    if " (deleted)" in text:
        text = text.replace(" (deleted)", "")
    return posixpath.normpath(text)
