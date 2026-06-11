# orchestrator/evaluation/extract/vol3.py
#
# Volatility 3 extraction wrapper (Phase 3.2). Runs the pinned plugin set with
# JSON renderers via the in-tree VolatilityRunner and returns
# {plugin: [rows]} for the GT-blind vol3 heuristics.

from __future__ import annotations

from pathlib import Path
from typing import Any

from orchestrator.forensics.vol_runner import VolatilityRunner

DEFAULT_PLUGINS = (
    "linux.pslist",
    "linux.psscan",
    "linux.bash",
    "linux.sockstat",
    "linux.netstat",
    "linux.malfind",
    "linux.lsmod",
    "linux.proc.Maps",
)


def extract_plugins(
    vol: VolatilityRunner,
    memory_path: Path,
    distro_id: str,
    plugins: tuple[str, ...] = DEFAULT_PLUGINS,
) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for plugin in plugins:
        try:
            out[plugin] = vol.run_plugin(memory_path, distro_id, plugin)
        except RuntimeError:
            # A plugin missing for this kernel build is not fatal: the heuristics
            # degrade gracefully to whatever plugins did run.
            out[plugin] = []
    return out
