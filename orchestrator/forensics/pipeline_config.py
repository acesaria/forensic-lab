# orchestrator/forensics/pipeline_config.py
#
# Reproducibility config: pinned raw extraction tool versions from
# pipeline.yaml and the installed tool version check used by `cli.py verify`.

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

import yaml

from orchestrator.core.provenance import command_output

_PKG_DIR = Path(__file__).resolve().parent

_RAW_TOOL_SETTINGS = {
    "volatility3": ("vol_bin", "vol3"),
    "mmls": ("mmls_bin", "mmls"),
    "fls": ("fls_bin", "fls"),
    "fsstat": ("fsstat_bin", "fsstat"),
    "log2timeline": ("log2timeline_bin", "log2timeline"),
    "psort": ("psort_bin", "psort"),
}


def load_pipeline_config(path: str | Path | None = None) -> dict[str, Any]:
    p = Path(path) if path else _PKG_DIR / "pipeline.yaml"
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def raw_tool_paths(host_cfg: dict[str, Any]) -> dict[str, str]:
    tools: dict[str, str] = {}
    for tool, (config_key, default) in _RAW_TOOL_SETTINGS.items():
        configured = str(host_cfg.get(config_key, default))
        resolved = shutil.which(configured)
        candidate = Path(configured).expanduser()
        if resolved is None and candidate.is_file():
            resolved = str(candidate.resolve())
        tools[tool] = resolved or configured
    return tools


def reported_version(tool: str, tools: dict[str, str]) -> str | None:
    if tool == "volatility3":
        output = command_output([tools[tool]], allow_nonzero=True)
        if output is None:
            return None
        match = re.search(r"^Volatility 3 Framework\s+([^\s]+)\s*$", output, re.MULTILINE)
        return match.group(1) if match else None

    commands = {
        "plaso": [tools["log2timeline"], "--version"],
        "sleuthkit": [tools["fls"], "-V"],
    }
    output = command_output(commands[tool])
    return output.splitlines()[0] if output else None


def verify_versions(
    pipeline_cfg: dict[str, Any],
    tools: dict[str, str],
) -> list[str]:
    # Returns a list of human-readable mismatch/absence problems. Empty == OK.
    # The pinned version string must appear in the tool's reported version text.
    pins = pipeline_cfg.get("versions", {})
    problems: list[str] = []
    for tool, pin in pins.items():
        if tool not in {"plaso", "volatility3", "sleuthkit"}:
            continue
        reported = reported_version(tool, tools)
        if reported is None:
            problems.append(f"{tool}: not installed (need {pin})")
        elif str(pin) not in reported:
            problems.append(f"{tool}: installed version does not match pin {pin}")
    return problems
