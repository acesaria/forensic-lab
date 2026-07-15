"""Raw-tool executable resolution and live version reporting."""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from orchestrator.core.provenance import command_output

_RAW_TOOL_SETTINGS = {
    "volatility3": ("vol_bin", "vol3"),
    "mmls": ("mmls_bin", "mmls"),
    "fls": ("fls_bin", "fls"),
    "fsstat": ("fsstat_bin", "fsstat"),
    "log2timeline": ("log2timeline_bin", "log2timeline"),
    "psort": ("psort_bin", "psort"),
}


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
        match = re.search(
            r"\bVolatility\s+3(?:\s+Framework)?(?:\s+version)?\s*:?\s+([^\s]+)",
            output,
            re.IGNORECASE,
        )
        return match.group(1) if match else None

    commands = {
        "plaso": [tools["log2timeline"], "--version"],
        "sleuthkit": [tools["fls"], "-V"],
    }
    output = command_output(commands[tool], allow_nonzero=True)
    return output.splitlines()[0] if output else None
