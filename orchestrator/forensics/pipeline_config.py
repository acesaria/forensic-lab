"""Raw-tool executable resolution."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

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
