# orchestrator/forensics/pipeline_config.py
#
# Reproducibility config: pinned raw extraction tool versions from
# pipeline.yaml and the installed tool version check used by `cli.py verify`.

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

_PKG_DIR = Path(__file__).resolve().parent


def load_pipeline_config(path: str | Path | None = None) -> dict[str, Any]:
    p = Path(path) if path else _PKG_DIR / "pipeline.yaml"
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def _probe_version(cmd: list[str]) -> str | None:
    if shutil.which(cmd[0]) is None:
        return None
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return (res.stdout + res.stderr).strip()


def verify_versions(pipeline_cfg: dict[str, Any]) -> list[str]:
    # Returns a list of human-readable mismatch/absence problems. Empty == OK.
    # The pinned version string must appear in the tool's reported version text.
    pins = pipeline_cfg.get("versions", {})
    probes = {
        "plaso": ["log2timeline", "--version"],
        "volatility3": ["vol3", "--help"],
        "sleuthkit": ["fls", "-V"],
    }
    problems: list[str] = []
    for tool, pin in pins.items():
        cmd = probes.get(tool)
        if cmd is None:
            continue
        reported = _probe_version(cmd)
        if reported is None:
            problems.append(f"{tool}: not installed (need {pin})")
        elif str(pin) not in reported:
            problems.append(f"{tool}: installed version does not match pin {pin}")
    return problems
