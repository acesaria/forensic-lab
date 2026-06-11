# orchestrator/evaluation/provenance.py
#
# Reproducibility plumbing (Phase 6). Every artifact (image, memory dump,
# storage file, findings, matches) gets a SHA-256 recorded in a per-run
# provenance.json, and the runner verifies installed tool versions match the
# pins in pipeline.yaml.

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return "sha256:" + h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_provenance(run_id: str, artifacts: dict[str, Path], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"run_id": run_id, "artifacts": {}}
    for label, path in artifacts.items():
        p = Path(path)
        out["artifacts"][label] = {
            "path": str(p),
            "sha256": sha256_file(p) if p.is_file() else None,
        }
    if extra:
        out.update(extra)
    return out


def write_provenance(obj: dict[str, Any], out_path: str | Path) -> Path:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return p


# --- version verification ------------------------------------------------

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
        "plaso": ["log2timeline.py", "--version"],
        "volatility3": ["vol", "--help"],
        "sleuthkit": ["fls", "-V"],
    }
    problems: list[str] = []
    for tool, pin in pins.items():
        cmd = probes.get(tool)
        if cmd is None:
            continue  # pysigma / yara_python are python deps, checked elsewhere
        reported = _probe_version(cmd)
        if reported is None:
            problems.append(f"{tool}: not installed (need {pin})")
        elif str(pin) not in reported:
            problems.append(f"{tool}: installed version does not match pin {pin}")
    return problems
