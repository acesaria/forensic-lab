# orchestrator/forensics/pipeline_config.py
#
# Reproducibility config: pinned tool versions and rule-set refs from
# pipeline.yaml, the ruleset hash recorded with run outputs, and the installed
# tool version check used by `cli.py verify`.

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

_PKG_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _PKG_DIR.parent.parent


def load_pipeline_config(path: str | Path | None = None) -> dict[str, Any]:
    p = Path(path) if path else _PKG_DIR / "pipeline.yaml"
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def ruleset_hash(pipeline_cfg: dict[str, Any], repo_root: Path = _REPO_ROOT) -> str:
    # Stable hash over every rule file the detectors load, plus the pinned refs,
    # so a rule change is visible in run outputs.
    rs = pipeline_cfg.get("rulesets", {})
    h = hashlib.sha256()
    h.update(str(rs.get("sigma_ref", "")).encode())
    files: list[Path] = []
    rule_dirs = list(rs.get("sigma_rule_dirs", [])) + list(rs.get("sigma_vendored_dirs", []))
    yara_dir = rs.get("yara_rules_dir")
    if yara_dir:
        rule_dirs.append(yara_dir)
    for d in rule_dirs:
        base = (repo_root / d)
        if base.is_dir():
            files.extend(sorted(base.rglob("*.yml")))
            files.extend(sorted(base.rglob("*.yaml")))
            files.extend(sorted(base.rglob("*.yar")))
            files.extend(sorted(base.rglob("*.yara")))
            commit = base.parent / "COMMIT.txt"  # pin file for vendored trees
            if commit.is_file():
                files.append(commit)
    for f in rs.get("tagging_files", []):
        p = repo_root / f
        if p.is_file():
            files.append(p)
    for f in sorted(set(files)):
        h.update(f.read_bytes())
    return "sha256:" + h.hexdigest()


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
