# orchestrator/forensics/yara_runner.py
#
# Thin YARA I/O over the vendored Neo23x0 signature-base subset
# (vendor/yara/signature-base/). Compiles the rules with yara-python and scans a
# small set of directories in the mounted/extracted filesystem. Returns raw match
# records; Finding emission happens in evaluation/detect/yara_scan.py.
#
# Scope for scenario_01 (Ubuntu 22.04): scan /tmp and /etc only. yara-python is
# optional -- when absent, scanning degrades to an empty result rather than
# breaking the pipeline.

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

_VENDOR_DIR = Path(__file__).resolve().parents[2] / "vendor" / "yara" / "signature-base"

# Hardcoded for scenario_01; relative to the mount root passed by the caller.
DEFAULT_SCAN_DIRS: tuple[str, ...] = ("tmp", "etc")

# Don't read whole disks into RAM: skip oversized files (rules here target small
# payloads like the malicious .so).
_MAX_FILE_BYTES = 32 * 1024 * 1024


def vendored_rules_dir() -> Path:
    return _VENDOR_DIR


def pinned_commit() -> str | None:
    f = _VENDOR_DIR / "COMMIT.txt"
    if not f.is_file():
        return None
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line
    return None


def compile_rules(rules_dir: Path | None = None) -> Any | None:
    # Compile every .yar/.yara under the vendored tree into one ruleset. Returns
    # None if yara-python is missing or no rules compile.
    try:
        import yara  # type: ignore
    except ImportError:
        _log.warning("yara-python not installed; YARA scan skipped")
        return None
    d = rules_dir or vendored_rules_dir()
    if not d.is_dir():
        _log.warning("vendored YARA rules dir missing: %s", d)
        return None
    filepaths = {
        p.stem: str(p)
        for p in sorted(d.rglob("*.yar")) + sorted(d.rglob("*.yara"))
    }
    if not filepaths:
        return None
    try:
        return yara.compile(filepaths=filepaths)
    except Exception as exc:  # pragma: no cover - depends on optional dep
        _log.warning("YARA compilation failed: %s", exc)
        return None


def _iter_files(roots: list[Path]):
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.is_file() and not p.is_symlink():
                try:
                    if p.stat().st_size <= _MAX_FILE_BYTES:
                        yield p
                except OSError:
                    continue


def scan_paths(rules: Any, roots: list[Path]) -> list[dict[str, Any]]:
    # Returns one record per (file, matching rule): the path scanned, the rule
    # name, its namespace, tags, and the rule's meta dict.
    matches: list[dict[str, Any]] = []
    if rules is None:
        return matches
    for path in _iter_files(roots):
        try:
            hits = rules.match(str(path))
        except Exception:  # pragma: no cover - per-file scan error, keep going
            continue
        for hit in hits:
            matches.append(
                {
                    "path": str(path),
                    "rule": getattr(hit, "rule", str(hit)),
                    "namespace": getattr(hit, "namespace", ""),
                    "tags": list(getattr(hit, "tags", []) or []),
                    "meta": dict(getattr(hit, "meta", {}) or {}),
                }
            )
    return matches


def run(mount_root: Path, scan_dirs: tuple[str, ...] = DEFAULT_SCAN_DIRS,
        rules_dir: Path | None = None) -> list[dict[str, Any]]:
    # Convenience entry: compile vendored rules and scan mount_root/<dir> for each
    # configured dir. mount_root is where the acquired FS is mounted/extracted.
    rules = compile_rules(rules_dir)
    roots = [mount_root / d for d in scan_dirs]
    return scan_paths(rules, roots)
