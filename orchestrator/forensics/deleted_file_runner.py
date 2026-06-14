# orchestrator/forensics/deleted_file_runner.py
#
# Escalating deleted-file recovery for the "deleted_file" forensic operation.
# Three successive levels, stopping per target as soon as it is recovered:
#
#   Level 1  tsk_recover  metadata-based, safe, any supported FS
#   Level 2  ext4magic    journal-based, ext4 only (supersedes extundelete)
#   Level 3  photorec/scalpel  signature carving, last resort, high FP rate
#
# Pure tool I/O: runs the binaries, walks their output, and decides a per-target
# per-level OUTCOME (found / not_found / not_applicable / tool_error). It returns
# plain result dicts and imports nothing from the evaluation layer, so it stays in
# the forensics layer and never sees ground truth. Finding emission happens in
# orchestrator/evaluation/detect/deleted_file_recovery.py, which maps these
# results to Finding objects (the Prompt-4 runner/detector split).
#
# targets are plain dicts {entity_type, entity_value} handed in by the
# orchestrator (derived from GT deleted_file observables); no GT module is
# imported here.

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

TMPFS_NOTE = (
    "tmpfs has no persistent journal; tsk_recover and journal-based tools cannot "
    "recover tmpfs deletions"
)
CARVE_NOTE = (
    "signature-based carving produces many false positives; treat hits as "
    "candidate evidence only"
)

_VERSION_PROBES: dict[str, list[str]] = {
    "tsk_recover": ["tsk_recover", "-V"],
    "ext4magic": ["ext4magic", "-V"],  # -V prints "ext4magic  version : 0.3.2"
    "photorec": ["photorec", "/version"],
    "scalpel": ["scalpel", "-V"],
}


# --- binary / version helpers --------------------------------------------------


def _which(binary: str) -> str | None:
    return shutil.which(binary)


def _probe_version(cmd: list[str]) -> str | None:
    if _which(cmd[0]) is None:
        return None
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return (res.stdout + res.stderr).strip().splitlines()[0] if (res.stdout or res.stderr) else ""


def tool_versions() -> dict[str, str | None]:
    # Versions of the recovery tools actually present, for provenance.json.
    return {name: _probe_version(cmd) for name, cmd in _VERSION_PROBES.items()}


# --- target / output matching --------------------------------------------------


def _is_tmpfs_target(path: str, partition_info: dict[str, Any]) -> bool:
    # A target is unrecoverable when its filesystem is non-persistent: either the
    # whole acquired partition is tmpfs, or the path lives under a tmpfs mount
    # (passed as tmpfs_mounts, defaulting to the usual volatile mounts).
    if partition_info.get("is_tmpfs"):
        return True
    mounts = partition_info.get("tmpfs_mounts", ["/dev/shm", "/run"])
    return any(path == m or path.startswith(m.rstrip("/") + "/") for m in mounts)


def _iter_files(root: Path):
    if root.is_dir():
        for p in root.rglob("*"):
            if p.is_file():
                yield p


def _match_target_in_dir(target_path: str, root: Path) -> str | None:
    # Levels 1-2 preserve path structure: a match is a recovered file whose
    # filesystem-relative path equals the target, else one with the same basename.
    target = "/" + target_path.lstrip("/")
    base = target.rsplit("/", 1)[-1]
    fallback: str | None = None
    for p in _iter_files(root):
        rel = "/" + str(p.relative_to(root))
        if rel == target or rel.endswith(target):
            return str(p)
        if p.name == base and fallback is None:
            fallback = str(p)
    return fallback


def _match_carved(target_path: str, root: Path) -> str | None:
    # Level 3 carving loses names: match by file extension (a carved file of the
    # target's type is a candidate). No extension -> any carved file is a weak
    # candidate. This is deliberately permissive; high_fp_risk flags the caveat.
    base = target_path.rsplit("/", 1)[-1]
    ext = base.rsplit(".", 1)[-1].lower() if "." in base else ""
    first: str | None = None
    for p in _iter_files(root):
        if first is None:
            first = str(p)
        if ext and p.suffix.lower().lstrip(".") == ext:
            return str(p)
    return None if ext else first


# --- level executors (best-effort; return (recovered_root, error)) -------------


def _run_tsk_recover(image_path: Path, partition_info: dict[str, Any], out: Path) -> tuple[Path | None, str | None]:
    if _which("tsk_recover") is None:
        return None, "tsk_recover not installed"
    out.mkdir(parents=True, exist_ok=True)
    cmd = ["tsk_recover", "-e"]  # -e: every file, allocated + unallocated
    offset = int(partition_info.get("offset_sectors") or 0)
    if offset:
        cmd += ["-o", str(offset)]
    cmd += [str(image_path), str(out)]
    return _run(cmd, out)


def _run_ext4magic(image_path: Path, partition_info: dict[str, Any], out: Path) -> tuple[Path | None, str | None]:
    if _which("ext4magic") is None:
        return None, "ext4magic not installed"
    out.mkdir(parents=True, exist_ok=True)
    # -a 1: recover everything changed after epoch; -r: restore deleted; -d: dest.
    # An external journal image may be supplied via partition_info["journal"].
    cmd = ["ext4magic", str(image_path), "-a", "1", "-r", "-d", str(out)]
    journal = partition_info.get("journal")
    if journal:
        cmd += ["-j", str(journal)]
    return _run(cmd, out)


def _run_carving(tool: str, image_path: Path, out: Path) -> tuple[Path | None, str | None]:
    out.mkdir(parents=True, exist_ok=True)
    if tool == "scalpel":
        cmd = ["scalpel", "-o", str(out), str(image_path)]
    else:  # photorec batch mode
        cmd = ["photorec", "/d", str(out), "/cmd", str(image_path), "fileopt,everything,enable,search"]
    return _run(cmd, out)


def _run(cmd: list[str], out: Path) -> tuple[Path | None, str | None]:
    _log.debug("recovery: %s", " ".join(cmd))
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"{cmd[0]} failed to execute: {exc}"
    if res.returncode != 0:
        return None, f"{cmd[0]} exit {res.returncode}: {res.stderr.strip() or '(no output)'}"
    return out, None


# --- result record -------------------------------------------------------------


def _record(
    target: dict[str, Any],
    *,
    level: int,
    tool: str,
    outcome: str,
    recovered_path: str | None = None,
    high_fp_risk: bool = False,
    note: str | None = None,
    tool_version: str | None = None,
) -> dict[str, Any]:
    return {
        "target": target["entity_value"],
        "entity_type": target.get("entity_type", "path"),
        "recovery_level": level,
        "source_tool": tool,
        "recovery_outcome": outcome,
        "recovered_path": recovered_path,
        "high_fp_risk": high_fp_risk,
        "note": note,
        "tool_version": tool_version,
    }


# --- public entry point --------------------------------------------------------


def run(
    image_path: Path,
    partition_info: dict[str, Any],
    targets: list[dict[str, Any]],
    output_dir: Path,
    run_id: str,
) -> dict[str, Any]:
    # Returns {"results": [<per-target per-level record>...], "tool_versions": {...}}.
    # Each tool runs at most once per level (over the whole image); a target found
    # at a level is not attempted at higher levels.
    output_dir = Path(output_dir)
    versions = tool_versions()
    results: list[dict[str, Any]] = []

    missing: list[dict[str, Any]] = []
    for t in targets:
        if _is_tmpfs_target(t["entity_value"], partition_info):
            results.append(
                _record(t, level=1, tool="tsk_recover", outcome="not_applicable",
                        note=TMPFS_NOTE)
            )
        else:
            missing.append(t)

    # Level 1 -- tsk_recover.
    if missing:
        root, err = _run_tsk_recover(image_path, partition_info, output_dir / "tsk_recover")
        still: list[dict[str, Any]] = []
        for t in missing:
            if err is not None:
                results.append(_record(t, level=1, tool="tsk_recover", outcome="tool_error",
                                       note=err, tool_version=versions["tsk_recover"]))
                still.append(t)  # a tool error is not a clean miss: escalate
                continue
            hit = _match_target_in_dir(t["entity_value"], root)
            if hit:
                results.append(_record(t, level=1, tool="tsk_recover", outcome="found",
                                       recovered_path=hit, tool_version=versions["tsk_recover"]))
            else:
                results.append(_record(t, level=1, tool="tsk_recover", outcome="not_found",
                                       tool_version=versions["tsk_recover"]))
                still.append(t)
        missing = still

    # Level 2 -- ext4magic (ext4 only).
    if missing and partition_info.get("fs_type") == "ext4":
        root, err = _run_ext4magic(image_path, partition_info, output_dir / "ext4magic")
        still = []
        for t in missing:
            if err is not None:
                results.append(_record(t, level=2, tool="ext4magic", outcome="tool_error",
                                       note=err, tool_version=versions["ext4magic"]))
                still.append(t)
                continue
            hit = _match_target_in_dir(t["entity_value"], root)
            if hit:
                results.append(_record(t, level=2, tool="ext4magic", outcome="found",
                                       recovered_path=hit, tool_version=versions["ext4magic"]))
            else:
                results.append(_record(t, level=2, tool="ext4magic", outcome="not_found",
                                       tool_version=versions["ext4magic"]))
                still.append(t)
        missing = still

    # Level 3 -- signature carving (photorec preferred, scalpel fallback).
    if missing:
        tool = "photorec" if _which("photorec") else ("scalpel" if _which("scalpel") else None)
        if tool is None:
            for t in missing:
                results.append(_record(t, level=3, tool="photorec", outcome="tool_error",
                                       high_fp_risk=True,
                                       note="no carving tool (photorec/scalpel) available; " + CARVE_NOTE))
        else:
            root, err = _run_carving(tool, image_path, output_dir / tool)
            for t in missing:
                if err is not None:
                    results.append(_record(t, level=3, tool=tool, outcome="tool_error",
                                           high_fp_risk=True, note=f"{err}; {CARVE_NOTE}",
                                           tool_version=versions[tool]))
                    continue
                hit = _match_carved(t["entity_value"], root)
                results.append(_record(
                    t, level=3, tool=tool,
                    outcome="found" if hit else "not_found",
                    recovered_path=hit, high_fp_risk=True, note=CARVE_NOTE,
                    tool_version=versions[tool],
                ))

    return {"results": results, "tool_versions": versions}
