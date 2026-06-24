# orchestrator/forensics/deleted_file_runner.py
#
# Escalating deleted-file recovery for the "deleted_file" forensic operation.
# Two successive levels, stopping per target as soon as it is recovered:
#
#   Level 1  tsk_recover  metadata-based, safe, any supported FS
#   Level 2  ext4magic    journal-based, ext4 only (supersedes extundelete)
#
# Signature carving (photorec/scalpel) was deliberately dropped: it cannot name
# what it recovers and its precision is too unreliable to justify here.
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

_VERSION_PROBES: dict[str, list[str]] = {
    "tsk_recover": ["tsk_recover", "-V"],
    "ext4magic": ["ext4magic", "-V"],  # -V prints "ext4magic  version : 0.3.2"
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


# --- level executors (best-effort; return (recovered_root, error)) -------------


def _run_tsk_recover(image_path: Path, partition_info: dict[str, Any], out: Path) -> tuple[Path | None, str | None]:
    if _which("tsk_recover") is None:
        return None, "tsk_recover not installed"
    out.mkdir(parents=True, exist_ok=True)
    cmd = ["tsk_recover", "-e"]  # -e: every file, allocated + unallocated
    # partition_info carries a BYTE offset; tsk_recover -o is in sectors.
    offset_sectors = int(partition_info.get("offset_bytes") or 0) // 512
    if offset_sectors:
        cmd += ["-o", str(offset_sectors)]
    cmd += [str(image_path), str(out)]
    return _run(cmd, out)


def _prepare_partition_raw(
    image_path: Path, partition_info: dict[str, Any], work_dir: Path
) -> tuple[Path | None, str | None]:
    # ext4magic reads neither EWF/E01 nor a whole-disk image and has no
    # partition-offset option, so it needs a RAW image of the ext4 partition
    # ALONE. We keep the full E01 as the canonical artifact (TSK/plaso/etc) and
    # derive a partition raw just for ext4magic:
    #   ewfexport full E01 -> disk.raw  (-t - => single deterministic file,
    #                                     sidestepping the 1.4 GiB segment split)
    #   dd bs=512 skip=<start> count=<count> disk.raw -> disk_part.raw
    # The journal travels inside the partition, so no external -j is needed.
    # TODO(live-acq): when acquiring from inside the running VM over SSH
    # (dcfldd | nc, see core/ssh_client.run), the receiver can write this
    # partition raw directly and the ewfexport step becomes a no-op.
    start = partition_info.get("part_start_sector")
    if start is None:
        start = int(partition_info.get("offset_bytes") or 0) // 512
    count = partition_info.get("part_count_sectors")
    if not count:
        return None, "partition sector count unavailable; cannot carve ext4 partition for ext4magic"

    work_dir.mkdir(parents=True, exist_ok=True)
    part_raw = work_dir / "disk_part.raw"

    if image_path.suffix.lower() in (".raw", ".dd", ".img"):
        disk_raw = image_path  # already raw (e.g. a future live-acquired image)
    else:
        if _which("ewfexport") is None:
            return None, "ewfexport not installed"
        disk_raw = work_dir / "disk.raw"
        _log.info("ext4magic prep: ewfexport %s -> %s (raw)", image_path.name, disk_raw.name)
        try:
            with disk_raw.open("wb") as fh:
                res = subprocess.run(
                    ["ewfexport", "-u", "-q", "-f", "raw", "-t", "-", str(image_path)],
                    stdout=fh, stderr=subprocess.PIPE,
                )
        except (OSError, subprocess.SubprocessError) as exc:
            return None, f"ewfexport failed to execute: {exc}"
        if res.returncode != 0:
            return None, f"ewfexport exit {res.returncode}: {res.stderr.decode(errors='replace').strip() or '(no output)'}"

    dd_cmd = [
        "dd", f"if={disk_raw}", f"of={part_raw}",
        "bs=512", f"skip={start}", f"count={count}", "conv=sparse",
    ]
    _log.info("ext4magic prep: %s", " ".join(dd_cmd))
    try:
        dd = subprocess.run(dd_cmd, capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"dd failed to execute: {exc}"
    if dd.returncode != 0:
        return None, f"dd partition extract exit {dd.returncode}: {dd.stderr.strip() or '(no output)'}"
    _log.info("ext4magic prep: ext4 partition raw ready (%s, %s sectors @ %s)", part_raw.name, count, start)
    return part_raw, None


def _ext4magic_window(partition_info: dict[str, Any]) -> list[str]:
    # -a/-b bound the journal scan to the case window (unix epoch seconds).
    # Default -a 1 (everything after epoch) when no window is supplied; -b omitted.
    start = partition_info.get("window_start_epoch")
    end = partition_info.get("window_end_epoch")
    flags = ["-a", str(int(start)) if start else "1"]
    if end:
        flags += ["-b", str(int(end))]
    return flags


def _run_ext4magic(
    part_raw: Path, partition_info: dict[str, Any], relpath: str, out: Path
) -> tuple[str | None, str | None]:
    # Two stages on the ext4 partition raw: list (diagnostic, non-fatal) then
    # recover. -f takes a filesystem-relative path (tmp/T1082.txt, no leading
    # slash). Returns (recovered_path | None, error).
    if _which("ext4magic") is None:
        return None, "ext4magic not installed"
    out.mkdir(parents=True, exist_ok=True)
    window = _ext4magic_window(partition_info)
    base = ["ext4magic", str(part_raw), "-f", relpath, *window]

    list_cmd = base + ["-l"]
    _log.info("ext4magic list: %s", " ".join(list_cmd))
    try:
        lres = subprocess.run(list_cmd, capture_output=True, text=True)
        _log.debug("ext4magic list rc=%s\n%s", lres.returncode, (lres.stdout or lres.stderr).strip())
    except (OSError, subprocess.SubprocessError) as exc:
        _log.debug("ext4magic list skipped: %s", exc)

    rec_cmd = base + ["-r", "-d", str(out)]
    _log.info("ext4magic recover: %s", " ".join(rec_cmd))
    _, err = _run(rec_cmd, out)
    if err is not None:
        return None, err
    return _match_target_in_dir(relpath, out), None


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

    # Level 2 -- ext4magic (ext4 only, journal-based). Terminal: no carving level
    # beyond this. Runs on a raw image of the ext4 partition (carved once from the
    # full E01), not on the whole-disk E01 itself.
    if missing and partition_info.get("fs_type") == "ext4":
        ext4_base = output_dir / "ext4magic"
        part_raw, prep_err = _prepare_partition_raw(image_path, partition_info, ext4_base)
        for t in missing:
            if prep_err is not None:
                results.append(_record(t, level=2, tool="ext4magic", outcome="tool_error",
                                       note=prep_err, tool_version=versions["ext4magic"]))
                continue
            # ext4magic -f wants a filesystem-relative path (tmp/T1082.txt), not
            # an absolute one. Recover each target into its own subdir so matches
            # stay unambiguous.
            relpath = t["entity_value"].lstrip("/")
            out = ext4_base / "recovered" / relpath.replace("/", "_")
            hit, err = _run_ext4magic(part_raw, partition_info, relpath, out)
            if err is not None:
                results.append(_record(t, level=2, tool="ext4magic", outcome="tool_error",
                                       note=err, tool_version=versions["ext4magic"]))
            elif hit:
                results.append(_record(t, level=2, tool="ext4magic", outcome="found",
                                       recovered_path=hit, tool_version=versions["ext4magic"]))
            else:
                results.append(_record(t, level=2, tool="ext4magic", outcome="not_found",
                                       tool_version=versions["ext4magic"]))

    return {"results": results, "tool_versions": versions}
