"""Small, reusable helpers for the Father disk investigation notebook.

This module is orchestration glue, not a forensic-tool reimplementation.
Every actual forensic operation (mmls, fsstat, ifind, icat, istat, fls, jls,
jcat, ...) is invoked as `subprocess.run()` directly in the notebook cell
that needs it -- the command stays visible there, not hidden behind a
wrapper. The functions here only save that output to disk, log the
invocation, and parse small known-format text into structured values.
Nothing here re-implements what The Sleuth Kit or ext4/jbd2 already do.

Import from the notebook with:

    import sys; sys.path.insert(0, ".")
    from investigation_utils import *
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# RUN_ID -> paths
# --------------------------------------------------------------------------


@dataclasses.dataclass
class RunPaths:
    run_id: str
    repo_root: Path  # repository root -- used to render repo-relative paths
    rundir: Path  # shared/experiments/<RUN_ID>            (read-only input)
    manifest: Path  # <rundir>/manifest.json
    acquisition: Path  # <rundir>/dumps/acquisition.json
    disk_e01: Path  # <rundir>/dumps/disk/evidence_disk.E01
    command_log: Path  # <rundir>/command_log.jsonl
    inv_dir: Path  # shared/investigations/<RUN_ID>
    derived_disk: Path  # <inv_dir>/derived/disk
    raw_dir: Path  # <inv_dir>/derived/disk/raw
    findings_json: Path  # <inv_dir>/derived/disk/findings.json
    metrics_json: Path  # <inv_dir>/derived/disk/metrics.json
    report_md: Path  # <inv_dir>/report/disk.md
    disk_commands_log: Path  # <inv_dir>/logs/disk-commands.log


def resolve_run_paths(run_id: str, repo_root: Optional[Path] = None) -> RunPaths:
    """Derive every path used by the disk investigation from RUN_ID alone.

    Raises FileNotFoundError if a required *input* file is missing. Does not
    create or touch any output directory (call ensure_output_dirs for that).
    """
    root = Path(repo_root) if repo_root is not None else Path.cwd()

    rundir = root / "shared" / "experiments" / run_id
    manifest = rundir / "manifest.json"
    acquisition = rundir / "dumps" / "acquisition.json"
    disk_e01 = rundir / "dumps" / "disk" / "evidence_disk.E01"
    command_log = rundir / "command_log.jsonl"

    required = {
        "manifest": manifest,
        "acquisition": acquisition,
        "disk_e01": disk_e01,
    }
    missing = [str(p) for p in required.values() if not p.is_file()]
    if missing:
        raise FileNotFoundError(
            f"RUN_ID '{run_id}': missing required input file(s): {missing}"
        )

    inv_dir = root / "shared" / "investigations" / run_id
    derived_disk = inv_dir / "derived" / "disk"

    return RunPaths(
        run_id=run_id,
        repo_root=root,
        rundir=rundir,
        manifest=manifest,
        acquisition=acquisition,
        disk_e01=disk_e01,
        command_log=command_log,
        inv_dir=inv_dir,
        derived_disk=derived_disk,
        raw_dir=derived_disk / "raw",
        findings_json=derived_disk / "findings.json",
        metrics_json=derived_disk / "metrics.json",
        report_md=inv_dir / "report" / "disk.md",
        disk_commands_log=inv_dir / "logs" / "disk-commands.log",
    )


def ensure_output_dirs(paths: RunPaths) -> None:
    """Create every output directory this notebook writes to. Never touches
    shared/experiments/<RUN_ID> (the read-only input tree)."""
    paths.raw_dir.mkdir(parents=True, exist_ok=True)
    paths.metrics_json.parent.mkdir(parents=True, exist_ok=True)
    paths.report_md.parent.mkdir(parents=True, exist_ok=True)
    paths.disk_commands_log.parent.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------
# Command output: save + log (the two forensic side effects every tool
# invocation needs; the invocation itself is a plain subprocess.run() call
# written directly in the notebook cell).
# --------------------------------------------------------------------------


def save_raw(paths: RunPaths, label: str, content, binary: bool = False) -> Path:
    """Save content under derived/disk/raw/<label> -- a subprocess's stdout,
    or Python-derived content (e.g. a filtered excerpt)."""
    raw_path = paths.raw_dir / label
    if binary:
        raw_path.write_bytes(content)
    else:
        raw_path.write_text(content)
    return raw_path


def log_command(paths: RunPaths, proc: subprocess.CompletedProcess) -> None:
    """Append one subprocess invocation and its return code to this run's
    disk-commands.log -- the audit trail of every tool call."""
    with paths.disk_commands_log.open("a") as fh:
        fh.write(f"+ {' '.join(proc.args)}  (rc={proc.returncode})\n")


def run_command(
    args: list[str],
    label: Optional[str],
    paths: RunPaths,
    save: bool = True,
    binary: bool = False,
) -> subprocess.CompletedProcess:
    """Invoke a command, log it, and optionally save its stdout to raw/."""
    proc = subprocess.run(args, capture_output=True, text=not binary)
    log_command(paths, proc)
    if save and label:
        save_raw(paths, label, proc.stdout, binary=binary)
    proc.check_returncode()
    return proc


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + "\n")


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------


def safe_sha256(data_or_path) -> Optional[str]:
    """SHA-256 of bytes, or of a file's content if given a Path/str path.
    Returns None (never raises) if the path does not exist or is empty."""
    try:
        if isinstance(data_or_path, (str, Path)) and Path(data_or_path).is_file():
            data = Path(data_or_path).read_bytes()
        elif isinstance(data_or_path, (bytes, bytearray)):
            data = bytes(data_or_path)
        else:
            return None
    except OSError:
        return None
    if not data:
        return None
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Small parsers for known command output (TSK text formats only)
# --------------------------------------------------------------------------


def parse_label_lines(text: str) -> dict:
    """Split each 'Label: value' line in TSK text output on its first ':'.
    Reused by istat/fsstat parsing -- both are the same plain-text shape,
    and a colon inside a value (e.g. a timestamp's HH:MM:SS) is preserved
    since only the first ':' on the line is used as the split point."""
    fields = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        fields[label.strip()] = value.strip()
    return fields


def parse_mmls_root_offset(mmls_text: str) -> Optional[str]:
    """Pick the root-filesystem candidate from `mmls` output: the largest
    real (numbered, non-Meta/Unallocated) partition slot. Column 3 is the
    start sector, column 5 is the length in sectors."""
    candidates = []
    for line in mmls_text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        slot = parts[0]
        if not (slot.endswith(":") and slot[:-1].isdigit()):
            continue  # not a numbered slot row (e.g. "Meta", "-------")
        if not parts[1].isdigit():
            continue
        start_sector, length_sectors = parts[2], parts[4]
        candidates.append((int(length_sectors), start_sector))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return str(int(candidates[0][1]))


def parse_ewfverify(output: str) -> dict:
    """Parse `ewfverify -d <digest>` output for the computed hash and the
    overall SUCCESS/FAILURE verdict."""
    computed_hash = None
    for line in output.splitlines():
        if "calculated over data:" in line:
            _, _, value = line.partition("calculated over data:")
            computed_hash = value.strip()
            break
    return {
        "computed_hash": computed_hash,
        "success": "ewfverify: SUCCESS" in output,
    }


def parse_fsstat(fsstat_text: str) -> dict:
    fields = parse_label_lines(fsstat_text)
    return {
        "fs_type": fields.get("File System Type"),
        "volume_name": fields.get("Volume Name"),
        "unmounted_properly": "Unmounted properly" in fsstat_text,
        "journal_inode": fields.get("Journal Inode"),
        "block_size": int(fields["Block Size"]) if "Block Size" in fields else None,
    }


def parse_istat(istat_text: str) -> dict:
    """`istat` output is plain 'Label: value' lines -- split each line on
    its first ':' rather than using regex."""
    lines = istat_text.splitlines()
    fields = parse_label_lines(istat_text)
    return {
        "inode": fields.get("inode"),
        "allocated": "Allocated" in lines[1] if len(lines) > 1 else None,
        "size_bytes": int(fields["size"]) if "size" in fields else None,
        "symlink_target": fields.get("symbolic link to"),
        "file_modified": fields.get("File Modified"),
        "inode_modified": fields.get("Inode Modified"),
        "file_created": fields.get("File Created"),
        "accessed": fields.get("Accessed"),
    }


def parse_istat_timestamp(ts_str: Optional[str]) -> Optional[str]:
    """Normalize TSK timestamp for comparison. Returns None if invalid or '0000-00-00'."""
    if not ts_str or "0000-00-00" in ts_str:
        return None
    # Strip timezone suffix to ensure sortable YYYY-MM-DD HH:MM:SS.NNNNNNNNN
    return ts_str.partition(" (")[0].strip()


def detect_timestomp(istat_info: dict) -> bool:
    """
    Return True if simple heuristics detect likely timestamp backdating.

    Heuristics:
    1. mtime < crtime (logical impossibility: modification predates birth).
    2. mtime < ctime (supporting signal: mtime pushed back while ctime records metadata change).
    """
    m = parse_istat_timestamp(istat_info.get("file_modified"))
    c = parse_istat_timestamp(istat_info.get("inode_modified"))
    cr = parse_istat_timestamp(istat_info.get("file_created"))

    if not m:
        return False

    # Heuristic 1: Backdating relative to creation (Birth)
    if cr and m < cr:
        return True

    # Heuristic 2: Backdating relative to metadata change (Status Change)
    if c and m < c:
        return True

    return False


def parse_fls_regular_files(fls_text: str) -> list:
    """Parse `fls -p` output lines of the form `r/r 12345:  name` into
    [(inode, name), ...] for live regular files. Deleted entries (marked
    with a leading `*`) are excluded -- use a separate parser/grep for those
    since their inode is frequently reused/unreliable."""
    out = []
    for line in fls_text.splitlines():
        if not line.startswith("r/r"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        inode = parts[1].rstrip(":").split("-")[0]
        name = parts[2].strip()
        out.append((inode, name))
    return out
# --------------------------------------------------------------------------
# Report rendering
# --------------------------------------------------------------------------


def _render_kv_section(lines: list, section: dict) -> None:
    """Render a flat-ish dict as bullet points; a nested dict/list value is
    rendered as an indented fenced JSON block instead of a raw Python repr,
    so the report stays readable rather than dumping str(dict)."""
    for k, v in section.items():
        if isinstance(v, (dict, list)):
            lines.append(f"- **{k}**:")
            lines.append("  ```json")
            for json_line in json.dumps(v, indent=2, default=str).splitlines():
                lines.append(f"  {json_line}")
            lines.append("  ```")
        else:
            lines.append(f"- **{k}**: {v}")


def write_report(findings: dict, paths: RunPaths, metrics: dict) -> Path:
    """Render the canonical Markdown disk report directly from the findings
    dict and the separately-computed metrics dict (passed in, not embedded
    in findings.json -- findings.json and metrics.json each stay the single
    place their own content lives). This is not a generic templating/
    report-generator framework -- it is one function tied to this
    investigation's own findings schema."""
    f = findings
    raw_rel = paths.raw_dir.relative_to(paths.repo_root)
    metrics_rel = paths.metrics_json.relative_to(paths.repo_root)

    lines = []
    lines.append(f"# Disk examination — {f['case']['run_id']}")
    lines.append("")
    lines.append(
        "Generated by `investigations/father/disk_investigation.ipynb`. "
        f"Raw command output is under `{raw_rel}/`."
    )
    lines.append("")

    lines.append("## 1. Case / run identification")
    lines.append("")
    _render_kv_section(lines, f["case"])
    lines.append("")

    lines.append("## 2. Evidence inputs and integrity")
    lines.append("")
    _render_kv_section(lines, f["evidence"])
    lines.append("")

    lines.append("## 3. Filesystem discovery")
    lines.append("")
    _render_kv_section(lines, f["filesystem"])
    lines.append("")

    lines.append("## 4. Preload persistence chain")
    lines.append("")
    _render_kv_section(lines, f["preload"])
    lines.append("")

    lines.append("## 5. Installed library identity")
    lines.append("")
    _render_kv_section(lines, f["library"])
    lines.append("")

    lines.append("## 6. Visible /tmp artifacts")
    lines.append("")
    _render_kv_section(lines, f["tmp_artifacts"])
    lines.append("")

    lines.append("## 7. Deleted-file recovery and journal evidence")
    lines.append("")
    _render_kv_section(lines, f["deleted_rk_so"])
    lines.append("")
    lines.append("### Journal")
    lines.append("")
    _render_kv_section(lines, f["journal"])
    lines.append("")
    lines.append("### Recovery tooling (extundelete / ext4magic)")
    lines.append("")
    _render_kv_section(lines, f["recovery_tooling"])
    lines.append("")

    lines.append("## 8. Findings table")
    lines.append("")
    lines.append("| Area | Status | Evidence path |")
    lines.append("|---|---|---|")
    for row in f["findings_table"]:
        lines.append(f"| {row['area']} | {row['status']} | `{row['evidence_path']}` |")
    lines.append("")

    lines.append("## 9. Metrics")
    lines.append("")
    lines.append(f"See `{metrics_rel}` (machine-readable; summarized here).")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    for k, v in metrics.items():
        v_str = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        lines.append(f"| {k} | {v_str} |")
    lines.append("")

    lines.append("## 10. Limitations")
    lines.append("")
    for item in f["limitations"]:
        lines.append(f"- {item}")
    lines.append("")

    lines.append("## 11. Reproducibility")
    lines.append("")
    lines.append("```bash")
    lines.append(
        f"RUN_ID={f['case']['run_id']} jupyter nbconvert --to notebook --execute \\"
    )
    lines.append("    investigations/father/disk_investigation.ipynb")
    lines.append("```")
    lines.append("")
    lines.append(
        "Every offset, inode, and precondition value above was rediscovered from "
        "this run's own evidence when the notebook last ran; none are literal "
        "constants carried over from another run."
    )
    lines.append("")

    paths.report_md.parent.mkdir(parents=True, exist_ok=True)
    paths.report_md.write_text("\n".join(lines))
    return paths.report_md
