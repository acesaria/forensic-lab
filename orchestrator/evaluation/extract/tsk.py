# orchestrator/evaluation/extract/tsk.py
#
# Sleuth Kit extraction wrapper (Phase 3.3). Produces an fls -m bodyfile (the
# whole filesystem, including deleted entries) via the in-tree SleuthKitRunner.
# The bodyfile is the GT-blind input for the tsk filesystem heuristics.

from __future__ import annotations

from pathlib import Path
from typing import Any

from orchestrator.forensics.sleuth_runner import SleuthKitRunner


def extract_bodyfile(sleuth: SleuthKitRunner, disk_path: Path) -> dict[str, Any]:
    offset = sleuth.partition_offset(disk_path)
    # fls -m emits bodyfile rows for every name, allocated or not, mounting the
    # listing at "/" so paths read absolute.
    lines = sleuth.fls(disk_path, offset, flags="-r -m /")
    return {"bodyfile": "\n".join(lines)}


def write_bodyfile(raw_tsk: dict[str, Any], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text((raw_tsk.get("bodyfile") or "") + "\n", encoding="utf-8")
    return out_path
