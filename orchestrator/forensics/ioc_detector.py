"""
IOC detection against Volatility3 and Sleuth Kit outputs.

Phase 1:
- only handles 'process' IOCs via Volatility;
- only handles 'file' IOCs via Sleuth Kit;
- no metrics, just a match/miss flag in a per-scenario JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from orchestrator.forensics.vol_runner import VolatilityRunner
from orchestrator.forensics.sleuth_runner import SleuthKitRunner

def _match_process_ioc(vol, memory_image, distro_id, ioc):
    raise NotImplementedError

def _match_file_ioc(sleuth, disk_image, ioc):
    raise NotImplementedError


def detect_iocs_for_scenario(
    vol: VolatilityRunner,
    sleuth: SleuthKitRunner,
    memory_image: Path,
    disk_image: Path,
    distro_id: str,
    ground_truth_path: Path,
    output_path: Path,
) -> None:
    gt = json.loads(ground_truth_path.read_text())
    iocs = gt.get("iocs", [])

    # Phase 1: keep this dumb and explicit.
    findings: list[dict[str, Any]] = []
    for ioc in iocs:
        if ioc["type"] == "process":
            matched = _match_process_ioc(vol, memory_image, distro_id, ioc)
        elif ioc["type"] == "file":
            matched = _match_file_ioc(sleuth, disk_image, ioc)
        else:
            matched = False

        findings.append(
            {
                "ioc_id": ioc["id"],
                "type": ioc["type"],
                "matched": matched,
            }
        )

    output = {
        "scenario_id": gt.get("scenario_id"),
        "findings": findings,
    }
    output_path.write_text(json.dumps(output, indent=2))
