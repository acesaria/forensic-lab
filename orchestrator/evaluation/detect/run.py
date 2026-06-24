# orchestrator/evaluation/detect/run.py
#
# Detection driver: runs every GT-blind detector over the extracted raw outputs,
# assigns deterministic finding ids, and writes findings.jsonl. This module (and
# everything it imports) is GT-blind -- it never sees the manifest or scenario.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Iterable

from orchestrator.evaluation.detect import (
    deleted_file_recovery,
    plaso_sigma,
    plaso_tagging,
    tsk_heuristics,
    vol3_heuristics,
    yara_scan,
)
from orchestrator.evaluation.detect.base import assign_ids
from orchestrator.evaluation.contracts.models import Finding

# The registered detector plugins, each a detect(raw_outputs, rules_config)
# callable. Adding a channel is one entry here plus its module. The external-tool
# detectors no-op when their raw_outputs key is absent, so runs without those
# tools are unaffected.
DETECTORS: tuple[Callable[[dict[str, Any], dict[str, Any]], Iterable[Finding]], ...] = (
    plaso_sigma.detect,
    plaso_tagging.detect,
    vol3_heuristics.detect,
    tsk_heuristics.detect,
    yara_scan.detect,
    deleted_file_recovery.detect,
)


def run_detection(
    raw_outputs: dict[str, Any], rules_config: dict[str, Any] | None = None
) -> list[Finding]:
    cfg = rules_config or {}
    collected: list[Finding] = []
    for detector in DETECTORS:
        collected.extend(detector(raw_outputs, cfg))
    return assign_ids(collected)


def write_findings(findings: list[Finding], out_path: str | Path) -> Path:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f.to_dict(), sort_keys=True) + "\n")
    return p
