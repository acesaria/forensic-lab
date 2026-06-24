# orchestrator/evaluation/detect/deleted_file_recovery.py
#
# GT-blind adapter that turns the escalating deleted-file recovery RESULTS
# produced by forensics.deleted_file_runner (placed in raw_outputs["deleted_file"])
# into Finding objects, one per target per attempted level. The runner already
# decided each outcome against the (GT-derived, plain-dict) targets handed to it;
# this layer only maps results to Findings. GT-blind: no GT/scenario import, the
# targets are opaque dicts.
#
# These findings self-report recovery_outcome, so the matcher excludes them from
# entity matching and metrics.compute accounts for them in a dedicated recovery
# breakdown (found -> TP, not_found-at-highest-level -> FN, not_applicable ->
# excluded as unsupported_fs).

from __future__ import annotations

from typing import Any, Iterable

from orchestrator.evaluation.contracts.models import Finding
from orchestrator.evaluation.detect.base import make_finding

_OP = "deleted_file"


def detect(raw_outputs: dict[str, Any], rules_config: dict[str, Any]) -> Iterable[Finding]:
    payload = raw_outputs.get("deleted_file")
    results = payload.get("results") if isinstance(payload, dict) else payload
    if not isinstance(results, list):
        return
    for r in results:
        if not isinstance(r, dict):
            continue
        target = r.get("target")
        outcome = r.get("recovery_outcome")
        if not target or not outcome:
            continue
        tool = r.get("source_tool", "tsk_recover")
        level = r.get("recovery_level")
        yield make_finding(
            source_tool=tool,
            detector=f"{tool}:recover",
            event_class="file_deleted",
            entity_type=r.get("entity_type", "path"),
            entity_value=str(target),  # the artifact we tried to recover
            ts_quality="none",
            forensic_operation=_OP,
            recovery_level=int(level) if level is not None else None,
            recovery_outcome=outcome,
            note=r.get("note"),
            raw_ref=(
                f"deleted_file:{tool}:L{level}:{r['recovered_path']}"
                if r.get("recovered_path")
                else f"deleted_file:{tool}:L{level}:{target}"
            ),
            confidence="high" if outcome == "found" else "low",
        )
