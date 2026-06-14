# orchestrator/evaluation/detect/base.py
#
# GT-blind detection layer foundation. A detector is a callable
#   detect(raw_outputs, rules_config) -> Iterable[Finding]
# that decides "this looks suspicious" WITHOUT any knowledge of ground truth.
# This module owns the shared Finding constructor and the deterministic
# finding-id assignment; nothing here imports the matcher, the manifest, or a
# scenario module (enforced by tests/test_detect_blindness.py).

from __future__ import annotations

from typing import Any, Iterable, Protocol

from orchestrator.evaluation.contracts.models import Entity, Finding

# Controlled event-class vocabulary mirrored from the contract. Duplicated as a
# plain tuple so this layer needs no import that could smuggle in GT awareness.
EVENT_CLASSES: tuple[str, ...] = (
    "file_created",
    "file_deleted",
    "file_modified",
    "process_exec",
    "persistence_installed",
    "network_connection",
    "auth_login",
    "log_tampering",
    "history_cleared",
)

# Forensic operation that produced a finding (mirrored as a plain tuple, like
# EVENT_CLASSES, so the detect layer pulls in nothing GT-aware). Every detector
# tags its findings with one of these so metrics can be sliced per operation.
FORENSIC_OPERATIONS: tuple[str, ...] = (
    "timeline",
    "memory_analysis",
    "string_search",
    "deleted_file",
    "content_scan",
)

# Outcome of a single deleted-file recovery attempt (one level, one target).
RECOVERY_OUTCOMES: tuple[str, ...] = (
    "found",
    "not_found",
    "not_applicable",
    "tool_error",
)


class Detector(Protocol):
    name: str

    def detect(
        self, raw_outputs: dict[str, Any], rules_config: dict[str, Any]
    ) -> Iterable[Finding]:
        ...


def make_finding(
    *,
    source_tool: str,
    detector: str,
    event_class: str,
    entity_type: str,
    entity_value: Any,
    ts_quality: str,
    forensic_operation: str,
    rule_layer: str = "community",
    technique: str | None = None,
    ts_utc: str | None = None,
    raw_ref: str | None = None,
    confidence: str = "medium",
    recovery_level: int | None = None,
    recovery_outcome: str | None = None,
    high_fp_risk: bool | None = None,
    note: str | None = None,
) -> Finding:
    if event_class not in EVENT_CLASSES:
        raise ValueError(f"unknown event_class: {event_class}")
    if forensic_operation not in FORENSIC_OPERATIONS:
        raise ValueError(f"unknown forensic_operation: {forensic_operation}")
    if recovery_outcome is not None and recovery_outcome not in RECOVERY_OUTCOMES:
        raise ValueError(f"unknown recovery_outcome: {recovery_outcome}")
    return Finding(
        finding_id="",  # assigned by assign_ids after collection
        source_tool=source_tool,
        detector=detector,
        rule_layer=rule_layer,
        event_class=event_class,
        ts_quality=ts_quality,
        entity=Entity(type=entity_type, value=entity_value),
        technique=technique,
        ts_utc=ts_utc,
        raw_ref=raw_ref,
        confidence=confidence,
        forensic_operation=forensic_operation,
        recovery_level=recovery_level,
        recovery_outcome=recovery_outcome,
        high_fp_risk=high_fp_risk,
        note=note,
    )


def assign_ids(findings: Iterable[Finding]) -> list[Finding]:
    # Deterministic ids independent of detector execution order: sort by a stable
    # natural key, then number f-000000.. so the same inputs always yield the same
    # findings.jsonl regardless of which detector ran first.
    items = list(findings)
    items.sort(key=_sort_key)
    for i, f in enumerate(items):
        f.finding_id = f"f-{i:06d}"
    return items


def _sort_key(f: Finding) -> tuple:
    return (
        f.ts_utc or "~",  # "~" sorts after digits, pushing timeless to the end
        f.source_tool,
        f.detector,
        f.event_class,
        str(f.entity.type),
        str(f.entity.value),
        str(f.raw_ref or ""),
    )
