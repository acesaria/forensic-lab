# orchestrator/evaluation/contracts/models.py
#
# In-memory dataclasses for the Phase 2 contracts. These are deliberately thin:
# from_dict/to_dict round-trip the JSON form so the same objects flow from
# detect/ through match/ to metrics/ without each layer re-parsing dicts.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# Controlled vocabulary (Phase 4.2). Shared by GT events and findings so the
# equivalence table in matching.yaml is the only place classes are bridged.
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

# Entity types and ts_quality values are enforced by the JSON Schemas
# (contracts/*.schema.json), which are the on-disk source of truth.

# Forensic operation that produced a finding, so metrics can be sliced per
# operation as well as per source_tool. A finding always carries exactly one.
FORENSIC_OPERATIONS: tuple[str, ...] = (
    "timeline",
    "memory_analysis",
    "string_search",
    "deleted_file",
    "content_scan",
)


@dataclass(frozen=True)
class Entity:
    type: str
    value: Any

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "value": self.value}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Entity":
        return cls(type=d["type"], value=d["value"])


@dataclass
class Observable:
    """One acceptable evidentiary locus for a GT event: where and with which tool
    the same event can legitimately be observed (a filesystem path, a log line, a
    memory mapping...). An event may have several; an empty list means "no locus
    declared yet" and keeps older scenarios working unchanged."""

    operation: str  # one of FORENSIC_OPERATIONS
    source_tool: str  # tsk | plaso | vol3 | plaso_sigma | yara
    entity_type: str  # path | process | socket | mapping | log_line | string
    entity_value: str
    time_hint: dict[str, Any] | None = None  # {kind, ts_utc?, window_s?}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Observable":
        return cls(
            operation=d["operation"],
            source_tool=d["source_tool"],
            entity_type=d["entity_type"],
            entity_value=d["entity_value"],
            time_hint=d.get("time_hint"),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "operation": self.operation,
            "source_tool": self.source_tool,
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
        }
        if self.time_hint is not None:
            out["time_hint"] = self.time_hint
        return out


@dataclass
class GtEvent:
    gt_id: str
    ts_utc: str
    technique: str
    event_class: str
    entity: Entity
    details: dict[str, Any] = field(default_factory=dict)
    expected_sources: list[str] = field(default_factory=list)
    observables: list[Observable] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GtEvent":
        return cls(
            gt_id=d["gt_id"],
            ts_utc=d["ts_utc"],
            technique=d["technique"],
            event_class=d["event_class"],
            entity=Entity.from_dict(d["entity"]),
            details=d.get("details", {}) or {},
            expected_sources=list(d.get("expected_sources", []) or []),
            observables=[Observable.from_dict(o) for o in d.get("observables", []) or []],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "gt_id": self.gt_id,
            "ts_utc": self.ts_utc,
            "technique": self.technique,
            "event_class": self.event_class,
            "entity": self.entity.to_dict(),
            "details": self.details,
            "expected_sources": self.expected_sources,
            "observables": [o.to_dict() for o in self.observables],
        }


@dataclass
class GtManifest:
    scenario_id: str
    run_id: str
    distro: str
    events: list[GtEvent]
    cleanup: bool = False
    random_seed: int | None = None
    timezone: str = "UTC"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GtManifest":
        return cls(
            scenario_id=d["scenario_id"],
            run_id=d["run_id"],
            distro=d["distro"],
            events=[GtEvent.from_dict(e) for e in d.get("events", [])],
            cleanup=bool(d.get("cleanup", False)),
            random_seed=d.get("random_seed"),
            timezone=d.get("timezone", "UTC"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "run_id": self.run_id,
            "distro": self.distro,
            "cleanup": self.cleanup,
            "random_seed": self.random_seed,
            "timezone": self.timezone,
            "events": [e.to_dict() for e in self.events],
        }


@dataclass
class Finding:
    finding_id: str
    source_tool: str  # plaso | vol3 | tsk
    detector: str
    rule_layer: str  # community | custom
    event_class: str
    ts_quality: str  # wallclock | relative | none
    entity: Entity
    technique: str | None = None
    ts_utc: str | None = None
    raw_ref: str | None = None
    confidence: str = "medium"
    # The forensic operation that produced this finding (FORENSIC_OPERATIONS).
    # Defaults to "timeline" so older findings.jsonl deserialize unchanged.
    forensic_operation: str = "timeline"
    # Escalating deleted-file recovery metadata. All default None so non-recovery
    # findings (the common case) serialize exactly as before; they are emitted
    # only by the deleted_file recovery channel.
    recovery_level: int | None = None  # 1 (tsk_recover) | 2 (ext4magic) | 3 (carving)
    recovery_outcome: str | None = None  # found | not_found | not_applicable | tool_error
    high_fp_risk: bool | None = None  # True only for Level 3 signature carving
    note: str | None = None  # free-text caveat / gap explanation

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            finding_id=d["finding_id"],
            source_tool=d["source_tool"],
            detector=d["detector"],
            rule_layer=d["rule_layer"],
            event_class=d["event_class"],
            ts_quality=d["ts_quality"],
            entity=Entity.from_dict(d["entity"]),
            technique=d.get("technique"),
            ts_utc=d.get("ts_utc"),
            raw_ref=d.get("raw_ref"),
            confidence=d.get("confidence", "medium"),
            forensic_operation=d.get("forensic_operation", "timeline"),
            recovery_level=d.get("recovery_level"),
            recovery_outcome=d.get("recovery_outcome"),
            high_fp_risk=d.get("high_fp_risk"),
            note=d.get("note"),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "finding_id": self.finding_id,
            "source_tool": self.source_tool,
            "detector": self.detector,
            "rule_layer": self.rule_layer,
            "technique": self.technique,
            "event_class": self.event_class,
            "ts_utc": self.ts_utc,
            "ts_quality": self.ts_quality,
            "entity": self.entity.to_dict(),
            "raw_ref": self.raw_ref,
            "confidence": self.confidence,
            "forensic_operation": self.forensic_operation,
        }
        # Emit recovery fields only when set, so existing findings.jsonl is byte
        # unchanged and only recovery findings carry the extra keys.
        for key in ("recovery_level", "recovery_outcome", "high_fp_risk", "note"):
            val = getattr(self, key)
            if val is not None:
                out[key] = val
        return out


@dataclass
class Matches:
    matching_config_hash: str
    ruleset_hash: str
    tp: list[dict[str, Any]] = field(default_factory=list)
    fp: list[dict[str, Any]] = field(default_factory=list)
    fn: list[str] = field(default_factory=list)
    background_noise: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Matches":
        return cls(
            matching_config_hash=d["matching_config_hash"],
            ruleset_hash=d["ruleset_hash"],
            tp=list(d.get("tp", [])),
            fp=list(d.get("fp", [])),
            fn=list(d.get("fn", [])),
            background_noise=list(d.get("background_noise", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "matching_config_hash": self.matching_config_hash,
            "ruleset_hash": self.ruleset_hash,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "background_noise": self.background_noise,
        }


def findings_to_jsonl(findings: Iterable[Finding]) -> str:
    import json

    return "".join(
        json.dumps(f.to_dict(), sort_keys=True) + "\n" for f in findings
    )
