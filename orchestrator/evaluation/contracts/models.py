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

ENTITY_TYPES: tuple[str, ...] = ("path", "process", "user", "socket")

TS_QUALITIES: tuple[str, ...] = ("wallclock", "relative", "none")


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
class GtEvent:
    gt_id: str
    ts_utc: str
    technique: str
    event_class: str
    entity: Entity
    details: dict[str, Any] = field(default_factory=dict)
    expected_sources: list[str] = field(default_factory=list)

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
        )

    def to_dict(self) -> dict[str, Any]:
        return {
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
        }


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
