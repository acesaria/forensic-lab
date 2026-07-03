"""Small JSON-serializable canonical records for the DFIR lab.

This is deliberately not a full ontology. The records define the stable nouns
that sit between scenario execution, forensic adapters, GT-blind detection, and
GT-aware scoring.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from types import UnionType
from typing import Any, ClassVar, get_args, get_origin, get_type_hints


class EvidenceSource(str, Enum):
    DISK = "disk"
    MEMORY = "memory"
    TIMELINE = "timeline"
    LOG = "log"
    UNKNOWN = "unknown"


class TemporalQuality(str, Enum):
    EXACT = "exact"
    BOUNDED = "bounded"
    RELATIVE_ORDER = "relative_order"
    NONE = "none"


class MatchLevel(str, Enum):
    INSTANCE = "instance"
    CLASS = "class"
    NONE = "none"


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def _is_optional(annotation: Any) -> bool:
    origin = get_origin(annotation)
    return origin in (UnionType, getattr(__import__("typing"), "Union")) and type(None) in get_args(annotation)


def _coerce_value(annotation: Any, value: Any) -> Any:
    if value is None:
        return None
    origin = get_origin(annotation)
    args = get_args(annotation)
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return value if isinstance(value, annotation) else annotation(value)
    if origin in (list, tuple) and args:
        return [_coerce_value(args[0], item) for item in value]
    if origin in (UnionType, getattr(__import__("typing"), "Union")):
        non_none = [arg for arg in args if arg is not type(None)]
        if len(non_none) == 1:
            return _coerce_value(non_none[0], value)
    return value


@dataclass
class CanonicalRecord:
    """Base mixin for required-field validation and JSON conversion."""

    required_fields: ClassVar[tuple[str, ...]] = ()
    allow_empty_required_fields: ClassVar[tuple[str, ...]] = ()

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for name in self.required_fields:
            value = getattr(self, name)
            if value is None:
                raise ValueError(f"{self.__class__.__name__}.{name} is required")
            if (
                isinstance(value, str)
                and not value.strip()
                and name not in self.allow_empty_required_fields
            ):
                raise ValueError(f"{self.__class__.__name__}.{name} is required")
        hints = get_type_hints(self.__class__)
        for name, annotation in hints.items():
            if name in ("required_fields", "allow_empty_required_fields"):
                continue
            value = getattr(self, name, None)
            if value is None and not _is_optional(annotation):
                continue
            coerced = _coerce_value(annotation, value)
            if coerced is not value:
                setattr(self, name, coerced)

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]):
        hints = get_type_hints(cls)
        kwargs: dict[str, Any] = {}
        for name, annotation in hints.items():
            if name in ("required_fields", "allow_empty_required_fields"):
                continue
            if name in data:
                kwargs[name] = _coerce_value(annotation, data[name])
        return cls(**kwargs)

    @classmethod
    def from_json(cls, text: str):
        return cls.from_dict(json.loads(text))


@dataclass
class ScenarioStep(CanonicalRecord):
    required_fields: ClassVar[tuple[str, ...]] = (
        "scenario_id",
        "step_id",
        "action",
    )

    scenario_id: str
    step_id: str
    action: str
    executor: str = "shell"
    command: str | None = None
    actor: str = "attacker"
    parameters: dict[str, Any] = field(default_factory=dict)
    attck: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class GroundTruthEvent(CanonicalRecord):
    required_fields: ClassVar[tuple[str, ...]] = (
        "run_id",
        "scenario_id",
        "step_id",
        "event_type",
        "object_type",
        "object_identity",
        "action",
        "actor",
        "time",
        "evidence_basis",
        "attck",
    )

    run_id: str
    scenario_id: str
    step_id: str
    event_type: str
    object_type: str
    object_identity: str
    action: str
    actor: str
    time: str
    evidence_basis: list[EvidenceSource]
    attck: list[str]
    temporal_quality: TemporalQuality = TemporalQuality.EXACT
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ArtifactExpectation(CanonicalRecord):
    required_fields: ClassVar[tuple[str, ...]] = (
        "ae_id",
        "scenario_id",
        "step_id",
        "artifact_class",
        "observable_kind",
        "source_eligibility",
        "persistence",
        "observability",
        "instance_constraints",
        "critical",
        "attck",
    )

    ae_id: str
    scenario_id: str
    step_id: str
    artifact_class: str
    observable_kind: str
    source_eligibility: list[EvidenceSource]
    persistence: str
    observability: str
    instance_constraints: dict[str, Any]
    critical: bool
    attck: list[str]
    temporal_quality: TemporalQuality = TemporalQuality.NONE
    notes: str = ""


@dataclass
class ReferenceContext(CanonicalRecord):
    required_fields: ClassVar[tuple[str, ...]] = (
        "ref_id",
        "run_id",
        "scenario_id",
        "source",
        "locator",
    )

    ref_id: str
    run_id: str
    scenario_id: str
    source: EvidenceSource
    locator: str
    description: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolFinding(CanonicalRecord):
    required_fields: ClassVar[tuple[str, ...]] = (
        "finding_id",
        "run_id",
        "tool",
        "tool_version",
        "adapter_version",
        "source_type",
        "artifact_class",
        "entity",
        "time",
        "raw_ref",
        "provenance",
    )

    finding_id: str
    run_id: str
    tool: str
    tool_version: str
    adapter_version: str
    source_type: EvidenceSource
    artifact_class: str
    entity: dict[str, Any]
    time: str | None
    raw_ref: str
    provenance: dict[str, Any]
    temporal_quality: TemporalQuality = TemporalQuality.NONE


@dataclass
class DetectionClaim(CanonicalRecord):
    required_fields: ClassVar[tuple[str, ...]] = (
        "claim_id",
        "run_id",
        "rule_id",
        "artifact_class",
        "entity",
        "confidence",
        "source_findings",
        "attck",
    )

    claim_id: str
    run_id: str
    rule_id: str
    artifact_class: str
    entity: dict[str, Any]
    confidence: float
    source_findings: list[str]
    attck: list[str]
    notes: str = ""

    def validate(self) -> None:
        super().validate()
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("DetectionClaim.confidence must be between 0 and 1")


@dataclass
class MatchResult(CanonicalRecord):
    required_fields: ClassVar[tuple[str, ...]] = (
        "match_id",
        "run_id",
        "target_id",
        "finding_or_claim_id",
        "match_level",
        "relation",
        "score",
        "fields_matched",
        "notes",
    )
    allow_empty_required_fields: ClassVar[tuple[str, ...]] = ("notes",)

    match_id: str
    run_id: str
    target_id: str
    finding_or_claim_id: str
    match_level: MatchLevel
    relation: str
    score: float
    fields_matched: list[str]
    notes: str

    def validate(self) -> None:
        super().validate()
        if not 0.0 <= float(self.score) <= 1.0:
            raise ValueError("MatchResult.score must be between 0 and 1")
