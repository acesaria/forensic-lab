"""Small JSON-serializable canonical records for the DFIR lab.

This is deliberately not a full ontology. The records define the stable nouns
that sit between scenario execution, forensic adapters, GT-blind detection, and
GT-aware scoring.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path
from types import UnionType
from typing import Any, ClassVar, get_args, get_origin, get_type_hints


class EvidenceSource(str, Enum):
    DISK = "disk"
    MEMORY = "memory"
    TIMELINE = "timeline"
    LOG = "log"
    UNKNOWN = "unknown"


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


# ponytail: cached per class -- validate()/from_dict() run per record, and
# get_type_hints() reflection per row is measurable on multi-thousand-row runs.
@lru_cache(maxsize=None)
def _type_hints(cls: type) -> dict[str, Any]:
    return get_type_hints(cls)


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
        for name, annotation in _type_hints(self.__class__).items():
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
        kwargs: dict[str, Any] = {}
        for name, annotation in _type_hints(cls).items():
            if name in ("required_fields", "allow_empty_required_fields"):
                continue
            if name in data:
                kwargs[name] = _coerce_value(annotation, data[name])
        return cls(**kwargs)

    @classmethod
    def from_json(cls, text: str):
        return cls.from_dict(json.loads(text))


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
    # Scored vs contextual (METHODOLOGY §3, §10.2): only expectations authored
    # with required_for_scoring: true enter metric denominators. Fail safe:
    # missing/null/non-True never scores.
    required_for_scoring: bool = False
    notes: str = ""

    def validate(self) -> None:
        super().validate()
        self.required_for_scoring = self.required_for_scoring is True


@dataclass
class ToolFinding(CanonicalRecord):
    """One normalized row of raw tool output.

    time_kind convention (METHODOLOGY §6.D, §10.6): when ``time`` is set, the
    adapter records which timestamp it is in ``entity["time_kind"]`` --
    ``crtime`` / ``mtime`` / ``ctime`` / ``atime`` for filesystem sources, the
    plaso ``timestamp_desc`` value for timeline sources. No ``time`` (memory is
    point-in-time) means no ``time_kind``. Adapters never collapse MACB into
    one unlabelled timestamp. (Adapters fill this in the v3 Step 5 pass.)
    """

    required_fields: ClassVar[tuple[str, ...]] = (
        "finding_id",
        "run_id",
        "tool",
        "tool_version",
        "adapter_version",
        "source_type",
        "artifact_class",
        "entity",
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
    raw_ref: str
    provenance: dict[str, Any]
    time: str | None = None


@dataclass
class DetectionClaim(CanonicalRecord):
    """A GT-blind rule shortlisted findings (METHODOLOGY §3). No confidence
    float: the only claim-level grading v3 reads is the baseline downgrade
    flag in ``entity["baseline"]["downgraded"]`` (§6.C)."""

    required_fields: ClassVar[tuple[str, ...]] = (
        "claim_id",
        "run_id",
        "rule_id",
        "artifact_class",
        "entity",
        "source_findings",
        "attck",
    )

    claim_id: str
    run_id: str
    rule_id: str
    artifact_class: str
    entity: dict[str, Any]
    source_findings: list[str]
    attck: list[str]
    notes: str = ""
