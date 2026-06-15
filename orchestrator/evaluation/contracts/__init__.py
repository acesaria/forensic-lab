# orchestrator/evaluation/contracts
#
# Data contracts shared across every pipeline layer (Phase 2). The dataclasses
# are the in-memory form; the JSON Schemas in this package are the on-disk
# contract validated at every stage boundary (orchestrator.evaluation.contracts.validate).

from __future__ import annotations

from orchestrator.evaluation.contracts.models import (
    EVENT_CLASSES,
    Entity,
    Finding,
    GtEvent,
    GtManifest,
    Matches,
)

__all__ = [
    "EVENT_CLASSES",
    "Entity",
    "Finding",
    "GtEvent",
    "GtManifest",
    "Matches",
]
