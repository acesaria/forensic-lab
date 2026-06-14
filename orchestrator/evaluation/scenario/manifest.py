# orchestrator/evaluation/scenario/manifest.py
#
# Ground-truth manifest emission AT EXECUTION TIME (Phase 2.1). The scenario logs
# each seeded action as it performs it, so timestamps are exact and the manifest
# is never hand-written. Parameter randomization draws instance values from a
# seeded RNG: the seed is recorded for reproducibility, but constants differ
# across seeds, so any detection rule that hardcodes an instance value breaks on
# the next seed (the anti-circularity guarantee).

from __future__ import annotations

import json
import random
import string
from pathlib import Path
from typing import Any

from orchestrator.evaluation.contracts.models import (
    Entity,
    GtEvent,
    GtManifest,
    Observable,
)
from orchestrator.evaluation.contracts.validate import validate_gt_manifest
from orchestrator.forensics.timeutil import now_utc_ms


class ScenarioParams:
    """Seeded source of randomized instance parameters. Same seed -> same draws,
    so a run is reproducible; different seeds -> different filenames/dirs/ports,
    so rules cannot memorise a value."""

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self._rng = random.Random(seed)

    def token(self, length: int = 6) -> str:
        alphabet = string.ascii_lowercase + string.digits
        return "".join(self._rng.choice(alphabet) for _ in range(length))

    def basename(self, prefix: str = ".", ext: str = "") -> str:
        return f"{prefix}{self.token()}{ext}"

    def choice(self, options: list[str]) -> str:
        return self._rng.choice(list(options))

    def port(self, low: int = 20000, high: int = 60000) -> int:
        return self._rng.randint(low, high)

    def delay_s(self, low: float = 0.5, high: float = 3.0) -> float:
        return round(self._rng.uniform(low, high), 3)


class GtManifestBuilder:
    """Accumulates GT events as the scenario executes, then emits gt_manifest.json.

    record() captures the wall-clock time at call, so event timestamps reflect
    when the action actually happened rather than a guessed value."""

    def __init__(
        self,
        scenario_id: str,
        run_id: str,
        distro: str,
        *,
        seed: int = 0,
        cleanup: bool = False,
        timezone: str = "UTC",
    ) -> None:
        self.scenario_id = scenario_id
        self.run_id = run_id
        self.distro = distro
        self.seed = seed
        self.cleanup = cleanup
        self.timezone = timezone
        self.params = ScenarioParams(seed)
        self._events: list[GtEvent] = []

    def record(
        self,
        *,
        technique: str,
        event_class: str,
        entity_type: str,
        entity_value: Any,
        ts_utc: str | None = None,
        details: dict[str, Any] | None = None,
        expected_sources: list[str] | None = None,
        observables: list[Observable | dict[str, Any]] | None = None,
    ) -> GtEvent:
        gt_id = f"G{len(self._events) + 1}"
        event = GtEvent(
            gt_id=gt_id,
            ts_utc=ts_utc or now_utc_ms(),
            technique=technique,
            event_class=event_class,
            entity=Entity(type=entity_type, value=entity_value),
            details=details or {},
            expected_sources=expected_sources or [],
            observables=[
                o if isinstance(o, Observable) else Observable.from_dict(o)
                for o in (observables or [])
            ],
        )
        self._events.append(event)
        return event

    def to_manifest(self) -> GtManifest:
        return GtManifest(
            scenario_id=self.scenario_id,
            run_id=self.run_id,
            distro=self.distro,
            events=list(self._events),
            cleanup=self.cleanup,
            random_seed=self.seed,
            timezone=self.timezone,
        )

    def write(self, path: str | Path) -> Path:
        obj = self.to_manifest().to_dict()
        validate_gt_manifest(obj)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
        return p
