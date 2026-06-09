# orchestrator/forensics/ioc_detector/context.py
#
# DetectorContext bundles the per-run resources (the tool runners + acquired
# images + timeline) with the caches that keep each expensive call -- the
# partition probe, the fls listing, a vol3 plugin -- to one invocation per run.
# Every detector takes (spec, ctx), so adding a detector never grows an argument
# list.

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from orchestrator.forensics.sleuth_runner import SleuthKitRunner, parse_fls_line
from orchestrator.forensics.vol_runner import VolatilityRunner

_log = logging.getLogger(__name__)


def _normalize_fls_path(name: str) -> str:
    # fls -p emits volume-root-relative paths without a leading slash and marks
    # directories with a trailing slash. Normalize to an absolute-looking path so
    # specs can write "/etc/ld.so.preload".
    return "/" + name.lstrip("/").rstrip("/")


@dataclass
class DetectorContext:
    sleuth: SleuthKitRunner
    vol: VolatilityRunner
    disk_path: Path
    memory_path: Path
    distro_id: str
    timeline_events: list[dict[str, Any]] | None = None

    _offset: int | None = field(default=None, init=False, repr=False)
    _fls_rows: list[dict[str, Any]] | None = field(default=None, init=False, repr=False)
    _plugins: dict[str, list[dict[str, Any]]] = field(
        default_factory=dict, init=False, repr=False
    )

    @property
    def offset(self) -> int:
        # Byte offset of the root ext partition, probed once.
        if self._offset is None:
            self._offset = self.sleuth.partition_offset(self.disk_path)
        return self._offset

    def fls_rows(self) -> list[dict[str, Any]]:
        # Whole-filesystem listing (-r -p), parsed and cached: one fls call covers
        # every disk spec.
        if self._fls_rows is None:
            rows: list[dict[str, Any]] = []
            for line in self.sleuth.fls(self.disk_path, self.offset, flags="-r -p"):
                parsed = parse_fls_line(line)
                if parsed is None:
                    continue
                parsed["path"] = _normalize_fls_path(parsed["name"])
                rows.append(parsed)
            self._fls_rows = rows
        return self._fls_rows

    def plugin_rows(self, plugin: str) -> list[dict[str, Any]]:
        # Run a vol3 plugin once per run. A plugin missing for this kernel/build
        # yields [] so the next candidate in a category still gets a turn.
        rows = self._plugins.get(plugin)
        if rows is None:
            try:
                rows = self.vol.run_plugin(self.memory_path, self.distro_id, plugin)
            except RuntimeError as exc:
                _log.warning("vol3 plugin %s failed: %s", plugin, exc)
                rows = []
            self._plugins[plugin] = rows
        return rows
