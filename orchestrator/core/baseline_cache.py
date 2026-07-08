"""Clean baseline canonical artifact cache.

The cache is keyed by the existing VM/snapshot identity, e.g.
``lab-ubuntu-22.04:baseline``. It stores canonical ToolFinding rows extracted
from the pristine baseline state plus the raw channel outputs that produced
them (analysis/bodyfile, vol3.json, timeline.jsonl, timeline.plaso), so the
rows can be re-adapted offline when adapters change; it does not create a
second baseline concept.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from orchestrator.adapters.common import ADAPTER_VERSION
from orchestrator.canonical import ToolFinding, load_jsonl
from orchestrator.core.paths import ProjectPaths

SCHEMA = "forensic-lab.baseline-cache.v2"
EXTRACTION_PROFILE = "canonical-tool-findings-v1"

# Raw channel files preserved under <cache_dir>/analysis for audit and
# offline re-adaptation.
RAW_CHANNELS = ("bodyfile", "vol3.json", "timeline.jsonl", "timeline.plaso")


@dataclass(frozen=True)
class BaselineCacheEntry:
    identity: str
    cache_dir: Path
    manifest_path: Path
    tool_findings_path: Path
    manifest: dict[str, Any]
    reused: bool


def baseline_identity(distro_id: str, *, vm_prefix: str, snapshot: str) -> str:
    return f"{vm_prefix}-{distro_id}:{snapshot}"


def cache_dir_for_identity(paths: ProjectPaths, identity: str) -> Path:
    digest = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:12]
    slug = "".join(ch if ch.isalnum() or ch in ".-" else "-" for ch in identity.lower())
    return paths.baselines_dir / f"{slug}-{digest}"


def expected_manifest(
    *,
    distro_id: str,
    vm_name: str,
    snapshot: str,
    identity: str,
    profile: dict[str, Any] | None,
    guest: dict[str, Any] | None,
    tool_versions: dict[str, Any] | None,
    volatility: dict[str, Any] | None,
) -> dict[str, Any]:
    warnings = _identity_warnings(profile=profile, guest=guest, tool_versions=tool_versions)
    return {
        "schema": SCHEMA,
        "distro": distro_id,
        "vm_name": vm_name,
        "baseline_snapshot": snapshot,
        "baseline_identity": identity,
        "extraction_profile": EXTRACTION_PROFILE,
        "adapter_version": ADAPTER_VERSION,
        "source_image": dict((profile or {}).get("image") or {}),
        "guest": guest or {},
        "tool_versions": tool_versions or {},
        "volatility": volatility or {},
        "warnings": warnings,
    }


def load_compatible_cache(
    paths: ProjectPaths,
    expected: dict[str, Any],
) -> BaselineCacheEntry | None:
    cache_dir = cache_dir_for_identity(paths, str(expected["baseline_identity"]))
    manifest_path = cache_dir / "manifest.json"
    tool_findings_path = cache_dir / "tool_findings.jsonl"
    if not manifest_path.is_file() or not tool_findings_path.is_file():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not _manifest_compatible(manifest, expected):
        return None
    if int((manifest.get("source_counts") or {}).get("disk") or 0) <= 0:
        return None
    return BaselineCacheEntry(
        identity=str(expected["baseline_identity"]),
        cache_dir=cache_dir,
        manifest_path=manifest_path,
        tool_findings_path=tool_findings_path,
        manifest=manifest,
        reused=True,
    )


def write_cache_manifest(
    paths: ProjectPaths,
    expected: dict[str, Any],
    *,
    tool_findings_path: Path,
    acquisition_manifest_path: Path | None,
) -> BaselineCacheEntry | None:
    cache_dir = cache_dir_for_identity(paths, str(expected["baseline_identity"]))
    cache_dir.mkdir(parents=True, exist_ok=True)
    records = load_jsonl(tool_findings_path, ToolFinding)
    source_counts = Counter(record.source_type.value for record in records)
    if source_counts.get("disk", 0) <= 0:
        return None
    manifest = {
        **expected,
        "created_at": time.time(),
        "tool_findings": str(tool_findings_path),
        "acquisition_manifest": str(acquisition_manifest_path) if acquisition_manifest_path else None,
        "tool_finding_count": len(records),
        "source_counts": dict(sorted(source_counts.items())),
        "raw_channels": _raw_channels(cache_dir),
    }
    manifest_path = cache_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return BaselineCacheEntry(
        identity=str(expected["baseline_identity"]),
        cache_dir=cache_dir,
        manifest_path=manifest_path,
        tool_findings_path=tool_findings_path,
        manifest=manifest,
        reused=False,
    )


def _raw_channels(cache_dir: Path) -> dict[str, dict[str, Any]]:
    """Path, sha256 and size of each preserved raw channel file (cheap
    whole-file hashes for audit/reproducibility, not per-file content hashes
    of the imaged filesystem)."""
    out: dict[str, dict[str, Any]] = {}
    for name in RAW_CHANNELS:
        path = cache_dir / "analysis" / name
        if not path.is_file():
            continue
        with path.open("rb") as fh:
            digest = hashlib.file_digest(fh, "sha256")
        out[name] = {
            "path": str(path),
            "sha256": digest.hexdigest(),
            "size_bytes": path.stat().st_size,
        }
    return out


def _manifest_compatible(manifest: dict[str, Any], expected: dict[str, Any]) -> bool:
    # adapter_version is part of the identity: stale-format rows must never be
    # reused silently. A mismatch forces a rebuild (offline re-adaptation of
    # the preserved raw channels is enough; no VM re-acquisition is required).
    keys = (
        "schema",
        "distro",
        "vm_name",
        "baseline_snapshot",
        "baseline_identity",
        "extraction_profile",
        "adapter_version",
        "source_image",
        "guest",
        "tool_versions",
        "volatility",
    )
    return all(manifest.get(key) == expected.get(key) for key in keys)


def _identity_warnings(
    *,
    profile: dict[str, Any] | None,
    guest: dict[str, Any] | None,
    tool_versions: dict[str, Any] | None,
) -> list[str]:
    warnings: list[str] = []
    image = (profile or {}).get("image") or {}
    if not image.get("url"):
        warnings.append("source image URL unavailable")
    if not (image.get("checksum") or image.get("checksum_url")):
        warnings.append("source image checksum identity unavailable")
    if not (guest or {}).get("kernel"):
        warnings.append("guest kernel unavailable")
    if not tool_versions:
        warnings.append("tool version identity unavailable")
    return warnings
