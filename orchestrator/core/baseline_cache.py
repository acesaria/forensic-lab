"""Clean baseline canonical artifact cache.

The cache is keyed by the existing VM/snapshot identity, e.g.
``lab-ubuntu-22.04:baseline``. It stores canonical ToolFinding rows extracted
from the pristine baseline state; it does not create a second baseline concept.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from orchestrator.canonical import ToolFinding, load_jsonl
from orchestrator.core.paths import ProjectPaths

SCHEMA = "forensic-lab.baseline-cache.v1"
EXTRACTION_PROFILE = "canonical-tool-findings-v1"

_FILESYSTEM_CLASSES = {
    "deleted_file_candidate",
    "file",
    "preload_configuration",
    "service_unit_file",
    "shared_object",
    "shell_history_log_event",
}


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
    if int(manifest.get("comparable_path_count") or 0) <= 0:
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
    comparable_paths = _comparable_paths(records)
    if not comparable_paths:
        return None
    manifest = {
        **expected,
        "created_at": time.time(),
        "tool_findings": str(tool_findings_path),
        "acquisition_manifest": str(acquisition_manifest_path) if acquisition_manifest_path else None,
        "tool_finding_count": len(records),
        "comparable_path_count": len(comparable_paths),
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


def _manifest_compatible(manifest: dict[str, Any], expected: dict[str, Any]) -> bool:
    keys = (
        "schema",
        "distro",
        "vm_name",
        "baseline_snapshot",
        "baseline_identity",
        "extraction_profile",
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


def _comparable_paths(findings: list[ToolFinding]) -> set[str]:
    out: set[str] = set()
    for finding in findings:
        if finding.artifact_class not in _FILESYSTEM_CLASSES:
            continue
        path = _normalize_path(finding.entity.get("path") or finding.entity.get("value"))
        if path:
            out.add(path)
    return out


def _normalize_path(value: Any) -> str:
    text = str(value or "").strip()
    if not text or not text.startswith("/"):
        return ""
    if " -> " in text:
        return ""
    if " (deleted)" in text:
        text = text.replace(" (deleted)", "")
    return posixpath.normpath(text)
