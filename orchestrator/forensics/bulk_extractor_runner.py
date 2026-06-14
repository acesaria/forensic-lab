# orchestrator/forensics/bulk_extractor_runner.py
#
# Thin bulk_extractor I/O over an E01/raw disk image. Runs the binary into a
# temp directory, parses one or more feature files, and returns raw string
# records. Finding emission happens in evaluation/detect/bulk_extractor_strings.py.
#
# bulk_extractor feature-file line format (tab-separated):
#   <forensic_path/offset>\t<feature>\t<context>
# Lines beginning with "#" are headers/comments.

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable

_log = logging.getLogger(__name__)

# Feature files worth parsing for scenario_01. wordlist captures path-like and
# config strings; url captures any embedded URLs.
DEFAULT_FEATURE_FILES: tuple[str, ...] = ("wordlist.txt", "url.txt")


def resolve_binary(name_or_path: str = "bulk_extractor") -> str:
    resolved = shutil.which(name_or_path) or name_or_path
    if not Path(resolved).is_file():
        raise FileNotFoundError(
            f"bulk_extractor binary not found: {name_or_path!r}. "
            "Install bulk_extractor or add it to PATH."
        )
    return resolved


def run_bulk_extractor(
    image_path: Path, out_dir: Path, be_bin: str = "bulk_extractor",
    scanners: tuple[str, ...] = ("wordlist",),
) -> dict[str, Any]:
    # Run bulk_extractor over the image into out_dir. Only the wordlist scanner is
    # enabled by default to keep the run fast and the feature set small; pass more
    # scanner names to widen it.
    binary = resolve_binary(be_bin)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [binary, "-o", str(out_dir)]
    for s in scanners:
        cmd += ["-e", s]
    cmd += [str(image_path)]
    _log.debug("bulk_extractor: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"bulk_extractor failed for {image_path.name}:\n"
            f"{result.stderr.strip() or '(no output)'}"
        )
    return {"command": cmd, "out_dir": str(out_dir), "returncode": result.returncode}


def parse_feature_file(
    path: Path, tokens: Iterable[str] | None = None
) -> list[dict[str, Any]]:
    # Parse a bulk_extractor feature file into {offset, feature, context} records.
    # When tokens is given, keep only lines containing one of them; otherwise keep
    # every feature line. Generic by design so the token filter can be widened or
    # dropped later without touching the parser.
    records: list[dict[str, Any]] = []
    if not path.is_file():
        return records
    token_list = list(tokens) if tokens else None
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            offset, feature = parts[0], parts[1]
            context = parts[2] if len(parts) > 2 else ""
            if token_list is not None and not any(t in feature for t in token_list):
                continue
            records.append({"offset": offset, "feature": feature, "context": context})
    return records


def run(
    image_path: Path,
    *,
    out_dir: Path | None = None,
    feature_files: tuple[str, ...] = DEFAULT_FEATURE_FILES,
    tokens: Iterable[str] | None = None,
    be_bin: str = "bulk_extractor",
) -> list[dict[str, Any]]:
    # Convenience entry: run bulk_extractor into a temp dir (unless out_dir given)
    # and parse the configured feature files into one flat record list.
    tmp = None
    target = out_dir
    if target is None:
        tmp = Path(tempfile.mkdtemp(prefix="bulk-extractor-"))
        target = tmp
    try:
        run_bulk_extractor(image_path, target, be_bin=be_bin)
        records: list[dict[str, Any]] = []
        for name in feature_files:
            records.extend(parse_feature_file(target / name, tokens=tokens))
        return records
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)
