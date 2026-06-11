# orchestrator/evaluation/contracts/validate.py
#
# JSON Schema validation at every stage boundary (Phase 7.4). The schemas live
# next to this module; validation is a hard gate -- a malformed artifact aborts
# the pipeline rather than silently producing wrong metrics.

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    import jsonschema
except ImportError as exc:  # pragma: no cover - dependency is declared
    raise RuntimeError(
        "jsonschema is required for contract validation; pip install jsonschema"
    ) from exc

_SCHEMA_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=None)
def _schema(name: str) -> dict[str, Any]:
    return json.loads((_SCHEMA_DIR / name).read_text(encoding="utf-8"))


def validate_gt_manifest(obj: dict[str, Any]) -> None:
    jsonschema.validate(obj, _schema("gt_manifest.schema.json"))


def validate_finding(obj: dict[str, Any]) -> None:
    jsonschema.validate(obj, _schema("findings.schema.json"))


def validate_findings(objs: list[dict[str, Any]]) -> None:
    schema = _schema("findings.schema.json")
    for o in objs:
        jsonschema.validate(o, schema)


def validate_matches(obj: dict[str, Any]) -> None:
    jsonschema.validate(obj, _schema("matches.schema.json"))


def load_gt_manifest(path: str | Path) -> dict[str, Any]:
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_gt_manifest(obj)
    return obj


def load_findings(path: str | Path) -> list[dict[str, Any]]:
    objs: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            objs.append(obj)
    validate_findings(objs)
    return objs
