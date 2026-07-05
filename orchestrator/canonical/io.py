"""JSON and JSONL helpers for canonical records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, TypeVar

from orchestrator.canonical.models import CanonicalRecord

T = TypeVar("T", bound=CanonicalRecord)


def append_jsonl(path: str | Path, record: CanonicalRecord) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(record.to_json() + "\n")
    return p


def write_jsonl(path: str | Path, records: Iterable[CanonicalRecord]) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(record.to_json() + "\n")
    return p


def load_jsonl(path: str | Path, record_type: type[T]) -> list[T]:
    out: list[T] = []
    with Path(path).open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
            out.append(record_type.from_dict(data))
    return out
