# orchestrator/evaluation/detect/yara_scan.py
#
# GT-blind detector over YARA matches produced by forensics.yara_runner (placed
# in raw_outputs["yara"]). Each (file, rule) match becomes a content_scan finding
# for the matched path. GT-blind: a YARA hit is a signature on file content, it
# carries no planted instance value; the matcher decides relevance against GT.

from __future__ import annotations

import re
from typing import Any, Iterable

from orchestrator.evaluation.contracts.models import Finding
from orchestrator.evaluation.detect.base import make_finding

_TOOL = "yara"
_ATTACK_RE = re.compile(r"(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def _technique(match: dict[str, Any]) -> str | None:
    meta = match.get("meta") or {}
    for key in ("technique", "mitre", "attack"):
        v = meta.get(key)
        if isinstance(v, str):
            m = _ATTACK_RE.search(v)
            if m:
                return m.group(1).upper()
    for tag in match.get("tags") or []:
        m = _ATTACK_RE.search(str(tag))
        if m:
            return m.group(1).upper()
    return None


def detect(raw_outputs: dict[str, Any], rules_config: dict[str, Any]) -> Iterable[Finding]:
    matches = raw_outputs.get("yara")
    if not isinstance(matches, list):
        return
    for m in matches:
        if not isinstance(m, dict):
            continue
        path = m.get("path")
        rule = m.get("rule")
        if not path or not rule:
            continue
        yield make_finding(
            source_tool=_TOOL,
            detector=f"yara:{rule}",
            event_class="file_created",  # a flagged file present on disk
            entity_type="path",
            entity_value=str(path),
            ts_quality="none",  # a content signature carries no reliable time
            forensic_operation="content_scan",
            technique=_technique(m),
            raw_ref=f"yara:{rule}:{path}",
            confidence="high",
        )
