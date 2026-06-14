# orchestrator/evaluation/detect/bulk_extractor_strings.py
#
# GT-blind detector over bulk_extractor feature records produced by
# forensics.bulk_extractor_runner (placed in raw_outputs["bulk_extractor"]). Each
# distinct feature string becomes a string_search finding. The runner already did
# any token filtering at the I/O layer; here we just normalize to findings, so no
# scenario constant is hardcoded in the GT-blind layer.

from __future__ import annotations

from typing import Any, Iterable

from orchestrator.evaluation.contracts.models import Finding
from orchestrator.evaluation.detect.base import make_finding

_TOOL = "bulk_extractor"


def detect(raw_outputs: dict[str, Any], rules_config: dict[str, Any]) -> Iterable[Finding]:
    records = raw_outputs.get("bulk_extractor")
    if not isinstance(records, list):
        return
    seen: set[str] = set()
    for r in records:
        if not isinstance(r, dict):
            continue
        feature = r.get("feature")
        if not feature or feature in seen:
            continue
        seen.add(feature)
        yield make_finding(
            source_tool=_TOOL,
            detector="bulk_extractor:wordlist",
            # A recovered string is the bare existence of an artifact token; the
            # permissive class lets it corroborate file/persistence events.
            event_class="file_created",
            entity_type="string",
            entity_value=str(feature),
            ts_quality="none",
            forensic_operation="string_search",
            raw_ref=f"bulk_extractor:offset={r.get('offset', '')}",
            confidence="low",
        )
