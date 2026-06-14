# orchestrator/evaluation/detect/sigma_vendored.py
#
# GT-blind detector that evaluates the VENDORED SigmaHQ Linux rules
# (vendor/sigma/, loaded via forensics.sigma_runner) against the Plaso event
# stream and emits source_tool="plaso_sigma" findings. The in-memory rule
# evaluation and the rule->class/technique/entity interpretation are reused from
# the sibling plaso_sigma detector so there is exactly one Sigma evaluator; only
# the rule SOURCE (vendored vs project-custom) and the source_tool tag differ.

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from orchestrator.evaluation.contracts.models import Finding
from orchestrator.evaluation.detect.base import make_finding
from orchestrator.evaluation.detect.plaso_sigma import (
    _FILE_EVENT_CLASSES,
    _entity_for,
    _is_filestat,
    _rule_event_class,
    _rule_source,
    _rule_technique,
    _ts,
    evaluate_rule,
)
from orchestrator.forensics.sigma_runner import load_rules

_TOOL = "plaso_sigma"


def detect(raw_outputs: dict[str, Any], rules_config: dict[str, Any]) -> Iterable[Finding]:
    events = raw_outputs.get("plaso", [])
    if not isinstance(events, list) or not events:
        return

    dirs = rules_config.get("sigma_vendored_dirs")
    rules: list[dict[str, Any]] = []
    if dirs:
        for d in dirs:
            rules.extend(load_rules(Path(d)))
    else:
        rules = load_rules()  # default vendor/sigma/rules/linux
    if not rules:
        return

    for rule in rules:
        rule_id = rule.get("id") or rule.get("title") or Path(rule.get("_path", "rule")).stem
        event_class = _rule_event_class(rule)
        technique = _rule_technique(rule)
        source = _rule_source(rule)
        gate_filestat = event_class not in _FILE_EVENT_CLASSES
        for i, event in enumerate(events):
            if not isinstance(event, dict):
                continue
            if gate_filestat and _is_filestat(event):
                continue
            if evaluate_rule(rule, event):
                etype, evalue = _entity_for(event_class, event, source)
                yield make_finding(
                    source_tool=_TOOL,
                    detector=f"sigma:{rule_id}",
                    rule_layer="community",
                    event_class=event_class,
                    entity_type=etype,
                    entity_value=evalue,
                    ts_quality="wallclock" if _ts(event) else "none",
                    forensic_operation="timeline",
                    technique=technique,
                    ts_utc=_ts(event),
                    raw_ref=f"plaso_sigma:event:{i}",
                    confidence="medium",
                )
