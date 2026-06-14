# orchestrator/evaluation/detect/plaso_sigma.py
#
# Plaso Sigma detector (Phase 3.1, Detector A). Evaluates Sigma rules against the
# psort JSON-L event stream. GT-blind: rules express behavioral patterns only;
# the rule-leakage lint forbids any instance constant in a rule file.
#
# pySigma is used when installed; otherwise a dependency-light evaluator handles
# the common Linux Sigma subset (named selections with field modifiers
# contains/startswith/endswith/re, and conditions built from and/or/not/
# "all of them"/"1 of them"/"all of <prefix>*"). A field-mapping table per data
# source bridges Plaso attributes to Sigma fields.

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

import yaml

from orchestrator.evaluation.detect.base import make_finding
from orchestrator.evaluation.contracts.models import Finding

_TOOL = "plaso"

# Sigma field -> ordered Plaso attributes to read for it, per data source. The
# default applies when a more specific source mapping has no entry. message is
# always the last-resort haystack so a rule still fires when a parser spells a
# field unexpectedly.
_FIELD_MAP: dict[str, dict[str, tuple[str, ...]]] = {
    "default": {
        "Image": ("executable", "Image", "filename", "display_name"),
        "CommandLine": ("command", "CommandLine", "body", "message"),
        "TargetFilename": ("filename", "TargetFilename", "display_name"),
        "DestinationIp": ("dest_ip", "DestinationIp"),
        "DestinationPort": ("dest_port", "DestinationPort"),
        "User": ("username", "user", "User"),
        "_msg": ("message", "body"),
    },
    "auth": {
        "User": ("username", "user"),
        "_msg": ("body", "message"),
    },
    "cron": {
        "_msg": ("body", "message"),
    },
}

_CATEGORY_TO_CLASS = {
    "process_creation": "process_exec",
    "file_event": "file_created",
    "file_change": "file_modified",
    "file_delete": "file_deleted",
    "network_connection": "network_connection",
}

# Event classes that legitimately derive from a filesystem-metadata (fs:stat)
# event. A file existing under /tmp is not evidence it executed or opened a
# socket, so process/network rules must not fire on bare filestat rows.
_FILE_EVENT_CLASSES = frozenset(
    {
        "file_created",
        "file_modified",
        "file_deleted",
        "persistence_installed",
        "log_tampering",
        "history_cleared",
    }
)


def _is_filestat(event: dict[str, Any]) -> bool:
    return event.get("data_type") == "fs:stat" or event.get("parser") == "filestat"


def _event_value(event: dict[str, Any], sigma_field: str, source: str) -> str | None:
    mapping = _FIELD_MAP.get(source, {})
    keys = mapping.get(sigma_field) or _FIELD_MAP["default"].get(sigma_field, ())
    for k in keys:
        v = event.get(k)
        if isinstance(v, (str, int)) and str(v) != "":
            return str(v)
    return None


def _match_value(event_val: str, modifier: str, expected: Any) -> bool:
    candidates = expected if isinstance(expected, list) else [expected]
    ev = event_val
    for exp in candidates:
        exp_s = str(exp)
        if modifier == "contains" and exp_s in ev:
            return True
        if modifier == "startswith" and ev.startswith(exp_s):
            return True
        if modifier == "endswith" and ev.endswith(exp_s):
            return True
        if modifier == "re" and re.search(exp_s, ev):
            return True
        if modifier == "" and ev == exp_s:
            return True
    return False


def _eval_selection(sel: Any, event: dict[str, Any], source: str) -> bool:
    # A selection is a mapping {field|modifier: value(s)} ANDed together, or a
    # list of such maps ORed together.
    if isinstance(sel, list):
        return any(_eval_selection(s, event, source) for s in sel)
    if not isinstance(sel, dict):
        return False
    for key, expected in sel.items():
        field, _, modifier = key.partition("|")
        ev = _event_value(event, field, source)
        if ev is None:
            # Unmapped field: fall back to scanning the message text so a rule is
            # not silently dead when a parser omits the exact attribute.
            ev = _event_value(event, "_msg", source) or ""
        if not _match_value(ev, modifier, expected):
            return False
    return True


def _eval_condition(condition: str, selections: dict[str, bool]) -> bool:
    expr = condition.strip()
    names = list(selections.keys())

    def _join(sel_names: list[str], op: str) -> str:
        return ("(" + f" {op} ".join(sel_names) + ")") if sel_names else "False"

    expr = expr.replace("all of them", _join(names, "and"))
    expr = re.sub(r"\b1 of them\b", _join(names, "or"), expr)
    expr = re.sub(r"\bany of them\b", _join(names, "or"), expr)

    def _of_prefix(m: re.Match) -> str:
        op = "and" if m.group(1) == "all" else "or"
        prefix = m.group(2)
        matched = [n for n in names if n.startswith(prefix)]
        return _join(matched, op)

    expr = re.sub(r"\b(all|1|any) of (\w+)\*", _of_prefix, expr)

    # Now a boolean expression over selection names + and/or/not/parens.
    tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z0-9_]*", expr)
    py = []
    for t in tokens:
        if t in ("and", "or", "not", "(", ")"):
            py.append(t)
        elif t in ("True", "False"):
            py.append(t)
        else:
            py.append("True" if selections.get(t, False) else "False")
    try:
        return bool(eval(" ".join(py), {"__builtins__": {}}, {}))  # noqa: S307
    except Exception:
        return False


def _rule_source(rule: dict[str, Any]) -> str:
    ls = rule.get("logsource", {}) or {}
    return str(ls.get("service") or ls.get("category") or "default")


def _rule_event_class(rule: dict[str, Any]) -> str:
    if rule.get("event_class"):
        return str(rule["event_class"])
    ls = rule.get("logsource", {}) or {}
    cat = ls.get("category")
    if cat in _CATEGORY_TO_CLASS:
        return _CATEGORY_TO_CLASS[cat]
    if ls.get("service") == "cron":
        return "persistence_installed"
    return "process_exec"


def _rule_technique(rule: dict[str, Any]) -> str | None:
    for tag in rule.get("tags", []) or []:
        m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag), re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return None


def _entity_for(event_class: str, event: dict[str, Any], source: str) -> tuple[str, str]:
    if event_class in ("file_created", "file_modified", "file_deleted", "persistence_installed"):
        v = _event_value(event, "TargetFilename", source) or _event_value(event, "Image", source)
        return "path", (v or "-")
    if event_class == "network_connection":
        ip = _event_value(event, "DestinationIp", source) or "-"
        port = _event_value(event, "DestinationPort", source)
        return "socket", (f"{ip}:{port}" if port else ip)
    v = _event_value(event, "CommandLine", source) or _event_value(event, "Image", source)
    return "process", (v or "-")


def _ts(event: dict[str, Any]) -> str | None:
    from orchestrator.forensics.timeutil import epoch_us_to_iso_ms

    ts = event.get("timestamp")
    if isinstance(ts, int) and ts > 0:
        return epoch_us_to_iso_ms(ts)
    return None


def load_rules(rule_dirs: list[Path]) -> list[tuple[dict[str, Any], str, Path]]:
    # Returns (rule, rule_layer, path). rule_layer is "custom" for rules under a
    # .../custom/ directory, "community" otherwise.
    rules: list[tuple[dict[str, Any], str, Path]] = []
    for d in rule_dirs:
        if not d.is_dir():
            continue
        for path in sorted(d.rglob("*.yml")) + sorted(d.rglob("*.yaml")):
            try:
                docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
            except yaml.YAMLError:
                continue
            layer = "custom" if "custom" in path.parts else "community"
            for doc in docs:
                if isinstance(doc, dict) and "detection" in doc:
                    rules.append((doc, layer, path))
    return rules


def evaluate_rule(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")
    source = _rule_source(rule)
    selections = {
        name: _eval_selection(sel, event, source)
        for name, sel in detection.items()
        if name != "condition"
    }
    return _eval_condition(str(condition), selections)


def detect(raw_outputs: dict[str, Any], rules_config: dict[str, Any]) -> Iterable[Finding]:
    events = raw_outputs.get("plaso", [])
    if not isinstance(events, list):
        return
    rule_dirs = [Path(p) for p in rules_config.get("sigma_rule_dirs", [])]
    rules = load_rules(rule_dirs)
    for rule, layer, path in rules:
        rule_id = rule.get("id") or rule.get("title") or path.stem
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
                    rule_layer=layer,
                    event_class=event_class,
                    entity_type=etype,
                    entity_value=evalue,
                    ts_quality="wallclock" if _ts(event) else "none",
                    forensic_operation="timeline",
                    technique=technique,
                    ts_utc=_ts(event),
                    raw_ref=f"plaso:event:{i}",
                    confidence="medium",
                )
