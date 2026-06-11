# orchestrator/evaluation/detect/plaso_tagging.py
#
# Plaso tagging detector (Phase 3.1, Detector B). Consumes events tagged by
# psort's tagging analysis (tag_linux.txt plus an optional project tagging file)
# and converts each tagged event into a finding. GT-blind: tags express generic
# behavior labels, never instance values.
#
# Input: raw_outputs["plaso_tagged"] -> list of events each carrying a "tag"
# list, or raw_outputs["plaso"] events that already carry a "tag" field.

from __future__ import annotations

from typing import Any, Iterable

from orchestrator.evaluation.detect.base import make_finding
from orchestrator.evaluation.contracts.models import Finding
from orchestrator.forensics.timeutil import epoch_us_to_iso_ms

_TOOL = "plaso"

# Tag label -> (event_class, technique). Tags not listed are skipped (a tag with
# no security meaning here is noise). Project tags can extend this via config.
_TAG_MAP: dict[str, tuple[str, str | None]] = {
    "login": ("auth_login", "T1078"),
    "logout": ("auth_login", "T1078"),
    "session": ("auth_login", "T1078"),
    "useradd": ("persistence_installed", "T1136.001"),
    "user_add": ("persistence_installed", "T1136.001"),
    "cron": ("persistence_installed", "T1053.003"),
    "scheduled_task": ("persistence_installed", "T1053.003"),
    "file_download": ("file_created", "T1105"),
    "shell_history": ("process_exec", "T1059.004"),
    "log_deletion": ("log_tampering", "T1070.002"),
}


def _ts(event: dict[str, Any]) -> str | None:
    ts = event.get("timestamp")
    if isinstance(ts, int) and ts > 0:
        return epoch_us_to_iso_ms(ts)
    return None


def _entity_for(event_class: str, event: dict[str, Any]) -> tuple[str, str]:
    if event_class in ("file_created", "persistence_installed", "log_tampering"):
        v = event.get("filename") or event.get("display_name") or event.get("message")
        return "path", str(v or "-")
    if event_class == "auth_login":
        v = event.get("username") or event.get("user") or event.get("body") or "-"
        return "user", str(v)
    v = event.get("command") or event.get("body") or event.get("message") or "-"
    return "process", str(v)


def detect(raw_outputs: dict[str, Any], rules_config: dict[str, Any]) -> Iterable[Finding]:
    events = raw_outputs.get("plaso_tagged")
    if not isinstance(events, list):
        events = [
            e for e in raw_outputs.get("plaso", []) if isinstance(e, dict) and e.get("tag")
        ]
    tag_map = dict(_TAG_MAP)
    tag_map.update(rules_config.get("tagging_map", {}) or {})

    for i, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        tags = event.get("tag") or event.get("label") or []
        if isinstance(tags, str):
            tags = [tags]
        for tag in tags:
            mapped = tag_map.get(str(tag))
            if not mapped:
                continue
            event_class, technique = mapped
            etype, evalue = _entity_for(event_class, event)
            yield make_finding(
                source_tool=_TOOL,
                detector=f"tagging:{tag}",
                rule_layer="community",
                event_class=event_class,
                entity_type=etype,
                entity_value=evalue,
                ts_quality="wallclock" if _ts(event) else "none",
                technique=technique,
                ts_utc=_ts(event),
                raw_ref=f"plaso:tagged:{i}",
                confidence="low",
            )
