# orchestrator/forensics/ioc_detector/plaso.py
#
# Timeline detection (Plaso). Matches the run's parsed timeline events against a
# spec's needles, and exposes the filesystem time for a path so disk artifacts
# can borrow a timestamp for the evaluator's ordering check.

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from orchestrator.forensics.ioc_detector.status import (
    DISK_STATUS_PRESENT,
    empty_detection,
)

if TYPE_CHECKING:
    from orchestrator.forensics.ioc_detector.context import DetectorContext


def epoch_us_to_iso(ts_us: int) -> str:
    # Plaso emits timestamps as microseconds since the Unix epoch (UTC).
    return datetime.fromtimestamp(ts_us / 1_000_000, timezone.utc).isoformat()


# Preferred filesystem time for a disk artifact's representative timestamp.
# Content-modification (mtime) is when the attack last touched the file: for a
# dropped file mtime == creation, but for a pre-existing log the attack appended
# to (e.g. auth.log) only mtime reflects the attack -- creation is the log's old
# birth date and would wrongly drag the step's time backwards.
_TS_DESC_PREFERENCE = ("Content Modification Time", "Creation Time")


def path_timeline_ts(events: list[dict[str, Any]] | None, path: str) -> int | None:
    # Filesystem time for `path` from Plaso, preferring content mtime. Only
    # fs:stat (filesystem-metadata) events count -- the parsed *log line* events
    # for a file like auth.log share its path but carry every historical line's
    # date, so including them would drag the time back to the file's first entry.
    # Returns epoch microseconds, or None when the timeline does not cover it.
    if not events or not path:
        return None
    by_desc: dict[str, int] = {}
    for event in events:
        if event.get("data_type") != "fs:stat":
            continue
        filename = event.get("filename")
        display = event.get("display_name")
        if filename != path and not (
            isinstance(display, str) and display.endswith(path)
        ):
            continue
        ts = event.get("timestamp")
        if not isinstance(ts, int) or ts <= 0:
            continue
        desc = event.get("timestamp_desc") or ""
        by_desc[desc] = min(by_desc.get(desc, ts), ts)
    for desc in _TS_DESC_PREFERENCE:
        if desc in by_desc:
            return by_desc[desc]
    return min(by_desc.values()) if by_desc else None


def detect_timeline(spec: dict[str, Any], ctx: "DetectorContext") -> dict[str, Any]:
    events = ctx.timeline_events
    if events is None:
        return empty_detection()

    query = spec["query"]
    needles = query.get("message_contains_any", [])
    # filename_substring matches filesystem-metadata events by path rather than
    # command text. The scenario runs non-interactively, so shell history is thin;
    # the path of a dropped/modified file is the reliable timeline signal. Plaso
    # spells the path differently across parsers, so scan filename, display_name,
    # then message.
    name_needle = query.get("filename_substring")

    matches: list[dict[str, Any]] = []
    matched_needle: str | None = None
    matched_field: str | None = None
    for event in events:
        message = event.get("message")
        if isinstance(message, str):
            hit = next((n for n in needles if n in message), None)
            if hit is not None:
                matches.append(
                    {"timestamp": event.get("timestamp"), "message": message}
                )
                if matched_needle is None:
                    matched_needle, matched_field = hit, "message"
                continue
        if name_needle is not None:
            for key in ("filename", "display_name", "message"):
                val = event.get(key)
                if isinstance(val, str) and name_needle in val:
                    matches.append(
                        {"timestamp": event.get("timestamp"), "message": val}
                    )
                    if matched_needle is None:
                        matched_needle, matched_field = name_needle, key
                    break

    if not matches:
        return empty_detection()

    ts_values = [
        m["timestamp"]
        for m in matches
        if isinstance(m["timestamp"], int) and m["timestamp"] > 0
    ]
    timestamp = min(ts_values) if ts_values else None
    return {
        "found": True,
        "status": DISK_STATUS_PRESENT,
        "evidence": {
            "tool": "plaso",
            "method": matched_field or "timeline",
            "locator": epoch_us_to_iso(timestamp) if timestamp else "-",
            "match": matched_needle,
        },
        "timestamp": timestamp,
        "matches": matches,
    }
