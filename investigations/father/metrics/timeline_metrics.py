#!/usr/bin/env python3
"""Father timeline-phase metrics.

Consumes the raw psort JSON-line output already written by
runme_timeline.sh under derived/timeline/raw/. Never invokes
log2timeline/psort itself.

Two modes, both operating on the same DERIVED directory:

    timeline_metrics.py --write-findings RUN_ID DERIVED_DIR WINDOW_START WINDOW_END
        Parse derived/timeline/raw/* into derived/timeline/findings.json.

    timeline_metrics.py RUN_ID DERIVED_DIR
        Read derived/timeline/findings.json and write derived/timeline/metrics.json.
"""
import json
import sys
from pathlib import Path


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def write_findings(run_id: str, derived: Path, window_start: str, window_end: str) -> None:
    raw = derived / "raw"
    window_rows = _read_jsonl(raw / "window-events.jsonl")

    family_counts: dict[str, int] = {}
    for row in window_rows:
        dt = row.get("data_type", "unknown")
        family_counts[dt] = family_counts.get(dt, 0) + 1

    inode_path = raw / "persistence-inode-events.jsonl"
    inode_query_run = inode_path.exists()
    inode_rows = _read_jsonl(inode_path) if inode_query_run else []

    skip_reason = None
    skip_marker = raw / "persistence-inode-events.SKIPPED.txt"
    if skip_marker.exists():
        skip_reason = skip_marker.read_text().strip()

    auth_related = [
        r for r in window_rows
        if r.get("data_type") in ("syslog:line", "systemd:journal")
        and any(k in str(r.get("message", "")).lower() for k in ("sudo", "sshd", "session"))
    ]

    findings = {
        "run_id": run_id,
        "window_start": window_start,
        "window_end": window_end,
        "window_event_count": len(window_rows),
        "event_family_counts": family_counts,
        "auth_related_event_count": len(auth_related),
        "inode_query_run": inode_query_run,
        "inode_event_count": len(inode_rows),
        "inode_query_skip_reason": skip_reason,
    }
    out = derived / "findings.json"
    out.write_text(json.dumps(findings, indent=2) + "\n")
    print(f"wrote {out}")


def write_metrics(run_id: str, derived: Path) -> None:
    findings_path = derived / "findings.json"
    if not findings_path.exists():
        raise SystemExit(f"missing {findings_path}; run with --write-findings first")
    f = json.loads(findings_path.read_text())

    metrics = {
        "run_id": run_id,
        "bounded_window": {
            "start": f["window_start"],
            "end": f["window_end"],
            "event_count": f["window_event_count"],
        },
        "event_family_counts": f["event_family_counts"],
        "auth_or_execution_events": f["auth_related_event_count"]
        if f["window_event_count"] > 0
        else "unknown (no events in window)",
        "persistence_inode_ordering": {
            "available": f["inode_query_run"],
            "event_count": f["inode_event_count"] if f["inode_query_run"] else "unknown",
            "reason_unavailable": f["inode_query_skip_reason"],
        },
    }
    out = derived / "metrics.json"
    out.write_text(json.dumps(metrics, indent=2) + "\n")
    print(f"wrote {out}")


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--write-findings":
        run_id, derived, window_start, window_end = argv[1], Path(argv[2]), argv[3], argv[4]
        write_findings(run_id, derived, window_start, window_end)
        return 0
    run_id, derived = argv[0], Path(argv[1])
    write_metrics(run_id, derived)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
