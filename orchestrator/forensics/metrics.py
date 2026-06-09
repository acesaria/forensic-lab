# orchestrator/forensics/metrics.py
#
# Recovery metrics derived from forensics_report.json. Two consumers share this
# logic so the numbers never drift:
#   - the orchestrator, which writes a per-run metrics.csv beside each
#     forensics_report.json and refreshes the combined no-cleanup vs cleanup view;
#   - scripts/report_metrics.py, the on-demand CLI.
#
# Table 1  one row per run: detection rate (DR), quality-of-recovery (QoR),
#          and temporal Order (do recovered artifacts respect the step order).
#          This is the only aggregator written to the combined cross-run CSV.
# Table 2  one row per declared artifact (per-run only): the tool:method that
#          found it, the artifact locator, whether it was found, and details
#          (the match criterion + timestamp, or room for manual notes).
#
# No false-positive metric: every count is "found vs declared", never an FP rate.

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterator

# Tool display order; "unknown" covers artifacts whose type the evaluator could
# not route. QoR bands: Low <50, Medium 50-74, High >=75.
_TOOL_ORDER = {"sleuthkit": 0, "vol3": 1, "plaso": 2, "unknown": 3}
_QOR_HIGH = 75.0
_QOR_MEDIUM = 50.0

TABLE1_COLS = [
    "Scenario", "Cleanup", "Distro", "Found/Tot", "DR%", "QoR", "Order", "Active tools"
]
# Table 2 is per-experiment and per-artifact: Tool carries tool:method, Key
# artifact the locator, Details the match criterion + timestamp (or free notes).
TABLE2_COLS = ["Step", "Phase", "Tool", "Key artifact", "Found", "Details"]


def load_report(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def iter_artifacts(
    report: dict[str, Any],
) -> Iterator[tuple[str, dict[str, Any], dict[str, Any]]]:
    # (step_name, step, artifact) for every declared artifact. Skipped/empty
    # steps contribute nothing.
    for step_name, step in report.get("steps", {}).items():
        for art in step.get("artifacts", []):
            yield step_name, step, art


def has_cleanup(report: dict[str, Any]) -> bool:
    # Derived from content, not argument order: any cleanup-phase artifact, or
    # (for pre-phase reports) a step named "cleanup".
    if any(a.get("phase") == "cleanup" for _, _, a in iter_artifacts(report)):
        return True
    return "cleanup" in report.get("steps", {})


def distro_of(report: dict[str, Any]) -> str:
    # run_id is "<distro>_<scenario>_<timestamp>"; strip scenario + timestamp.
    run_id = report.get("run_id", "")
    scenario = report.get("scenario_id", "")
    if scenario and scenario in run_id:
        return run_id.split(scenario)[0].strip("_") or run_id
    return run_id or "unknown"


def active_tools(report: dict[str, Any]) -> list[str]:
    active = {
        tool
        for step in report.get("steps", {}).values()
        for tool, hit in (step.get("tool_hits") or {}).items()
        if hit
    }
    return sorted(active, key=lambda t: _TOOL_ORDER.get(t, 99))


def qor_band(pct: float | None) -> str:
    if pct is None:
        return "n/a"
    if pct >= _QOR_HIGH:
        return "High"
    if pct >= _QOR_MEDIUM:
        return "Medium"
    return "Low"


def order_label(report: dict[str, Any]) -> str:
    # Temporal consistency: OK when recovered artifacts respect step order,
    # violated when they do not, n/a when fewer than two steps carry a timestamp.
    consistent = (report.get("temporal_consistency") or {}).get("consistent")
    if consistent is True:
        return "OK"
    if consistent is False:
        return "violated"
    return "n/a"


def _epoch_us_to_iso(ts_us: int) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts_us / 1_000_000, timezone.utc).isoformat()


def _artifact_tool(art: dict[str, Any]) -> str:
    # "tool:method" for a hit (e.g. sleuthkit:fls+icat); the inferred tool alone
    # when nothing was found (no method ran to a hit).
    ev = art.get("evidence") or {}
    base = ev.get("tool") or art.get("tool") or "unknown"
    method = ev.get("method")
    return f"{base}:{method}" if method else base


def _artifact_details(art: dict[str, Any]) -> str:
    # The match criterion plus the artifact timestamp; a free-text column the
    # thesis can also annotate by hand. Empty/"not_found" when nothing matched.
    if not art.get("found"):
        return art.get("status") or "not_found"
    ev = art.get("evidence") or {}
    parts: list[str] = []
    if ev.get("match"):
        parts.append(str(ev["match"]))
    ts = art.get("timestamp")
    if isinstance(ts, int) and ts > 0:
        parts.append(_epoch_us_to_iso(ts))
    return "; ".join(parts) or (art.get("status") or "")


def table1_row(report: dict[str, Any]) -> dict[str, Any]:
    arts = [a for _, _, a in iter_artifacts(report)]
    total = len(arts)
    found = sum(1 for a in arts if a.get("found"))
    # QoR looks only at attack-phase primaries (phase defaults to "attack" for
    # pre-phase reports): it is the mean recovery quality of the core attack
    # evidence, where each primary scores its status->quality (0.0 when missing).
    primaries = [
        a for a in arts if a.get("primary") and a.get("phase", "attack") == "attack"
    ]
    p_total = len(primaries)
    p_found = sum(1 for a in primaries if a.get("found"))
    qor_pct = (
        sum(a.get("quality", 0.0) for a in primaries) / p_total * 100
        if p_total
        else None
    )
    return {
        "Scenario": report.get("scenario_id", "unknown"),
        "Cleanup": "Yes" if has_cleanup(report) else "No",
        "Distro": distro_of(report),
        "Found/Tot": f"{found}/{total}",
        "DR%": round(found / total * 100, 1) if total else 0.0,
        "QoR": qor_band(qor_pct),
        "Order": order_label(report),
        "Active tools": ", ".join(active_tools(report)) or "-",
        # text summaries only:
        "_qor_detail": f"{qor_pct:.0f}% ({p_found}/{p_total} found)"
        if qor_pct is not None
        else "n/a",
    }


def table2_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    # One row per declared artifact, in scenario order. Found artifacts name
    # their locator and tool:method; missing ones still appear (coverage) with
    # the inferred tool and a not_found detail.
    rows: list[dict[str, Any]] = []
    for step_name, _, art in iter_artifacts(report):
        found = bool(art.get("found"))
        ev = art.get("evidence") or {}
        locator = ev.get("locator") if found else None
        rows.append(
            {
                "Step": step_name,
                "Phase": art.get("phase", "attack"),
                "Tool": _artifact_tool(art),
                "Key artifact": locator or art.get("id") or "-",
                "Found": "yes" if found else "no",
                "Details": _artifact_details(art),
            }
        )
    return rows


def _write_sections(
    out_path: Path, sections: list[tuple[str, list[str], list[dict[str, Any]]]]
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        for i, (title, cols, rows) in enumerate(sections):
            if i:
                writer.writerow([])
            writer.writerow([f"# {title}"])
            writer.writerow(cols)
            for row in rows:
                writer.writerow([row[c] for c in cols])


def write_run_metrics(report: dict[str, Any], out_path: Path) -> Path:
    # Per-experiment: this run's summary row + its per-artifact breakdown (no Run
    # column -- the file already belongs to one run).
    _write_sections(
        out_path,
        [
            ("Table 1: run summary", TABLE1_COLS, [table1_row(report)]),
            ("Table 2: per artifact", TABLE2_COLS, table2_rows(report)),
        ],
    )
    return out_path


def write_combined_metrics(reports: list[dict[str, Any]], out_path: Path) -> Path:
    # Cross-run A/B: only the Table-1 summary (one row per run). The per-artifact
    # Table 2 is per-run detail and is meaningless aggregated across runs, so it
    # is intentionally omitted here.
    t1 = [table1_row(r) for r in reports]
    _write_sections(out_path, [("Table 1: per-run summary", TABLE1_COLS, t1)])
    return out_path


def discover_latest(experiments_dir: Path) -> tuple[Path, Path] | None:
    # Latest no-cleanup and cleanup forensics_report.json. run_id ends in a
    # timestamp, so lexical sort over the run dir == chronological; last wins.
    reports = sorted(experiments_dir.glob("*/analysis/forensics_report.json"))
    no_cleanup: Path | None = None
    cleanup: Path | None = None
    for path in reports:
        try:
            report = load_report(path)
        except (OSError, ValueError):
            continue
        if has_cleanup(report):
            cleanup = path
        else:
            no_cleanup = path
    if no_cleanup is None or cleanup is None:
        return None
    return no_cleanup, cleanup


def refresh_combined(experiments_dir: Path, out_path: Path) -> Path | None:
    # Best-effort: the combined view needs both a no-cleanup and a cleanup run.
    # Returns None (and writes nothing) until both exist.
    found = discover_latest(experiments_dir)
    if found is None:
        return None
    no_cleanup, cleanup = found
    write_combined_metrics([load_report(no_cleanup), load_report(cleanup)], out_path)
    return out_path
