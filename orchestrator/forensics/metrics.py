# orchestrator/forensics/metrics.py
#
# Recovery metrics derived from forensics_report.json. Two consumers share this
# logic so the numbers never drift:
#   - the orchestrator, which writes a per-run metrics.csv beside each
#     forensics_report.json and refreshes the combined no-cleanup vs cleanup view;
#   - scripts/report_metrics.py, the on-demand CLI.
#
# Table 1  one row per run: detection rate (DR) + quality-of-recovery (QoR).
# Table 2  one row per (step, tool): found/total + the matched_by evidence.
#
# No false-positive metric: every count is "found vs declared", never an FP rate.

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterator

# Tool display order; "unknown" covers artifacts whose type the evaluator could
# not route. QoR bands: Low <50, Medium 50-74, High >=75.
_TOOL_ORDER = {"sleuth": 0, "vol3": 1, "plaso": 2, "unknown": 3}
_QOR_HIGH = 75.0
_QOR_MEDIUM = 50.0

TABLE1_COLS = ["Scenario", "Cleanup", "Distro", "Found/Tot", "DR%", "QoR", "Active tools"]
# Table 2 is per-experiment; the combined A/B view prepends a Run column so the
# two runs' rows never collide.
TABLE2_COLS = ["Step", "Phase", "Tool", "Found", "Total", "Key artifacts"]
TABLE2_COLS_RUN = ["Run", *TABLE2_COLS]


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


def run_label(report: dict[str, Any]) -> str:
    return "cleanup" if has_cleanup(report) else "no-cleanup"


def qor_label(found: int, total: int) -> str:
    if total == 0:
        return "n/a"
    pct = found / total * 100
    if pct >= _QOR_HIGH:
        return "High"
    if pct >= _QOR_MEDIUM:
        return "Medium"
    return "Low"


def table1_row(report: dict[str, Any]) -> dict[str, Any]:
    arts = [a for _, _, a in iter_artifacts(report)]
    total = len(arts)
    found = sum(1 for a in arts if a.get("found"))
    # QoR looks only at attack-phase primaries (phase defaults to "attack" for
    # pre-phase reports): completeness of the core attack evidence.
    primaries = [
        a for a in arts if a.get("primary") and a.get("phase", "attack") == "attack"
    ]
    p_total = len(primaries)
    p_found = sum(1 for a in primaries if a.get("found"))
    return {
        "Scenario": report.get("scenario_id", "unknown"),
        "Cleanup": "Yes" if has_cleanup(report) else "No",
        "Distro": distro_of(report),
        "Found/Tot": f"{found}/{total}",
        "DR%": round(found / total * 100, 1) if total else 0.0,
        "QoR": qor_label(p_found, p_total),
        "Active tools": ", ".join(active_tools(report)) or "-",
        "_qor_detail": f"{p_found}/{p_total}",  # text summaries only
    }


def table2_rows(
    report: dict[str, Any], *, include_run: bool = False
) -> list[dict[str, Any]]:
    label = run_label(report)
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for step_name, _, art in iter_artifacts(report):
        key = (step_name, art.get("tool") or "unknown")
        if key not in groups:
            groups[key] = {"phases": set(), "arts": []}
            order.append(key)
        groups[key]["arts"].append(art)
        groups[key]["phases"].add(art.get("phase", "attack"))

    rows: list[dict[str, Any]] = []
    for step_name, tool in order:
        g = groups[(step_name, tool)]
        found = [a for a in g["arts"] if a.get("found")]
        keys = sorted({a.get("matched_by") for a in found if a.get("matched_by")})
        row = {
            "Step": step_name,
            "Phase": "/".join(sorted(p for p in g["phases"] if p)) or "attack",
            "Tool": tool,
            "Found": len(found),
            "Total": len(g["arts"]),
            "Key artifacts": "; ".join(keys),
        }
        if include_run:
            row = {"Run": label, **row}
        rows.append(row)
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
    # Per-experiment: this run's summary row + its step x tool breakdown (no Run
    # column -- the file already belongs to one run).
    _write_sections(
        out_path,
        [
            ("Table 1: run summary", TABLE1_COLS, [table1_row(report)]),
            ("Table 2: per step x tool", TABLE2_COLS, table2_rows(report)),
        ],
    )
    return out_path


def write_combined_metrics(reports: list[dict[str, Any]], out_path: Path) -> Path:
    # Cross-run A/B: one Table-1 row per run + a Run-tagged Table 2.
    t1 = [table1_row(r) for r in reports]
    t2 = [row for r in reports for row in table2_rows(r, include_run=True)]
    _write_sections(
        out_path,
        [
            ("Table 1: per-run summary", TABLE1_COLS, t1),
            ("Table 2: per step x tool", TABLE2_COLS_RUN, t2),
        ],
    )
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
