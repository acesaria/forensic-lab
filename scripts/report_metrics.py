#!/usr/bin/env python3
"""Recovery metrics for two forensics_report.json files (no-cleanup vs cleanup).

Reads the per-run reports written by orchestrator/forensics/evaluator.py and
emits two tables:

  Table 1  one row per run: overall detection rate + quality-of-recovery (QoR).
  Table 2  one row per (step, tool): found/total + the matched_by evidence.

No false-positive metric: every count is "found vs declared", never an FP rate.

Usage:
    python report_metrics.py NO_CLEANUP.json CLEANUP.json [-o metrics.csv]
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Iterator

# Tool display order; "unknown" covers artifacts whose type the evaluator could
# not route. QoR bands per the thesis spec: Low <50, Medium 50-74, High >=75.
_TOOL_ORDER = {"sleuth": 0, "vol3": 1, "plaso": 2, "unknown": 3}
_QOR_HIGH = 75.0
_QOR_MEDIUM = 50.0

TABLE1_COLS = ["Scenario", "Cleanup", "Distro", "Found/Tot", "DR%", "QoR", "Active tools"]
TABLE2_COLS = ["Run", "Step", "Phase", "Tool", "Found", "Total", "Key artifacts"]


def load_report(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def iter_artifacts(
    report: dict[str, Any],
) -> Iterator[tuple[str, dict[str, Any], dict[str, Any]]]:
    # Yield (step_name, step, artifact) for every declared artifact. Steps that
    # were skipped or have no specs contribute zero artifacts and drop out.
    for step_name, step in report.get("steps", {}).items():
        for art in step.get("artifacts", []):
            yield step_name, step, art


def has_cleanup(report: dict[str, Any]) -> bool:
    # Derive cleanup status from content, not argument order: any cleanup-phase
    # artifact, or (for older reports without a phase field) a "cleanup" step.
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
    # pre-phase reports); it measures completeness of the core attack evidence.
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
        "_qor_detail": f"{p_found}/{p_total}",  # text summary only
    }


def table2_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    label = "cleanup" if has_cleanup(report) else "no-cleanup"
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
        rows.append(
            {
                "Run": label,
                "Step": step_name,
                "Phase": "/".join(sorted(p for p in g["phases"] if p)) or "attack",
                "Tool": tool,
                "Found": len(found),
                "Total": len(g["arts"]),
                "Key artifacts": "; ".join(keys),
            }
        )
    return rows


def write_csv(out: Path, t1: list[dict[str, Any]], t2: list[dict[str, Any]]) -> None:
    # One file, two sections (Table 2 carries a Run column so rows never collide).
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["# Table 1: per-run summary"])
        w.writerow(TABLE1_COLS)
        for r in t1:
            w.writerow([r[c] for c in TABLE1_COLS])
        w.writerow([])
        w.writerow(["# Table 2: per step x tool"])
        w.writerow(TABLE2_COLS)
        for r in t2:
            w.writerow([r[c] for c in TABLE2_COLS])


def _print_table(headers: list[str], rows: list[list[Any]]) -> None:
    cells = [headers] + rows
    widths = [max(len(str(r[i])) for r in cells) for i in range(len(headers))]

    def fmt(row: list[Any]) -> str:
        return "  ".join(str(row[i]).ljust(widths[i]) for i in range(len(headers)))

    print(fmt(headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt(row))


def discover_latest(experiments_dir: Path) -> tuple[str, str]:
    # Pick the most recent no-cleanup and cleanup forensics_report.json under the
    # lab's experiments tree. run_id ends in a timestamp, so lexical sort over the
    # run directory == chronological; last of each class wins. This is how the
    # script "connects" to shared/experiments without touching the pipeline.
    reports = sorted(experiments_dir.glob("*/analysis/forensics_report.json"))
    no_cleanup: Path | None = None
    cleanup: Path | None = None
    for path in reports:
        try:
            report = load_report(str(path))
        except (OSError, ValueError):
            continue
        if has_cleanup(report):
            cleanup = path
        else:
            no_cleanup = path
    if no_cleanup is None or cleanup is None:
        raise SystemExit(
            f"--latest needs at least one no-cleanup and one cleanup report under "
            f"{experiments_dir} (found no-cleanup={no_cleanup is not None}, "
            f"cleanup={cleanup is not None})"
        )
    print(f"no-cleanup: {no_cleanup}\ncleanup:    {cleanup}\n")
    return str(no_cleanup), str(cleanup)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Recovery metrics from two forensics_report.json files."
    )
    ap.add_argument(
        "no_cleanup", nargs="?", help="path to the no-cleanup forensics_report.json"
    )
    ap.add_argument(
        "cleanup", nargs="?", help="path to the cleanup forensics_report.json"
    )
    ap.add_argument("-o", "--out", default="report_metrics.csv", help="CSV output path")
    ap.add_argument(
        "--latest",
        action="store_true",
        help="auto-discover the latest no-cleanup + cleanup reports under --experiments-dir",
    )
    ap.add_argument(
        "--experiments-dir",
        default="shared/experiments",
        help="experiments root for --latest (default: shared/experiments)",
    )
    args = ap.parse_args()

    if args.latest:
        no_cleanup_path, cleanup_path = discover_latest(Path(args.experiments_dir))
    elif args.no_cleanup and args.cleanup:
        no_cleanup_path, cleanup_path = args.no_cleanup, args.cleanup
    else:
        ap.error("provide two report paths, or use --latest")

    reports = [load_report(no_cleanup_path), load_report(cleanup_path)]
    t1 = [table1_row(r) for r in reports]
    t2 = [row for r in reports for row in table2_rows(r)]

    out = Path(args.out)
    write_csv(out, t1, t2)

    print("Table 1: per-run summary")
    _print_table(TABLE1_COLS, [[r[c] for c in TABLE1_COLS] for r in t1])
    print()
    for r in t1:
        print(
            f"  {r['Scenario']} [{r['Cleanup']}]: DR {r['DR%']}%  "
            f"QoR {r['QoR']} ({r['_qor_detail']} attack primaries)  "
            f"tools: {r['Active tools']}"
        )
    print("\nTable 2: per step x tool")
    _print_table(TABLE2_COLS, [[r[c] for c in TABLE2_COLS] for r in t2])
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
