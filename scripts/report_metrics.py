#!/usr/bin/env python3
"""On-demand recovery metrics for forensics_report.json files.

The metric logic lives in orchestrator.forensics.metrics, shared with the
orchestrator (which writes a per-run metrics.csv automatically after each run).
This CLI is the cross-run no-cleanup vs cleanup comparison.

Usage:
    python scripts/report_metrics.py NO_CLEANUP.json CLEANUP.json [-o out.csv]
    python scripts/report_metrics.py --latest [--experiments-dir shared/experiments]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

# Allow `python scripts/report_metrics.py` to import the orchestrator package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator.forensics.metrics import (  # noqa: E402  (after sys.path tweak)
    TABLE1_COLS,
    discover_latest,
    load_report,
    table1_row,
    write_combined_metrics,
)


def _print_table(headers: list[str], rows: list[list[Any]]) -> None:
    cells = [headers] + rows
    widths = [max(len(str(r[i])) for r in cells) for i in range(len(headers))]

    def fmt(row: list[Any]) -> str:
        return "  ".join(str(row[i]).ljust(widths[i]) for i in range(len(headers)))

    print(fmt(headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt(row))


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Cross-run recovery metrics from two forensics_report.json files."
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
        found = discover_latest(Path(args.experiments_dir))
        if found is None:
            ap.error(
                f"--latest needs a no-cleanup and a cleanup report under "
                f"{args.experiments_dir}"
            )
        no_cleanup_path, cleanup_path = found
        print(f"no-cleanup: {no_cleanup_path}\ncleanup:    {cleanup_path}\n")
    elif args.no_cleanup and args.cleanup:
        no_cleanup_path, cleanup_path = args.no_cleanup, args.cleanup
    else:
        ap.error("provide two report paths, or use --latest")

    reports = [load_report(no_cleanup_path), load_report(cleanup_path)]
    out = write_combined_metrics(reports, Path(args.out))

    t1 = [table1_row(r) for r in reports]
    print("Table 1: per-run summary")
    _print_table(TABLE1_COLS, [[r[c] for c in TABLE1_COLS] for r in t1])
    print()
    for r in t1:
        print(
            f"  {r['Scenario']} [{r['Cleanup']}]: DR {r['DR%']}%  "
            f"QoR {r['QoR']} [{r['_qor_detail']} attack primaries]  "
            f"Order {r['Order']}  "
            f"tools: {r['Active tools']}"
        )
    # Per-artifact Table 2 is per-run detail (see each run's analysis/metrics.csv);
    # the cross-run comparison is the Table 1 summary only.
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
