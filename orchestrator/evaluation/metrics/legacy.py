# orchestrator/evaluation/metrics/legacy.py
#
# Transition shim (Constraints: keep --legacy-csv). Re-derives the old
# Scenario,Cleanup,Distro,Found/Tot,DR%,QoR,Order,Active tools layout from the
# NEW pipeline so existing thesis tables keep rendering during the cutover.
# Nothing here re-introduces GT lookup: every value comes from a MetricRow.

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from orchestrator.evaluation.metrics.compute import MetricRow

LEGACY_COLS = (
    "Scenario",
    "Cleanup",
    "Distro",
    "Found/Tot",
    "DR%",
    "QoR",
    "Order",
    "Active tools",
)

_QOR_HIGH = 75.0
_QOR_MEDIUM = 50.0


def _qor_band(composite: float | None) -> str:
    # QoR is dropped as a primary metric; for the legacy view it is the derived
    # composite f1 * order_pairwise, banded as before.
    if composite is None:
        return "n/a"
    pct = composite * 100
    if pct >= _QOR_HIGH:
        return "High"
    if pct >= _QOR_MEDIUM:
        return "Medium"
    return "Low"


def _order_label(order_pairwise: float | None) -> str:
    if order_pairwise is None:
        return "n/a"
    return "OK" if order_pairwise >= 1.0 else "violated"


def legacy_row(row: MetricRow) -> dict[str, Any]:
    v = row.values
    f1 = v.get("f1")
    order = v.get("order_pairwise")
    composite = None if (f1 is None or order is None) else f1 * order
    recall = v.get("recall")
    return {
        "Scenario": v["scenario"],
        "Cleanup": "Yes" if v["cleanup"] else "No",
        "Distro": v["distro"],
        "Found/Tot": f"{v['tp']}/{v['gt_n']}",
        "DR%": round(recall * 100, 1) if recall is not None else 0.0,
        "QoR": _qor_band(composite),
        "Order": _order_label(order),
        "Active tools": v["tools"].replace("|", ", ") or "-",
    }


def write_legacy_csv(rows: list[MetricRow], out_path: str | Path) -> Path:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(LEGACY_COLS))
        writer.writeheader()
        for row in rows:
            writer.writerow(legacy_row(row))
    return p
