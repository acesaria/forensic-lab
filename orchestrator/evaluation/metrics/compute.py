# orchestrator/evaluation/metrics/compute.py
#
# Metric computation (Phase 5). Exact formulas over matches.json + the GT event
# count N. Null (not zero) is emitted for undefined ratios so the paper never
# reports a fabricated 0.

from __future__ import annotations

import math
from dataclasses import dataclass
from itertools import combinations
from typing import Any

from orchestrator.evaluation.contracts.models import GtManifest, Matches
from orchestrator.forensics.timeutil import parse_iso_utc

# Phase 2.4 column order. uniq_<tool> is reported for the three pinned tools.
METRICS_COLS: tuple[str, ...] = (
    "run_id",
    "scenario",
    "cleanup",
    "distro",
    "tools",
    "ruleset_hash",
    "gt_n",
    "tp",
    "fp",
    "fn",
    "recall",
    "precision",
    "f1",
    "order_pairwise",
    "kendall_tau",
    "time_mae_s",
    "uniq_tsk",
    "uniq_plaso",
    "uniq_vol3",
    "notes",
)

_ORDER_TIE_S = 1.0  # ties within 1 s count as correctly ordered


@dataclass
class MetricRow:
    values: dict[str, Any]

    def as_list(self) -> list[Any]:
        return [_fmt(self.values.get(c)) for c in METRICS_COLS]


def _fmt(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, float):
        # Stable, deterministic textual form.
        return f"{v:.6g}"
    return str(v)


def _wallclock_tp(matches: Matches) -> list[dict[str, Any]]:
    # TP rows whose primary finding carries a wall-clock time -- the subset that
    # participates in order_pairwise / kendall_tau / time_mae.
    out = []
    for row in matches.tp:
        if row.get("primary_ts_quality") == "wallclock" and row.get("primary_ts_utc"):
            out.append(row)
    return out


def order_pairwise(matches: Matches) -> float | None:
    rows = _wallclock_tp(matches)
    if len(rows) < 2:
        return None
    pts = [
        (parse_iso_utc(r["gt_ts_utc"]), parse_iso_utc(r["primary_ts_utc"]))
        for r in rows
    ]
    correct = 0
    total = 0
    for (g1, f1), (g2, f2) in combinations(pts, 2):
        total += 1
        gt_diff = g1 - g2
        rec_diff = f1 - f2
        if abs(rec_diff) <= _ORDER_TIE_S:
            correct += 1
        elif (gt_diff > 0) == (rec_diff > 0):
            correct += 1
    return correct / total if total else None


def kendall_tau(matches: Matches) -> float | None:
    rows = _wallclock_tp(matches)
    if len(rows) < 2:
        return None
    gt = [parse_iso_utc(r["gt_ts_utc"]) for r in rows]
    rec = [parse_iso_utc(r["primary_ts_utc"]) for r in rows]
    try:
        from scipy.stats import kendalltau

        tau, _ = kendalltau(gt, rec)
        return None if (tau is None or math.isnan(tau)) else float(tau)
    except ImportError:
        return _kendall_tau_b(gt, rec)


def _kendall_tau_b(x: list[float], y: list[float]) -> float | None:
    # Hand-rolled tau-b for when scipy is absent. Handles ties in either ranking.
    n = len(x)
    if n < 2:
        return None
    concordant = discordant = 0
    ties_x = ties_y = 0
    for i, j in combinations(range(n), 2):
        dx = x[i] - x[j]
        dy = y[i] - y[j]
        if dx == 0 and dy == 0:
            ties_x += 1
            ties_y += 1
            continue
        if dx == 0:
            ties_x += 1
            continue
        if dy == 0:
            ties_y += 1
            continue
        if (dx > 0) == (dy > 0):
            concordant += 1
        else:
            discordant += 1
    n0 = n * (n - 1) / 2
    denom = math.sqrt((n0 - ties_x) * (n0 - ties_y))
    if denom == 0:
        return None
    return (concordant - discordant) / denom


def time_mae_s(matches: Matches) -> float | None:
    deltas = [
        r["delta_t_s"]
        for r in _wallclock_tp(matches)
        if r.get("delta_t_s") is not None
    ]
    if not deltas:
        return None
    return sum(deltas) / len(deltas)


def unique_contribution(matches: Matches) -> dict[str, int]:
    # For each tool T: count TP GT events whose contributing-tool set is exactly
    # {T}. Reported for the three pinned tools.
    counts = {"tsk": 0, "plaso": 0, "vol3": 0}
    for row in matches.tp:
        tools = set(row.get("tools", []))
        if len(tools) == 1:
            (only,) = tuple(tools)
            if only in counts:
                counts[only] += 1
    return counts


def all_tools(matches: Matches) -> list[str]:
    tools: set[str] = set()
    for row in matches.tp:
        tools.update(row.get("tools", []))
    return sorted(tools)


def compute_row(
    manifest: GtManifest,
    matches: Matches,
    *,
    run_id: str | None = None,
    scenario: str | None = None,
    distro: str | None = None,
    cleanup: bool | None = None,
    notes: str = "",
) -> MetricRow:
    n = len(manifest.events)  # the only thing read from the manifest
    tp = len(matches.tp)
    fp = len(matches.fp)
    fn = len(matches.fn)

    recall = tp / n if n else None
    precision = tp / (tp + fp) if (tp + fp) else None
    if recall in (None, 0) or precision in (None, 0):
        f1: float | None = None
    else:
        f1 = 2 * precision * recall / (precision + recall)

    uniq = unique_contribution(matches)
    return MetricRow(
        {
            "run_id": run_id if run_id is not None else manifest.run_id,
            "scenario": scenario if scenario is not None else manifest.scenario_id,
            "cleanup": (manifest.cleanup if cleanup is None else cleanup),
            "distro": distro if distro is not None else manifest.distro,
            "tools": "|".join(all_tools(matches)),
            "ruleset_hash": matches.ruleset_hash,
            "gt_n": n,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "recall": recall,
            "precision": precision,
            "f1": f1,
            "order_pairwise": order_pairwise(matches),
            "kendall_tau": kendall_tau(matches),
            "time_mae_s": time_mae_s(matches),
            "uniq_tsk": uniq["tsk"],
            "uniq_plaso": uniq["plaso"],
            "uniq_vol3": uniq["vol3"],
            "notes": notes,
        }
    )


def write_metrics_csv(rows: list[MetricRow], out_path: Any, append: bool = False) -> Any:
    import csv
    from pathlib import Path

    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    write_header = not (append and p.exists())
    mode = "a" if append else "w"
    with p.open(mode, newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        if write_header:
            writer.writerow(METRICS_COLS)
        for row in rows:
            writer.writerow(row.as_list())
    return p
