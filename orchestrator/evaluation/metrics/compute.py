# orchestrator/evaluation/metrics/compute.py
#
# Metric computation (Phase 5). Exact formulas over matches.json + the GT event
# count N. Null (not zero) is emitted for undefined ratios so the paper never
# reports a fabricated 0.

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations
from typing import Any

from orchestrator.evaluation.contracts.models import Finding, GtManifest, Matches
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


def _timeline_tp(matches: Matches) -> list[dict[str, Any]]:
    # TP rows that participate in order_pairwise / time_mae: the
    # primary must carry a wall-clock time AND be a timeline-operation finding.
    # memory_analysis primaries (and anything ts_quality != wallclock) carry no
    # reliable order and are excluded. primary_operation defaults to "timeline"
    # for matches.json written before this field existed.
    out = []
    for row in matches.tp:
        if row.get("primary_ts_quality") != "wallclock" or not row.get("primary_ts_utc"):
            continue
        if row.get("primary_operation", "timeline") != "timeline":
            continue
        out.append(row)
    return out


def order_pairwise(matches: Matches) -> float | None:
    rows = _timeline_tp(matches)
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


def time_mae_s(matches: Matches) -> float | None:
    deltas = [
        r["delta_t_s"]
        for r in _timeline_tp(matches)
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

    # Standard global (micro-averaged) precision/recall/F1 over matched GT events:
    #   recall    = matched events / all GT events
    #   precision = matched events / (matched events + in-scope FP clusters)
    # Corroboration is no longer a precision denominator; it is reported per TP as
    # n_supporting_clusters and sliced in the per-operation breakdown.
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


# Per-(forensic_operation, source_tool, rule_layer) breakdown plus a global micro
# row. Standard precision/recall/F1 per slice, sliced from the same matches the
# global row uses, so the two views never disagree.
BREAKDOWN_COLS: tuple[str, ...] = (
    "forensic_operation",
    "source_tool",
    "rule_layer",
    "tp",
    "fp",
    "fn",
    "precision",
    "recall",
    "f1",
)


@dataclass
class BreakdownRow:
    values: dict[str, Any]

    def as_list(self) -> list[Any]:
        return [_fmt(self.values.get(c)) for c in BREAKDOWN_COLS]


def _f1(precision: float | None, recall: float | None) -> float | None:
    if not precision or not recall:
        return None
    return 2 * precision * recall / (precision + recall)


def compute_breakdown(
    manifest: GtManifest, matches: Matches, findings: list[Finding]
) -> list[BreakdownRow]:
    by_id = {f.finding_id: f for f in findings}

    # TP per slice: distinct GT events covered by a finding of (op, src, layer).
    tp_events: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    matched_pairs: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for row in matches.tp:
        gid = row["gt_id"]
        for fid in row.get("finding_ids", []):
            f = by_id.get(fid)
            if f is None:
                continue
            tp_events[(f.forensic_operation, f.source_tool, f.rule_layer)].add(gid)
            matched_pairs[gid].add((f.forensic_operation, f.source_tool))

    # FP per slice: in-scope false-positive clusters, by the representative's slice.
    fp_groups: dict[tuple[str, str, str], int] = defaultdict(int)
    for row in matches.fp:
        rep = by_id.get(row.get("representative"))
        if rep is None:
            ids = row.get("finding_ids", [])
            rep = by_id.get(ids[0]) if ids else None
        if rep is None:
            continue
        fp_groups[(rep.forensic_operation, rep.source_tool, rep.rule_layer)] += 1

    # FN per slice: GT observable expectations (operation, source_tool) with no
    # matched finding for the event. rule_layer is not a GT property, so FN is
    # attributed at (operation, source_tool) level on a layer-agnostic "*" row.
    # TODO: once GT observables routinely carry layer hints, fold FN into the
    # per-layer rows instead of the aggregate "*" row.
    # deleted_file recall is owned by the dedicated recovery breakdown (recovery
    # findings are excluded from the matcher), so it is not counted here.
    fn_pairs: dict[tuple[str, str], set[str]] = defaultdict(set)
    for ev in manifest.events:
        expected = {
            (o.operation, o.source_tool)
            for o in ev.observables
            if o.operation != "deleted_file"
        }
        for pair in expected - matched_pairs.get(ev.gt_id, set()):
            fn_pairs[pair].add(ev.gt_id)

    rows: list[BreakdownRow] = []
    groups = set(tp_events) | set(fp_groups)
    for op, src, layer in sorted(groups):
        tp = len(tp_events.get((op, src, layer), ()))
        fp = fp_groups.get((op, src, layer), 0)
        precision = tp / (tp + fp) if (tp + fp) else None
        recall = float(tp) / tp if tp else None  # fn is on the "*" rows
        rows.append(
            BreakdownRow(
                {
                    "forensic_operation": op,
                    "source_tool": src,
                    "rule_layer": layer,
                    "tp": tp,
                    "fp": fp,
                    "fn": 0,
                    "precision": precision,
                    "recall": recall,
                    "f1": _f1(precision, recall),
                }
            )
        )
    for (op, src), gids in sorted(fn_pairs.items()):
        fn = len(gids)
        rows.append(
            BreakdownRow(
                {
                    "forensic_operation": op,
                    "source_tool": src,
                    "rule_layer": "*",
                    "tp": 0,
                    "fp": 0,
                    "fn": fn,
                    "precision": None,
                    "recall": 0.0 if fn else None,
                    "f1": None,
                }
            )
        )

    # Global micro row, computed from the same matches as compute_row so the two
    # always agree (not a sum of slices, which would double-count corroborated
    # events appearing in several operations).
    mtp, mfp, mfn = len(matches.tp), len(matches.fp), len(matches.fn)
    micro_p = mtp / (mtp + mfp) if (mtp + mfp) else None
    micro_r = mtp / (mtp + mfn) if (mtp + mfn) else None
    rows.append(
        BreakdownRow(
            {
                "forensic_operation": "__micro__",
                "source_tool": "*",
                "rule_layer": "*",
                "tp": mtp,
                "fp": mfp,
                "fn": mfn,
                "precision": micro_p,
                "recall": micro_r,
                "f1": _f1(micro_p, micro_r),
            }
        )
    )
    return rows


def write_breakdown_csv(rows: list[BreakdownRow], out_path: Any) -> Any:
    import csv
    from pathlib import Path

    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(BREAKDOWN_COLS)
        for row in rows:
            writer.writerow(row.as_list())
    return p


# Per-level breakdown of the escalating deleted-file recovery, derived directly
# from each finding's recovery_outcome (recovery findings are excluded from the
# matcher). Each target resolves to ONE outcome at the level where it was found,
# or at the highest level attempted if it was never found. Outcome accounting,
# per NIST CFTT / SWGDE "declare tool limitations" guidance:
#   found          -> TP at the level that recovered it
#   not_found      -> FN at the highest level attempted (the gap is real)
#   tool_error     -> counted with the gap (FN), surfaced separately for triage
#   not_applicable -> EXCLUDED from recall, reported as scope="unsupported_fs"
# Level 3 (carving) rows are flagged high_fp_risk: their precision is structurally
# unreliable and must not be mixed with the other levels' numbers.
RECOVERY_COLS: tuple[str, ...] = (
    "recovery_level",
    "source_tool",
    "found",
    "not_found",
    "tool_error",
    "not_applicable",
    "recall",
    "high_fp_risk",
    "scope",
)


@dataclass
class RecoveryRow:
    values: dict[str, Any]

    def as_list(self) -> list[Any]:
        return [_fmt(self.values.get(c)) for c in RECOVERY_COLS]


def _resolve_recovery_target(attempts: list[Finding]) -> tuple[int, str, str]:
    # Reduce one target's per-level attempts to (level, tool, status). A "found"
    # at the lowest level wins; else not_applicable; else the highest attempted
    # level decides the gap (not_found or tool_error). not_applicable resolves to
    # level 0 so it forms its own scope="unsupported_fs" row, never mixed with the
    # tools' recall.
    ordered = sorted(attempts, key=lambda f: (f.recovery_level or 0))
    found = next((f for f in ordered if f.recovery_outcome == "found"), None)
    if found is not None:
        return int(found.recovery_level or 1), found.source_tool, "found"
    na = next((f for f in ordered if f.recovery_outcome == "not_applicable"), None)
    if na is not None:
        return 0, na.source_tool, "not_applicable"
    highest = ordered[-1]
    status = "tool_error" if highest.recovery_outcome == "tool_error" else "not_found"
    return int(highest.recovery_level or 0), highest.source_tool, status


def compute_recovery_breakdown(findings: list[Finding]) -> list[RecoveryRow]:
    recs = [
        f for f in findings
        if f.forensic_operation == "deleted_file" and f.recovery_outcome is not None
    ]
    if not recs:
        return []
    by_target: dict[str, list[Finding]] = defaultdict(list)
    for f in recs:
        by_target[str(f.entity.value)].append(f)

    counts: dict[tuple[int, str], dict[str, int]] = defaultdict(
        lambda: {"found": 0, "not_found": 0, "tool_error": 0, "not_applicable": 0}
    )
    for attempts in by_target.values():
        level, tool, status = _resolve_recovery_target(attempts)
        counts[(level, tool)][status] += 1

    rows: list[RecoveryRow] = []
    total = {"found": 0, "not_found": 0, "tool_error": 0, "not_applicable": 0}
    for level, tool in sorted(counts, key=lambda k: (k[0], k[1])):
        c = counts[(level, tool)]
        for k in total:
            total[k] += c[k]
        gaps = c["not_found"] + c["tool_error"]
        denom = c["found"] + gaps
        is_na = level == 0
        rows.append(RecoveryRow({
            "recovery_level": "n/a" if is_na else level,
            "source_tool": tool,
            "found": c["found"],
            "not_found": c["not_found"],
            "tool_error": c["tool_error"],
            "not_applicable": c["not_applicable"],
            "recall": None if (is_na or denom == 0) else c["found"] / denom,
            "high_fp_risk": True if level == 3 else None,
            "scope": "unsupported_fs" if is_na else "applicable",
        }))

    gaps = total["not_found"] + total["tool_error"]
    denom = total["found"] + gaps  # not_applicable excluded from recall
    rows.append(RecoveryRow({
        "recovery_level": "__total__",
        "source_tool": "*",
        "found": total["found"],
        "not_found": total["not_found"],
        "tool_error": total["tool_error"],
        "not_applicable": total["not_applicable"],
        "recall": None if denom == 0 else total["found"] / denom,
        "high_fp_risk": None,
        "scope": "applicable",
    }))
    return rows


def write_recovery_csv(rows: list[RecoveryRow], out_path: Any) -> Any:
    import csv
    from pathlib import Path

    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(RECOVERY_COLS)
        for row in rows:
            writer.writerow(row.as_list())
    return p
