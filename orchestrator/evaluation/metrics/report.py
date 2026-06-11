# orchestrator/evaluation/metrics/report.py
#
# Per-scenario Markdown report (Phase 5), generated next to metrics.csv. Shows
# metric values with raw counts, the TP/FP/FN listings with raw_ref pointers
# back to tool output, a recall breakdown by rule_layer, and the derived
# composite f1 * order_pairwise (labelled explicitly as derived).

from __future__ import annotations

from pathlib import Path
from typing import Any

from orchestrator.evaluation.contracts.models import Finding, GtManifest, Matches
from orchestrator.evaluation.metrics.compute import MetricRow, compute_row


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.3f}"


def _recall_by_layer(
    manifest: GtManifest,
    findings: list[Finding],
    config: dict[str, Any] | None,
    config_path: str | Path | None,
) -> tuple[float | None, float | None]:
    # Re-match with community-only findings vs all findings; report recall for
    # each so the contribution of custom gap-filler rules is explicit.
    from orchestrator.evaluation.match.matcher import match

    n = len(manifest.events) or 1
    community = [f for f in findings if f.rule_layer == "community"]
    m_comm = match(manifest, community, config=config, config_path=config_path)
    m_all = match(manifest, findings, config=config, config_path=config_path)
    return (len(m_comm.tp) / n, len(m_all.tp) / n)


def render_report(
    manifest: GtManifest,
    matches: Matches,
    findings: list[Finding],
    *,
    row: MetricRow | None = None,
    config: dict[str, Any] | None = None,
    config_path: str | Path | None = None,
) -> str:
    if row is None:
        row = compute_row(manifest, matches)
    v = row.values
    by_id = {f.finding_id: f for f in findings}

    comm_recall, all_recall = _recall_by_layer(
        manifest, findings, config, config_path
    )

    order = v.get("order_pairwise")
    f1 = v.get("f1")
    derived = None if (order is None or f1 is None) else f1 * order
    mae = v["time_mae_s"]
    mae_str = "n/a" if mae is None else f"{mae:.3f}"

    lines: list[str] = []
    lines.append(f"# Scenario report: {v['scenario']} ({v['run_id']})")
    lines.append("")
    lines.append(f"- distro: `{v['distro']}`  cleanup: `{v['cleanup']}`")
    lines.append(f"- ruleset_hash: `{v['ruleset_hash']}`")
    lines.append(f"- contributing tools: `{v['tools'] or '-'}`")
    lines.append("")
    lines.append("## Metrics")
    lines.append("")
    lines.append("| metric | value | raw |")
    lines.append("| --- | --- | --- |")
    lines.append(f"| recall | {_pct(v['recall'])} | {v['tp']}/{v['gt_n']} |")
    lines.append(
        f"| precision | {_pct(v['precision'])} | {v['tp']}/{v['tp'] + v['fp']} |"
    )
    lines.append(f"| f1 | {_pct(f1)} | - |")
    lines.append(f"| order_pairwise | {_pct(order)} | - |")
    lines.append(f"| kendall_tau | {_pct(v['kendall_tau'])} | - |")
    lines.append(f"| time_mae_s | {mae_str} | - |")
    lines.append(
        f"| f1 * order_pairwise (DERIVED) | {_pct(derived)} | "
        f"f1={_pct(f1)} x order={_pct(order)} |"
    )
    lines.append("")
    lines.append("## Recall by rule layer")
    lines.append("")
    lines.append(f"- community only: {_pct(comm_recall)}")
    lines.append(f"- community + custom: {_pct(all_recall)}")
    lines.append("")
    lines.append("## Unique tool contribution (TP events found by exactly one tool)")
    lines.append("")
    lines.append(f"- tsk: {v['uniq_tsk']}")
    lines.append(f"- plaso: {v['uniq_plaso']}")
    lines.append(f"- vol3: {v['uniq_vol3']}")
    lines.append("")
    lines.append("## True positives")
    lines.append("")
    lines.append("| gt_id | tools | delta_t_s | primary raw_ref |")
    lines.append("| --- | --- | --- | --- |")
    for tprow in matches.tp:
        prim = by_id.get(tprow["primary_finding"])
        raw = prim.raw_ref if prim else "-"
        dt = tprow.get("delta_t_s")
        lines.append(
            f"| {tprow['gt_id']} | {'|'.join(tprow.get('tools', []))} | "
            f"{'n/a' if dt is None else f'{dt:.3f}'} | `{raw}` |"
        )
    lines.append("")
    lines.append("## False positives")
    lines.append("")
    lines.append("| cluster_id | representative raw_ref |")
    lines.append("| --- | --- |")
    for fprow in matches.fp:
        rep = by_id.get(fprow["representative"])
        raw = rep.raw_ref if rep else "-"
        lines.append(f"| {fprow['cluster_id']} | `{raw}` |")
    lines.append("")
    lines.append("## False negatives")
    lines.append("")
    if matches.fn:
        for gt_id in matches.fn:
            lines.append(f"- {gt_id}")
    else:
        lines.append("- (none)")
    lines.append("")
    if matches.background_noise:
        lines.append("## Background noise (out of scope window, excluded from precision)")
        lines.append("")
        for row_bg in matches.background_noise:
            lines.append(f"- {row_bg['cluster_id']} ({row_bg['representative']})")
        lines.append("")
    return "\n".join(lines)


def write_report(text: str, out_path: str | Path) -> Path:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text + "\n" if not text.endswith("\n") else text, encoding="utf-8")
    return p
