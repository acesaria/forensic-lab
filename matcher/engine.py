"""GT-aware matcher: outcomes and metrics per METHODOLOGY.md §5/§6/§10.

Reads artifact_expectations.jsonl, tool_findings.jsonl, detection_claims.jsonl
(plus execution_truth.jsonl for the RQ4 temporal block when available). Writes
outcomes.jsonl, metrics.json, report.md.

Matching is many-to-one (§10.1): each scored expectation independently
collects every claim that matches it; nothing is consumed, ranked, or scored.
Claims matching no expectation are residual claims counted per rule (§10.3) —
never false positives.
"""

from __future__ import annotations

import json
import posixpath
import statistics
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from orchestrator.canonical import (
    ArtifactExpectation,
    DetectionClaim,
    GroundTruthEvent,
    ToolFinding,
    load_jsonl,
)
from orchestrator.forensics.timeutil import parse_iso_utc

_METRICS_SCHEMA = "forensic-lab.matcher.metrics.v3"
_SOURCES = ("disk", "memory", "timeline")

# §5 is-a table, closed (§10.5): claim class -> extra expectation classes it
# can support (equality always supports). Only true subtype edges; no
# cross-domain aliases.
_SUPPORTS = {
    "shared_object": {"file", "library_mapping"},
    "service_unit_file": {"file"},
    "preload_configuration": {"file"},
    "deleted_file_candidate": {"file"},
    "library_mapping": {"shared_object", "file"},
}


# --- identity (§5, §10.4: exact and closed) -------------------------------


def _norm_path(value: Any) -> str:
    text = str(value or "").strip()
    for marker in (" (deleted-realloc)", " (deleted)"):
        text = text.replace(marker, "")
    return posixpath.normpath(text) if text.startswith("/") else text


def _path_identity(expected: str, actual: str) -> bool:
    """Normalized-exact equality; anchored suffix only for a relative
    expectation path. Basename equality never establishes identity (§10.4)."""
    e, a = _norm_path(expected), _norm_path(actual)
    if not e or not a:
        return False
    return a == e if e.startswith("/") else (a == "/" + e or a.endswith("/" + e))


def _subdicts(entity: dict[str, Any]) -> list[dict[str, Any]]:
    nested = (entity.get(k) for k in ("process", "library", "socket", "file", "source"))
    return [entity, *(d for d in nested if isinstance(d, dict))]


def _entity_paths(entity: dict[str, Any]) -> list[str]:
    out = []
    for d in _subdicts(entity):
        if d.get("path"):
            out.append(str(d["path"]))
        if str(d.get("type") or "") == "path" and d.get("value"):
            out.append(str(d["value"]))
    return out


def _entity_process_strings(entity: dict[str, Any]) -> list[str]:
    # §5: process identity looks only at process name, path, or argv.
    out = []
    for d in _subdicts(entity):
        if str(d.get("type") or "") in ("process", "command"):
            out += [str(d[k]) for k in ("value", "path") if d.get(k)]
            if isinstance(d.get("argv"), list):
                out.append(" ".join(str(x) for x in d["argv"] if x))
    return out


def _entity_endpoints(entity: dict[str, Any]) -> set[str]:
    out = set()
    for d in _subdicts(entity):
        if str(d.get("type") or "") != "socket":
            continue
        if d.get("value"):
            out.add(str(d["value"]).strip())
        for side in ("local", "remote"):
            ep = d.get(side)
            if isinstance(ep, dict) and ep.get("address") not in (None, "") and ep.get("port") not in (None, ""):
                out.add(f"{ep['address']}:{ep['port']}")
    return out


def _identity_spec(exp: ArtifactExpectation) -> dict[str, Any]:
    """The identity fields (§3) this expectation pins its object with."""
    c = exp.instance_constraints or {}
    spec: dict[str, Any] = {}
    if c.get("path"):
        spec["path"] = str(c["path"])
    if c.get("sha256"):
        spec["sha256"] = str(c["sha256"]).lower()
    if c.get("pid") not in (None, ""):
        spec["pid"] = str(c["pid"])
    endpoint = c.get("socket") or (
        c.get("listen_host") and c.get("listen_port")
        and f"{c['listen_host']}:{c['listen_port']}"
    )
    if endpoint:
        spec["socket"] = str(endpoint).strip()
    fragments = [str(c[k]) for k in ("process", "argv_contains") if c.get(k)]
    if fragments:
        spec["process"] = fragments
    return spec


def _identity_match(spec: dict[str, Any], entity: dict[str, Any]) -> list[str]:
    """Matched identity field names; empty list = no identity match."""
    hits = []
    if "path" in spec and any(_path_identity(spec["path"], p) for p in _entity_paths(entity)):
        hits.append("path")
    if "sha256" in spec and spec["sha256"] in {
        str(d["sha256"]).lower() for d in _subdicts(entity) if d.get("sha256")
    }:
        hits.append("sha256")
    if "pid" in spec and spec["pid"] in {
        str(d["pid"]) for d in _subdicts(entity) if d.get("pid") not in (None, "")
    }:
        hits.append("pid")
    if "socket" in spec and spec["socket"] in _entity_endpoints(entity):
        hits.append("socket")
    if "process" in spec:
        hay = _entity_process_strings(entity)
        # An absolute expected process pins the program; its name is the §5
        # "name" fragment (comm fields carry no directory).
        needles = [posixpath.basename(n) if n.startswith("/") else n for n in spec["process"]]
        if any(n and any(n in h for h in hay) for n in needles):
            hits.append("process")
    return hits


# --- core ------------------------------------------------------------------


def run_matcher_files(
    *,
    expectations_path: str | Path,
    tool_findings_path: str | Path,
    detection_claims_path: str | Path,
    execution_truth_path: str | Path | None = None,
    out_dir: str | Path,
) -> dict[str, Any]:
    truth: list[GroundTruthEvent] = []
    if execution_truth_path and Path(execution_truth_path).is_file():
        truth = load_jsonl(execution_truth_path, GroundTruthEvent)
    return run_matcher(
        load_jsonl(expectations_path, ArtifactExpectation),
        load_jsonl(tool_findings_path, ToolFinding),
        load_jsonl(detection_claims_path, DetectionClaim),
        truth,
        out_dir=out_dir,
    )


def run_matcher(
    expectations: list[ArtifactExpectation],
    findings: list[ToolFinding],
    claims: list[DetectionClaim],
    truth_events: Iterable[GroundTruthEvent] = (),
    *,
    out_dir: str | Path,
) -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    findings_by_id = {f.finding_id: f for f in findings}
    claim_sources = {
        c.claim_id: sorted({
            findings_by_id[fid].source_type.value
            for fid in c.source_findings
            if fid in findings_by_id
        })
        for c in claims
    }
    truth = list(truth_events)

    scored = [e for e in expectations if e.required_for_scoring]  # §10.2
    rows = [
        _match_one(e, findings, claims, findings_by_id, claim_sources, truth)
        for e in scored
    ] + [
        # Contextual: listed for context, never scored (§10.2).
        {"ae_id": e.ae_id, "artifact_class": e.artifact_class, "scored": False,
         "outcome": "contextual"}
        for e in expectations
        if not e.required_for_scoring
    ]

    run_id = next((c.run_id for c in claims), next((f.run_id for f in findings), ""))
    metrics = _metrics(rows, findings, claims, run_id)
    paths = {
        "outcomes_path": out / "outcomes.jsonl",
        "metrics_path": out / "metrics.json",
        "report_path": out / "report.md",
    }
    paths["outcomes_path"].write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8"
    )
    paths["metrics_path"].write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    paths["report_path"].write_text(render_report(metrics, rows), encoding="utf-8")
    return {**paths, "metrics": metrics, "outcomes": rows}


def _match_one(
    exp: ArtifactExpectation,
    findings: list[ToolFinding],
    claims: list[DetectionClaim],
    findings_by_id: dict[str, ToolFinding],
    claim_sources: dict[str, list[str]],
    truth: list[GroundTruthEvent],
) -> dict[str, Any]:
    spec = _identity_spec(exp)
    eligible = {s.value for s in exp.source_eligibility}
    exp_attck = set(exp.attck)

    # Funnel level 1 (§10.7): identity search over raw findings, rule-independent.
    observing = {f.finding_id: f for f in findings if _identity_match(spec, f.entity)}

    identified, supported, claimed = [], [], []
    identity_fields: set[str] = set()
    for claim in claims:
        fields = _identity_match(spec, claim.entity)
        if fields:
            identified.append(claim)
            identity_fields.update(fields)
        # §5 supported is "else" w.r.t. identified only: is-a class + eligible
        # source + non-empty ATT&CK overlap on both sides (§10.5).
        elif (
            _class_supports(exp.artifact_class, claim.artifact_class)
            and eligible & set(claim_sources.get(claim.claim_id, []))
            and exp_attck & set(claim.attck)
        ):
            supported.append(claim)
        # Funnel level 2: a rule shortlisted a finding that observed the object.
        # Identity on the claim itself also counts, keeping the funnel monotone.
        if fields or observing.keys() & set(claim.source_findings):
            claimed.append(claim)

    outcome = "identified" if identified else "supported" if supported else "missed"
    # The funnel names where the *specific object* was lost, so it is reported
    # for supported (class-level consolation) outcomes too (§3).
    gap = None if identified else (
        "acquisition_gap" if not observing
        else "detection_gap" if not claimed
        else "specificity_gap"
    )
    matched = identified + supported  # many-to-one: all claims kept (§10.1)
    src_of = lambda cs: sorted({s for c in cs for s in claim_sources.get(c.claim_id, [])})  # noqa: E731
    offset_s, time_kind, gt_time = _temporal(spec, identified, findings_by_id, truth)
    return {
        "ae_id": exp.ae_id,
        "artifact_class": exp.artifact_class,
        "scored": True,
        "outcome": outcome,
        "observed": bool(observing),
        "observed_by": sorted({f.source_type.value for f in observing.values()}),
        "claimed_by_rules": sorted({c.rule_id for c in claimed}),
        "claimed_sources": src_of(claimed),
        "identity_fields": sorted(identity_fields),
        "matched_claims": sorted(c.claim_id for c in matched),
        "sources": src_of(matched),
        "identified_sources": src_of(identified),
        "funnel_gap": gap,
        "gt_time": gt_time,
        "time_offset_s": offset_s,
        "time_kind": time_kind,
    }


def _class_supports(expected: str, actual: str) -> bool:
    return expected == actual or expected in _SUPPORTS.get(actual, ())


def _truth_entity(ev: GroundTruthEvent) -> dict[str, Any]:
    """Project a GT event's object onto the entity shape _identity_match reads."""
    ident = str(ev.object_identity).strip()
    if ev.object_type == "process_socket":  # "<pid>:<host>:<port>"
        pid, _, endpoint = ident.partition(":")
        return {"pid": pid, "type": "socket", "value": endpoint}
    if ev.object_type == "process":  # identity is the pid
        return {"pid": ident}
    return {"type": "path", "value": ident}


def _temporal(spec, identified, findings_by_id, truth):
    """RQ4 (§6.D): best evidence placement (min |offset|) for an identified
    expectation with a GT action time. The GT time comes only from a truth
    event whose object matches the expectation's identity fields — earliest
    such event (ISO sorts). Timestamps never affect outcomes (§10.4)."""
    times = [ev.time for ev in truth if _identity_match(spec, _truth_entity(ev))]
    gt_time = min(times) if times else None
    if not identified or not gt_time:
        return None, None, gt_time
    try:
        gt_epoch = parse_iso_utc(gt_time)
    except ValueError:
        return None, None, gt_time
    best = None  # (|offset|, offset, kind)
    for claim in identified:
        for fid in claim.source_findings:
            f = findings_by_id.get(fid)
            if f is None or not f.time or f.time == "unknown":
                continue
            try:
                offset = parse_iso_utc(str(f.time)) - gt_epoch
            except ValueError:
                continue
            kind = f.entity.get("time_kind") or f.provenance.get("timestamp_desc")
            if best is None or abs(offset) < best[0]:
                best = (abs(offset), offset, str(kind) if kind else None)
    return (None, None, gt_time) if best is None else (round(best[1], 3), best[2], gt_time)


# --- metrics (§6: four blocks, nothing else) --------------------------------


def _ratio(count: int, total: int) -> float | None:
    return round(count / total, 4) if total else None


def _metrics(
    rows: list[dict[str, Any]],
    findings: list[ToolFinding],
    claims: list[DetectionClaim],
    run_id: str,
) -> dict[str, Any]:
    scored = [r for r in rows if r["scored"]]
    n = len(scored)
    identified = [r for r in scored if r["outcome"] == "identified"]
    gaps = Counter(r["funnel_gap"] for r in scored if r["funnel_gap"])

    per_source = {
        s: {
            "observed": sum(1 for r in scored if s in r["observed_by"]),
            "claimed": sum(1 for r in scored if s in r["claimed_sources"]),
            "identified": sum(1 for r in scored if s in r["identified_sources"]),
            "unique_contribution": sum(1 for r in identified if r["identified_sources"] == [s]),
            "coverage_identified_alone": _ratio(
                sum(1 for r in scored if s in r["identified_sources"]), n
            ),
        }
        for s in _SOURCES
    }
    coverage_identified = _ratio(len(identified), n)
    best_single = max(
        (p["coverage_identified_alone"] or 0.0 for p in per_source.values()), default=0.0
    )

    # Residual claims (§3): claims matching no scored expectation.
    matched_ids = {cid for r in scored for cid in r["matched_claims"]}
    residual = [c for c in claims if c.claim_id not in matched_ids]
    downgraded = sum(
        1 for c in claims
        if isinstance(c.entity.get("baseline"), dict)
        and c.entity["baseline"].get("downgraded") is True
    )
    offsets = [r["time_offset_s"] for r in identified if r["time_offset_s"] is not None]

    return {
        "schema": _METRICS_SCHEMA,
        "run_id": run_id,
        "expectations": {"scored": n, "contextual": len(rows) - n},
        "coverage": {
            "identified": len(identified),
            "supported": sum(1 for r in scored if r["outcome"] == "supported"),
            "missed": sum(1 for r in scored if r["outcome"] == "missed"),
            "coverage_identified": coverage_identified,
            "coverage_any": _ratio(
                sum(1 for r in scored if r["outcome"] != "missed"), n
            ),
            "funnel": {g: gaps.get(g, 0) for g in
                       ("acquisition_gap", "detection_gap", "specificity_gap")},
        },
        "sources": {
            "per_source": per_source,
            # §6.B: ≥2 sources must corroborate the identification itself, so
            # only identity-matching claims' sources count here.
            "corroboration_rate": _ratio(
                sum(1 for r in identified if len(r["identified_sources"]) >= 2),
                len(identified),
            ),
            "combination_gain": round((coverage_identified or 0.0) - best_single, 4)
            if n else None,
        },
        "triage": {
            "raw_findings": len(findings),
            "claims": len(claims),
            "reduction_ratio": _ratio(len(findings) - len(claims), len(findings)),
            "residual_claims": len(residual),
            "residual_claims_per_rule": dict(
                sorted(Counter(c.rule_id for c in residual).items())
            ),
            "baseline_downgraded_claims": downgraded,
        },
        "temporal": {
            "expectations_with_offset": len(offsets),
            "median_abs_offset_s": round(statistics.median(abs(o) for o in offsets), 3)
            if offsets else None,
            "max_abs_offset_s": round(max(abs(o) for o in offsets), 3)
            if offsets else None,
        },
    }


# --- report ------------------------------------------------------------------


def render_report(metrics: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    cov, src, tri, tmp = (metrics[k] for k in ("coverage", "sources", "triage", "temporal"))
    exp = metrics["expectations"]
    fmt = lambda v: "n/a" if v is None else str(v)  # noqa: E731
    lines = [
        "# Reconstruction Report",
        "",
        f"Run: {metrics['run_id']}  |  scored expectations: {exp['scored']}"
        f"  |  contextual: {exp['contextual']}",
        "",
        "## A. Coverage (RQ1)",
        "",
        f"- identified: {cov['identified']}  supported: {cov['supported']}  missed: {cov['missed']}",
        f"- coverage_identified: {fmt(cov['coverage_identified'])}  coverage_any: {fmt(cov['coverage_any'])}",
        f"- funnel gaps: acquisition {cov['funnel']['acquisition_gap']}, "
        f"detection {cov['funnel']['detection_gap']}, "
        f"specificity {cov['funnel']['specificity_gap']}",
        "",
        "## B. Sources (RQ2)",
        "",
        "| source | observed | claimed | identified | unique contribution |",
        "|---|---:|---:|---:|---:|",
        *(
            f"| {s} | {p['observed']} | {p['claimed']} | {p['identified']} "
            f"| {p['unique_contribution']} |"
            for s, p in src["per_source"].items()
        ),
        "",
        f"- corroboration_rate: {fmt(src['corroboration_rate'])}",
        f"- combination_gain: {fmt(src['combination_gain'])}",
        "",
        "## C. Triage (RQ3)",
        "",
        f"- raw findings: {tri['raw_findings']} -> claims: {tri['claims']} "
        f"(reduction {fmt(tri['reduction_ratio'])})",
        f"- residual claims: {tri['residual_claims']}",
        f"- baseline-downgraded claims: {tri['baseline_downgraded_claims']}",
        "",
        "| rule | residual claims |",
        "|---|---:|",
        *(f"| {rule} | {count} |" for rule, count in tri["residual_claims_per_rule"].items()),
        "",
        "## D. Temporal (RQ4, lite)",
        "",
        f"- expectations with offset: {tmp['expectations_with_offset']}",
        f"- median |offset|: {fmt(tmp['median_abs_offset_s'])} s  "
        f"max |offset|: {fmt(tmp['max_abs_offset_s'])} s",
        "",
        "## Per-expectation table",
        "",
        "| expectation | outcome | observed by | claimed by (rules) | sources | time offset (s) |",
        "|---|---|---|---|---|---|",
        *(
            f"| {r['ae_id']} | contextual | - | - | - | - |"
            if not r["scored"] else
            f"| {r['ae_id']} | {r['outcome']} "
            f"| {', '.join(r['observed_by']) or '-'} "
            f"| {', '.join(r['claimed_by_rules']) or '-'} "
            f"| {', '.join(r['sources']) or '-'} "
            f"| {fmt(r['time_offset_s'])} |"
            for r in rows
        ),
    ]
    return "\n".join(lines) + "\n"


def render_console_summary(metrics: dict[str, Any]) -> list[str]:
    if metrics.get("schema") != _METRICS_SCHEMA:
        raise ValueError(
            f"unsupported metrics schema {metrics.get('schema')!r}; "
            f"regenerate with the current matcher (expected {_METRICS_SCHEMA})"
        )
    cov, src, tri = metrics["coverage"], metrics["sources"], metrics["triage"]
    return [
        f"coverage: identified {cov['identified']}/{metrics['expectations']['scored']} "
        f"supported {cov['supported']} missed {cov['missed']} "
        f"(coverage_any {cov['coverage_any']})",
        f"sources: corroboration_rate {src['corroboration_rate']} "
        f"combination_gain {src['combination_gain']}",
        f"triage: {tri['raw_findings']} findings -> {tri['claims']} claims; "
        f"residual {tri['residual_claims']}",
    ]
