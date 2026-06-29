"""GT-aware matcher for canonical artifacts.

Reads:
- artifact_expectations.jsonl
- tool_findings.jsonl
- detection_claims.jsonl

Writes:
- matches.jsonl
- metrics.json
- score_report.md

This is intentionally GT-aware and must stay downstream from GT-blind detectors.
"""

from __future__ import annotations

import hashlib
import json
import math
import posixpath
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from orchestrator.canonical import (
    ArtifactExpectation,
    DetectionClaim,
    EvidenceSource,
    MatchLevel,
    MatchResult,
    TemporalQuality,
    ToolFinding,
    load_jsonl,
    write_jsonl,
)
from orchestrator.forensics.timeutil import parse_iso_utc

_NONE = "__none__"
_TEMPORAL_VALUES = tuple(q.value for q in TemporalQuality)
_METRICS_SCHEMA_V2 = "forensic-lab.matcher.metrics.v2"


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    run_id: str
    artifact_class: str
    entity: dict[str, Any]
    source_types: set[EvidenceSource]
    source_ids: list[str]
    kind: str
    attck: set[str]
    time: str | None
    temporal_quality: TemporalQuality
    confidence: float


def run_matcher_files(
    *,
    expectations_path: str | Path,
    tool_findings_path: str | Path,
    detection_claims_path: str | Path | None,
    out_dir: str | Path,
    time_window_s: float = 120.0,
    allow_raw_finding_fallback: bool = False,
) -> dict[str, Any]:
    expectations = load_jsonl(expectations_path, ArtifactExpectation)
    tool_findings = load_jsonl(tool_findings_path, ToolFinding)
    if detection_claims_path:
        claims_path = Path(detection_claims_path)
        if not claims_path.is_file():
            raise FileNotFoundError(f"detection claims not found: {claims_path}")
        claims = load_jsonl(claims_path, DetectionClaim)
    elif allow_raw_finding_fallback:
        claims = []
    else:
        raise ValueError(
            "canonical claim-level scoring requires --detection-claims; "
            "use --debug-raw-findings only for debug raw ToolFinding fallback"
        )
    return run_matcher(
        expectations,
        tool_findings,
        claims,
        out_dir=out_dir,
        time_window_s=time_window_s,
        allow_raw_finding_fallback=allow_raw_finding_fallback,
    )


def run_matcher(
    expectations: list[ArtifactExpectation],
    tool_findings: list[ToolFinding],
    detection_claims: list[DetectionClaim],
    *,
    out_dir: str | Path,
    time_window_s: float = 120.0,
    allow_raw_finding_fallback: bool = False,
) -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    candidates = _build_candidates(
        tool_findings,
        detection_claims,
        allow_raw_finding_fallback=allow_raw_finding_fallback,
    )
    matches = _match(expectations, candidates, time_window_s=time_window_s)
    metrics = compute_metrics(expectations, candidates, matches, tool_findings)
    if allow_raw_finding_fallback and not detection_claims:
        metrics["candidate_input"] = "debug_raw_tool_findings"
        metrics["debug_only"] = True
    else:
        metrics["candidate_input"] = "detection_claims"
        metrics["debug_only"] = False
    write_jsonl(out / "matches.jsonl", matches)
    (out / "metrics.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "score_report.md").write_text(
        render_report(
            metrics,
            matches,
            tool_findings=tool_findings,
            detection_claims=detection_claims,
        ),
        encoding="utf-8",
    )
    return {
        "matches_path": out / "matches.jsonl",
        "metrics_path": out / "metrics.json",
        "report_path": out / "score_report.md",
        "metrics": metrics,
        "matches": matches,
    }


def _build_candidates(
    tool_findings: list[ToolFinding],
    claims: list[DetectionClaim],
    *,
    allow_raw_finding_fallback: bool = False,
) -> list[Candidate]:
    by_id = {finding.finding_id: finding for finding in tool_findings}
    if claims:
        return [_candidate_from_claim(claim, by_id) for claim in claims]
    if not allow_raw_finding_fallback:
        return []
    return [_candidate_from_finding(finding) for finding in tool_findings]


def _candidate_from_claim(claim: DetectionClaim, findings_by_id: dict[str, ToolFinding]) -> Candidate:
    linked = [findings_by_id[fid] for fid in claim.source_findings if fid in findings_by_id]
    sources = {finding.source_type for finding in linked} or {EvidenceSource.UNKNOWN}
    times = [finding.time for finding in linked if finding.time and finding.time != "unknown"]
    temporal = _best_temporal_quality([finding.temporal_quality for finding in linked])
    return Candidate(
        candidate_id=claim.claim_id,
        run_id=claim.run_id,
        artifact_class=claim.artifact_class,
        entity=dict(claim.entity),
        source_types=sources,
        source_ids=list(claim.source_findings),
        kind="claim",
        attck=set(claim.attck),
        time=sorted(times)[0] if times else None,
        temporal_quality=temporal,
        confidence=float(claim.confidence),
    )


def _candidate_from_finding(finding: ToolFinding) -> Candidate:
    return Candidate(
        candidate_id=finding.finding_id,
        run_id=finding.run_id,
        artifact_class=finding.artifact_class,
        entity=dict(finding.entity),
        source_types={finding.source_type},
        source_ids=[finding.finding_id],
        kind="tool_finding",
        attck=set(),
        time=finding.time if finding.time != "unknown" else None,
        temporal_quality=finding.temporal_quality,
        confidence=0.5,
    )


def _best_temporal_quality(values: Iterable[TemporalQuality]) -> TemporalQuality:
    order = {
        TemporalQuality.EXACT: 0,
        TemporalQuality.BOUNDED: 1,
        TemporalQuality.RELATIVE_ORDER: 2,
        TemporalQuality.NONE: 3,
    }
    items = list(values)
    if not items:
        return TemporalQuality.NONE
    return min(items, key=lambda v: order.get(v, 99))


def _match(
    expectations: list[ArtifactExpectation],
    candidates: list[Candidate],
    *,
    time_window_s: float,
) -> list[MatchResult]:
    scored: list[tuple[int, float, str, str, ArtifactExpectation, Candidate, list[str]]] = []
    for exp in expectations:
        for cand in candidates:
            level, score, fields = _score_pair(exp, cand, time_window_s=time_window_s)
            if level == MatchLevel.NONE:
                continue
            priority = 0 if level == MatchLevel.INSTANCE else 1
            scored.append((priority, -score, exp.ae_id, cand.candidate_id, exp, cand, fields))
    scored.sort(key=lambda row: row[:4])

    used_exp: set[str] = set()
    used_cand: set[str] = set()
    matches: list[MatchResult] = []
    for _priority, neg_score, _ae_id, _cid, exp, cand, fields in scored:
        if exp.ae_id in used_exp or cand.candidate_id in used_cand:
            continue
        level = MatchLevel.INSTANCE if _priority == 0 else MatchLevel.CLASS
        matches.append(
            _match_row(
                exp,
                cand.candidate_id,
                level,
                "tp",
                -neg_score,
                fields,
                f"{cand.kind} matched expectation",
                run_id=cand.run_id,
            )
        )
        used_exp.add(exp.ae_id)
        used_cand.add(cand.candidate_id)

    for exp in expectations:
        if exp.ae_id not in used_exp:
            matches.append(
                _match_row(
                    exp,
                    _NONE,
                    MatchLevel.NONE,
                    "fn",
                    0.0,
                    [],
                    "no matching claim or finding",
                )
            )
    for cand in candidates:
        if cand.candidate_id not in used_cand:
            matches.append(
                MatchResult(
                    match_id=_stable_match_id(_NONE, cand.candidate_id, "fp"),
                    run_id=cand.run_id,
                    target_id=_NONE,
                    finding_or_claim_id=cand.candidate_id,
                    match_level=MatchLevel.NONE,
                    relation="fp",
                    score=0.0,
                    fields_matched=[],
                    notes=f"unmatched {cand.kind}; artifact_class={cand.artifact_class}",
                )
            )
    return sorted(matches, key=lambda m: (m.relation, m.target_id, m.finding_or_claim_id))


def _match_row(
    exp: ArtifactExpectation,
    candidate_id: str,
    level: MatchLevel,
    relation: str,
    score: float,
    fields: list[str],
    notes: str,
    *,
    run_id: str | None = None,
) -> MatchResult:
    return MatchResult(
        match_id=_stable_match_id(exp.ae_id, candidate_id, relation),
        run_id=run_id or _run_id_from_expectation(exp),
        target_id=exp.ae_id,
        finding_or_claim_id=candidate_id,
        match_level=level,
        relation=relation,
        score=round(float(score), 4),
        fields_matched=fields,
        notes=notes,
    )


def _stable_match_id(target_id: str, candidate_id: str, relation: str) -> str:
    digest = hashlib.sha1(f"{target_id}|{candidate_id}|{relation}".encode("utf-8")).hexdigest()[:10]
    return f"m-{digest}"


def _run_id_from_expectation(exp: ArtifactExpectation) -> str:
    return str(exp.instance_constraints.get("run_id") or exp.scenario_id)


def _score_pair(
    exp: ArtifactExpectation,
    cand: Candidate,
    *,
    time_window_s: float,
) -> tuple[MatchLevel, float, list[str]]:
    if not _class_compatible(exp.artifact_class, cand.artifact_class):
        return MatchLevel.NONE, 0.0, []
    if not _source_compatible(exp, cand):
        return MatchLevel.NONE, 0.0, []

    fields = ["artifact_class", "source_type"]
    if _attck_compatible(exp, cand):
        fields.append("attck")
    elif exp.attck and cand.attck:
        return MatchLevel.NONE, 0.0, []

    instance_fields = _instance_fields(exp, cand, time_window_s=time_window_s)
    if instance_fields:
        fields.extend(instance_fields)
        return MatchLevel.INSTANCE, min(1.0, 0.82 + 0.03 * len(instance_fields)), fields

    if _class_context_compatible(exp, cand):
        return MatchLevel.CLASS, 0.55 + (0.05 if "attck" in fields else 0.0), fields
    return MatchLevel.NONE, 0.0, []


def _class_compatible(expected: str, actual: str) -> bool:
    if expected == actual:
        return True
    aliases = {
        "file": {"service_unit_file", "deleted_file_candidate", "shared_object", "preload_configuration"},
        "service_unit_file": {"file"},
        "shared_object": {"file", "library_mapping"},
        "preload_configuration": {"file", "shell_history_log_event"},
        "library_mapping": {"shared_object", "file"},
        "shell_history_log_event": {"process"},
        "process_socket_correlation": {"socket", "process"},
    }
    return actual in aliases.get(expected, set()) or expected in aliases.get(actual, set())


def _source_compatible(exp: ArtifactExpectation, cand: Candidate) -> bool:
    eligible = set(exp.source_eligibility)
    return EvidenceSource.UNKNOWN in eligible or bool(eligible & cand.source_types)


def _attck_compatible(exp: ArtifactExpectation, cand: Candidate) -> bool:
    return not exp.attck or not cand.attck or bool(set(exp.attck) & cand.attck)


def _class_context_compatible(exp: ArtifactExpectation, cand: Candidate) -> bool:
    if _attck_compatible(exp, cand):
        return True
    expected_step = exp.instance_constraints.get("step_id") or exp.step_id
    candidate_step = cand.entity.get("step_id")
    return bool(expected_step and candidate_step and str(expected_step) == str(candidate_step))


def _instance_fields(
    exp: ArtifactExpectation,
    cand: Candidate,
    *,
    time_window_s: float,
) -> list[str]:
    fields: list[str] = []
    constraints = exp.instance_constraints or {}
    exp_value = _expected_entity_value(exp)
    cand_value = str(cand.entity.get("value") or "")
    cand_type = str(cand.entity.get("type") or "")

    if exp_value:
        if cand_type == "path" or str(constraints.get("entity_type")) == "path" or "path" in constraints:
            if _path_match(exp_value, cand_value):
                fields.append("path")
        elif cand_type == "socket" or str(constraints.get("entity_type")) == "socket":
            if _socket_match(exp_value, cand):
                fields.append("socket")
        elif cand_type in ("process", "command") or str(constraints.get("entity_type")) == "process":
            if _process_match(exp_value, cand):
                fields.append("process")
        elif str(exp_value).strip() == cand_value.strip():
            fields.append("entity")

    expected_pid = constraints.get("pid")
    if expected_pid not in (None, "") and str(expected_pid) == str(cand.entity.get("pid")):
        fields.append("pid")

    expected_sha = constraints.get("sha256")
    if expected_sha and str(expected_sha).lower() == str(cand.entity.get("sha256", "")).lower():
        fields.append("sha256")

    if _time_match(constraints, cand, time_window_s=time_window_s):
        fields.append("time")

    return fields


def _expected_entity_value(exp: ArtifactExpectation) -> str:
    constraints = exp.instance_constraints or {}
    for key in ("entity_value", "path", "socket", "process", "command", "value"):
        value = constraints.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _path_match(expected: str, actual: str) -> bool:
    e = _normalize_path(expected)
    a = _normalize_path(actual)
    if not e or not a:
        return False
    return e == a or a.endswith(e) or e.endswith(a) or posixpath.basename(e) == posixpath.basename(a)


def _normalize_path(value: str) -> str:
    text = str(value).strip()
    if not text:
        return ""
    if " (deleted)" in text:
        text = text.replace(" (deleted)", "")
    if not text.startswith("/"):
        text = "/" + text
    return posixpath.normpath(text)


def _socket_match(expected: str, cand: Candidate) -> bool:
    actual = str(cand.entity.get("value") or "")
    if expected.strip() == actual.strip():
        return True
    remote = cand.entity.get("remote")
    if isinstance(remote, dict):
        joined = f"{remote.get('address')}:{remote.get('port')}"
        return expected.strip() == joined
    return False


def _process_match(expected: str, cand: Candidate) -> bool:
    actuals = [
        str(cand.entity.get("value") or ""),
        str(cand.entity.get("path") or ""),
        " ".join(str(x) for x in cand.entity.get("argv", []) if x),
    ]
    needle = posixpath.basename(expected.strip()) if expected.strip().startswith("/") else expected.strip()
    return any(needle and needle in value for value in actuals)


def _time_match(
    constraints: dict[str, Any],
    cand: Candidate,
    *,
    time_window_s: float,
) -> bool:
    expected_time = constraints.get("time") or constraints.get("ts_utc")
    if not expected_time or not cand.time:
        return False
    try:
        expected_epoch = parse_iso_utc(str(expected_time))
        actual_epoch = parse_iso_utc(str(cand.time))
    except ValueError:
        return False
    window = float(constraints.get("time_window_s") or time_window_s)
    return abs(expected_epoch - actual_epoch) <= window


def compute_metrics(
    expectations: list[ArtifactExpectation],
    candidates: list[Candidate],
    matches: list[MatchResult],
    tool_findings: list[ToolFinding],
) -> dict[str, Any]:
    tp = [m for m in matches if m.relation == "tp"]
    fp = [m for m in matches if m.relation == "fp"]
    fn = [m for m in matches if m.relation == "fn"]
    micro = _prf(len(tp), len(fp), len(fn))
    by_exp = {exp.ae_id: exp for exp in expectations}
    by_cand = {cand.candidate_id: cand for cand in candidates}
    critical = _critical_recall(expectations, matches)

    # The micro counts fold instance and class matches together. For thesis
    # reporting we separate two distinct questions: did we recover the exact
    # entity (instance) vs. did we recover the artifact class at all (class).
    instance_tp = sum(1 for m in tp if m.match_level == MatchLevel.INSTANCE)
    class_tp = sum(1 for m in tp if m.match_level == MatchLevel.CLASS)
    total_exp = len(expectations)
    # Instance-only treats a class-level hit as a miss: it is class coverage, not
    # instance reconstruction, so it is folded into the negative bucket.
    instance_only = _prf(instance_tp, len(fp), total_exp - instance_tp)
    # Backward-compatible diagnostic: this is not a final-claim precision. Its
    # denominator is still the candidate stream, with class-only support demoted
    # out of the numerator.
    final_reconstruction = _prf(instance_tp, len(fp) + class_tp, total_exp - instance_tp)
    reconstruction_summary = _reconstruction_summary(expectations, matches)
    source_coverage = _source_coverage(tool_findings, candidates, matches)
    corroboration = _multi_source_corroboration(candidates, matches)
    noise_reduction = _noise_reduction(
        raw_findings_count=len(tool_findings),
        candidate_claim_count=len(candidates),
        strong_instance_match_count=instance_tp,
    )
    baseline_comparison = _baseline_comparison_summary(candidates)
    methodology_warnings = [
        "candidate_diagnostics are detector/candidate-stream diagnostics, "
        "not final thesis reconstruction metrics",
        "final_reconstruction.precision is exposed as "
        "strict_candidate_stream_precision; unmatched candidate claims remain "
        "in its denominator",
        "pipeline_runtime_seconds is not emitted because the canonical full "
        "pipeline runtime is not explicitly measured in cached artifacts",
        "evidence_latency is not emitted because reliable GT action timestamps "
        "and artifact timestamps are not paired here",
        "noise_reduction is raw-to-candidate and raw-to-strong-count reduction "
        "only; it is not baseline-aware",
    ]
    if not baseline_comparison.get("available"):
        methodology_warnings.append(
            "baseline comparison is unavailable because no verified clean "
            "baseline tool_findings input was linked to the candidate stream"
        )

    metrics = {
        "schema": _METRICS_SCHEMA_V2,
        "counts": {"tp": len(tp), "fp": len(fp), "fn": len(fn)},
        "micro": micro,
        "candidate_diagnostics": {
            "description": (
                "detector/candidate-layer diagnostics only; "
                "not final thesis reconstruction metrics"
            ),
            **micro,
        },
        "final_reconstruction": {
            "description": (
                "candidate-stream diagnostic only; precision uses the candidate "
                "stream denominator and is not the thesis headline metric"
            ),
            "strong_instance_matches": instance_tp,
            "class_only_support": class_tp,
            "unmatched_candidates": len(fp),
            "missed_expected_after_strong_matching": total_exp - instance_tp,
            "precision_label": "strict_candidate_stream_precision",
            "precision_warning": (
                "denominator includes unmatched candidate claims and class-only "
                "support; do not present as final reconstruction precision"
            ),
            **final_reconstruction,
        },
        "strict_candidate_stream_precision": final_reconstruction["precision"],
        "reconstruction_summary": reconstruction_summary,
        "reconstruction": {
            "instance_only_precision": instance_only["precision"],
            "instance_only_recall": instance_only["recall"],
            "instance_only_f1": instance_only["f1"],
            "instance_only_tp": instance_tp,
            "class_level_recall": round(
                (instance_tp + class_tp) / total_exp, 4
            ) if total_exp else 0.0,
            "class_level_covered": instance_tp + class_tp,
            "expectations_total": total_exp,
            "critical_event_recall": critical["recall"],
        },
        "source_coverage": source_coverage,
        "multi_source_corroboration": corroboration,
        "noise_reduction": noise_reduction,
        "baseline_comparison": baseline_comparison,
        "methodology_warnings": methodology_warnings,
        "source_breakdown": _source_breakdown(tool_findings),
        "macro_f1_by_artifact_class": _macro_by_class(expectations, candidates, matches),
        "critical_recall": critical,
        "per_source": _per_source(expectations, matches, by_exp, by_cand),
        "per_artifact_class": _per_artifact_class(expectations, candidates, matches),
        "temporal_quality": _temporal_summary(tool_findings, candidates, matches, by_cand),
        "false_positives_per_run": _false_positives_per_run(matches, by_cand),
        "match_levels": {
            "instance": instance_tp,
            "class": class_tp,
        },
    }
    return metrics


def _reconstruction_summary(
    expectations: list[ArtifactExpectation],
    matches: list[MatchResult],
) -> dict[str, Any]:
    total = len(expectations)
    instance_ids = {
        m.target_id
        for m in matches
        if m.relation == "tp" and m.match_level == MatchLevel.INSTANCE
    }
    class_ids = {
        m.target_id
        for m in matches
        if m.relation == "tp" and m.match_level == MatchLevel.CLASS
    }
    critical_ids = {exp.ae_id for exp in expectations if exp.critical}
    observable_total = sum(
        1
        for exp in expectations
        if str(exp.observability).lower()
        not in {"", "none", "not_observable", "unobservable"}
    )
    strong = len(instance_ids)
    supported = len(class_ids)
    covered = strong + supported
    out: dict[str, Any] = {
        "expected_total": total,
        "observable_expected_total": observable_total,
        "strong_instance_matched_expected": strong,
        "class_only_supported_expected": supported,
        "missed_expected": max(0, total - covered),
        "strong_instance_recall": round(strong / total, 4) if total else 0.0,
        "class_support_coverage": round(supported / total, 4) if total else 0.0,
        "strong_or_supported_coverage": round(covered / total, 4) if total else 0.0,
    }
    if critical_ids:
        out["critical_strong_instance_recall"] = round(
            len(instance_ids & critical_ids) / len(critical_ids), 4
        )
    return out


def _source_coverage(
    tool_findings: list[ToolFinding],
    candidates: list[Candidate],
    matches: list[MatchResult],
) -> dict[str, Any]:
    by_cand = {cand.candidate_id: cand for cand in candidates}
    available_sources = sorted({finding.source_type.value for finding in tool_findings})
    candidate_sources = sorted(
        {
            source.value
            for cand in candidates
            for source in cand.source_types
            if source != EvidenceSource.UNKNOWN
        }
    )
    strong_sources = sorted(
        {
            source.value
            for match in matches
            if match.relation == "tp" and match.match_level == MatchLevel.INSTANCE
            for source in _candidate_sources(match, by_cand)
            if source != EvidenceSource.UNKNOWN
        }
    )
    out: dict[str, Any] = {
        "available_sources": available_sources,
        "candidate_sources": candidate_sources,
        "strong_reconstruction_sources": strong_sources,
        "available_source_count": len(available_sources),
        "candidate_source_count": len(candidate_sources),
        "strong_reconstruction_source_count": len(strong_sources),
        "denominator": "available_sources from raw ToolFinding records",
    }
    out["source_coverage_ratio"] = (
        round(len(strong_sources) / len(available_sources), 4) if available_sources else None
    )
    if not available_sources:
        out["note"] = (
            "source coverage ratio unavailable because no raw finding sources "
            "were available"
        )
    return out


def _candidate_sources(
    match: MatchResult,
    by_cand: dict[str, Candidate],
) -> set[EvidenceSource]:
    cand = by_cand.get(match.finding_or_claim_id)
    return set(cand.source_types) if cand else set()


def _multi_source_corroboration(
    candidates: list[Candidate],
    matches: list[MatchResult],
) -> dict[str, Any]:
    by_cand = {cand.candidate_id: cand for cand in candidates}
    strong = [m for m in matches if m.relation == "tp" and m.match_level == MatchLevel.INSTANCE]
    two_plus = 0
    per_expected: dict[str, int] = {}
    insufficient: list[str] = []
    for match in strong:
        cand = by_cand.get(match.finding_or_claim_id)
        source_count = 0
        if cand:
            source_count = len(
                {source for source in cand.source_types if source != EvidenceSource.UNKNOWN}
            )
        per_expected[match.target_id] = source_count
        if source_count >= 2:
            two_plus += 1
        if source_count == 0:
            insufficient.append(match.target_id)
    total = len(strong)
    out: dict[str, Any] = {
        "strong_reconstructed_with_2plus_sources": two_plus,
        "strong_reconstructed_total": total,
        "multi_source_corroboration_rate": round(two_plus / total, 4) if total else 0.0,
        "source_type_count_by_expected": dict(sorted(per_expected.items())),
    }
    if insufficient:
        out["limitation"] = (
            "some strong matches have no linked non-unknown source findings; "
            "they are counted as not multi-source corroborated"
        )
        out["insufficient_source_expected"] = sorted(insufficient)
    return out


def _noise_reduction(
    *,
    raw_findings_count: int,
    candidate_claim_count: int,
    strong_instance_match_count: int,
) -> dict[str, Any]:
    def reduction(after: int) -> float | None:
        if raw_findings_count == 0:
            return None
        return round(1 - (after / raw_findings_count), 4)

    return {
        "raw_findings_count": raw_findings_count,
        "candidate_claim_count": candidate_claim_count,
        "strong_instance_match_count": strong_instance_match_count,
        "raw_to_candidate_reduction": reduction(candidate_claim_count),
        "raw_to_strong_reconstruction_reduction": reduction(strong_instance_match_count),
        "note": "count reduction only; not baseline-aware",
    }


def _baseline_comparison_summary(candidates: list[Candidate]) -> dict[str, Any]:
    rows = [
        cand.entity.get("baseline")
        for cand in candidates
        if isinstance(cand.entity.get("baseline"), dict)
    ]
    if not rows:
        return {
            "available": False,
            "filtering_applied": False,
            "baseline_input": None,
            "baseline_path_count": 0,
            "compromised_path_count": 0,
            "status_counts": {
                "new_vs_baseline": 0,
                "changed_vs_baseline": 0,
                "present_in_baseline": 0,
                "unknown_baseline_status": 0,
            },
            "candidate_status_counts": {},
            "candidate_downgrades": 0,
            "candidate_suppressions": 0,
            "limitations": [
                "No verified clean baseline canonical tool_findings input was supplied."
            ],
        }
    first = rows[0]
    candidate_status_counts = Counter(str(row.get("status") or "unknown_baseline_status") for row in rows)
    action_counts = Counter(str(row.get("filter_action") or "none") for row in rows)
    return {
        "available": True,
        "filtering_applied": action_counts.get("confidence_downgraded", 0) > 0,
        "baseline_input": first.get("identity"),
        "baseline_path_count": int(first.get("baseline_path_count") or 0),
        "compromised_path_count": int(first.get("compromised_path_count") or 0),
        "status_counts": dict(first.get("status_counts") or {}),
        "candidate_status_counts": dict(sorted(candidate_status_counts.items())),
        "candidate_downgrades": action_counts.get("confidence_downgraded", 0),
        "candidate_suppressions": action_counts.get("suppressed", 0),
        "limitations": [
            "Path-only baseline comparison is candidate support, not a maliciousness verdict.",
            "Present-in-baseline timeline-only candidates are confidence-downgraded, not removed.",
            "Baseline metadata does not affect matcher formulas or strong reconstruction by itself.",
        ],
    }


def _source_breakdown(tool_findings: list[ToolFinding]) -> dict[str, int]:
    out = {source.value: 0 for source in EvidenceSource}
    for finding in tool_findings:
        out[finding.source_type.value] += 1
    return out


def _prf(tp: int, fp: int, fn: int) -> dict[str, float | int]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _macro_by_class(
    expectations: list[ArtifactExpectation],
    candidates: list[Candidate],
    matches: list[MatchResult],
) -> dict[str, Any]:
    per = _per_artifact_class(expectations, candidates, matches)
    values = [row["f1"] for row in per.values()]
    return {"macro_f1": round(sum(values) / len(values), 4) if values else 0.0, "classes": per}


def _critical_recall(expectations: list[ArtifactExpectation], matches: list[MatchResult]) -> dict[str, Any]:
    critical = {exp.ae_id for exp in expectations if exp.critical}
    hit = {m.target_id for m in matches if m.relation == "tp" and m.target_id in critical}
    return {
        "critical_total": len(critical),
        "critical_matched": len(hit),
        "recall": round(len(hit) / len(critical), 4) if critical else 1.0,
    }


def _per_source(
    expectations: list[ArtifactExpectation],
    matches: list[MatchResult],
    by_exp: dict[str, ArtifactExpectation],
    by_cand: dict[str, Candidate],
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for source in EvidenceSource:
        if source == EvidenceSource.UNKNOWN:
            continue
        exp_ids = {exp.ae_id for exp in expectations if source in exp.source_eligibility}
        cand_ids = {cand.candidate_id for cand in by_cand.values() if source in cand.source_types}
        tp = sum(1 for m in matches if m.relation == "tp" and m.target_id in exp_ids)
        fp = sum(1 for m in matches if m.relation == "fp" and m.finding_or_claim_id in cand_ids)
        fn = sum(1 for m in matches if m.relation == "fn" and m.target_id in exp_ids)
        out[source.value] = _prf(tp, fp, fn)
    return out


def _per_artifact_class(
    expectations: list[ArtifactExpectation],
    candidates: list[Candidate],
    matches: list[MatchResult],
) -> dict[str, Any]:
    by_cand = {cand.candidate_id: cand for cand in candidates}
    fp_classes = {
        by_cand[m.finding_or_claim_id].artifact_class
        for m in matches
        if m.relation == "fp" and m.finding_or_claim_id in by_cand
    }
    classes = sorted({exp.artifact_class for exp in expectations} | fp_classes)
    out: dict[str, Any] = {}
    for artifact_class in classes:
        exp_ids = {exp.ae_id for exp in expectations if exp.artifact_class == artifact_class}
        cand_ids = {cand.candidate_id for cand in candidates if cand.artifact_class == artifact_class}
        tp = sum(1 for m in matches if m.relation == "tp" and m.target_id in exp_ids)
        fp = sum(1 for m in matches if m.relation == "fp" and m.finding_or_claim_id in cand_ids)
        fn = sum(1 for m in matches if m.relation == "fn" and m.target_id in exp_ids)
        out[artifact_class] = _prf(tp, fp, fn)
    return out


def _temporal_summary(
    tool_findings: list[ToolFinding],
    candidates: list[Candidate],
    matches: list[MatchResult],
    by_cand: dict[str, Candidate],
) -> dict[str, Any]:
    finding_counts = {value: 0 for value in _TEMPORAL_VALUES}
    for finding in tool_findings:
        finding_counts[finding.temporal_quality.value] += 1
    matched_counts = {value: 0 for value in _TEMPORAL_VALUES}
    for match in matches:
        if match.relation != "tp":
            continue
        cand = by_cand.get(match.finding_or_claim_id)
        if cand:
            matched_counts[cand.temporal_quality.value] += 1
    return {"tool_findings": finding_counts, "matched_candidates": matched_counts}


def _false_positives_per_run(matches: list[MatchResult], by_cand: dict[str, Candidate]) -> dict[str, int]:
    out: dict[str, int] = {}
    for match in matches:
        if match.relation != "fp":
            continue
        cand = by_cand.get(match.finding_or_claim_id)
        run_id = cand.run_id if cand else match.run_id
        out[run_id] = out.get(run_id, 0) + 1
    return out


def render_report(
    metrics: dict[str, Any],
    matches: list[MatchResult],
    *,
    tool_findings: list[ToolFinding] | None = None,
    detection_claims: list[DetectionClaim] | None = None,
) -> str:
    _require_metrics_v2(metrics)
    micro = metrics["micro"]
    final = metrics.get("final_reconstruction", {})
    critical = metrics["critical_recall"]
    recon = metrics.get("reconstruction", {})
    recon_summary = metrics.get("reconstruction_summary", {})
    source_coverage = metrics.get("source_coverage", {})
    corroboration = metrics.get("multi_source_corroboration", {})
    noise = metrics.get("noise_reduction", {})
    baseline = metrics.get("baseline_comparison", {})
    warnings = metrics.get("methodology_warnings", [])
    sources = metrics.get("source_breakdown", {})
    tool_findings = tool_findings or []
    detection_claims = detection_claims or []
    claims_by_id = {claim.claim_id: claim for claim in detection_claims}
    finding_sources = {finding.finding_id: finding.source_type.value for finding in tool_findings}
    strong = [m for m in matches if m.relation == "tp" and m.match_level == MatchLevel.INSTANCE]
    support = [m for m in matches if m.relation == "tp" and m.match_level == MatchLevel.CLASS]
    unmatched = [m for m in matches if m.relation == "fp"]
    missed = [m for m in matches if m.relation == "fn"]
    lines = [
        "# Score Report",
        "",
        f"Candidate input: {metrics.get('candidate_input', 'detection_claims')}",
        "",
    ]
    if metrics.get("debug_only"):
        lines.extend([
            "Debug-only raw ToolFinding fallback was used; exclude this report from thesis metric reporting.",
            "",
        ])
    lines.extend([
        "## Candidate Diagnostics",
        "",
        "Detector/candidate-layer diagnostics only. These are not final thesis reconstruction metrics.",
        "",
        f"- Candidate TP: {micro['tp']}",
        f"- Candidate FP: {micro['fp']}",
        f"- Candidate FN: {micro['fn']}",
        f"- Candidate precision: {micro['precision']:.4f}",
        f"- Candidate recall: {micro['recall']:.4f}",
        f"- Candidate F1: {micro['f1']:.4f}",
        "",
        "## Reconstruction over Expected Artifacts",
        "",
        "Headline thesis reconstruction uses expected artifacts as the denominator. Class-only support is reported separately and does not increase strong instance recall.",
        "",
        f"- Expected artifacts: {recon_summary.get('expected_total', 0)}",
        f"- Observable expected artifacts: {recon_summary.get('observable_expected_total', 'n/a')}",
        f"- Strong instance matched expected artifacts: {recon_summary.get('strong_instance_matched_expected', 0)}",
        f"- Class-only/support expected artifacts: {recon_summary.get('class_only_supported_expected', 0)}",
        f"- Missed expected artifacts: {recon_summary.get('missed_expected', 0)}",
        f"- Strong instance recall: {recon_summary.get('strong_instance_recall', 0.0):.4f}",
        f"- Class support coverage: {recon_summary.get('class_support_coverage', 0.0):.4f}",
        f"- Strong-or-supported coverage: {recon_summary.get('strong_or_supported_coverage', 0.0):.4f}",
        f"- Critical strong instance recall: {recon_summary.get('critical_strong_instance_recall', 'n/a')}",
        "",
        "## Source Coverage",
        "",
        "Source coverage is based on strong instance matches and their linked source findings.",
        "",
        f"- Available raw sources: {', '.join(source_coverage.get('available_sources', [])) or '-'}",
        f"- Candidate sources: {', '.join(source_coverage.get('candidate_sources', [])) or '-'}",
        f"- Strong reconstruction sources: {', '.join(source_coverage.get('strong_reconstruction_sources', [])) or '-'}",
        f"- Source coverage ratio: {_fmt_optional_float(source_coverage.get('source_coverage_ratio'))}",
        f"- Denominator: {source_coverage.get('denominator', 'not defined')}",
        "",
        "## Multi-Source Corroboration",
        "",
        "Counts distinct linked source types per strong reconstructed expected artifact.",
        "",
        f"- Strong reconstructed with 2+ sources: {corroboration.get('strong_reconstructed_with_2plus_sources', 0)}",
        f"- Strong reconstructed total: {corroboration.get('strong_reconstructed_total', 0)}",
        f"- Multi-source corroboration rate: {corroboration.get('multi_source_corroboration_rate', 0.0):.4f}",
        "",
        "## Noise Reduction",
        "",
        "Count reduction only; this is not baseline-aware.",
        "",
        f"- Raw findings: {noise.get('raw_findings_count', 0)}",
        f"- Candidate claims: {noise.get('candidate_claim_count', 0)}",
        f"- Strong instance matches: {noise.get('strong_instance_match_count', 0)}",
        f"- Raw-to-candidate reduction: {_fmt_optional_float(noise.get('raw_to_candidate_reduction'))}",
        f"- Raw-to-strong-reconstruction reduction: {_fmt_optional_float(noise.get('raw_to_strong_reconstruction_reduction'))}",
        "",
        "## Baseline Comparison",
        "",
        "Clean-baseline comparison is conservative support metadata. It does not infer maliciousness and does not change matcher formulas.",
        "",
        f"- Baseline available: {bool(baseline.get('available'))}",
        f"- Baseline input: {baseline.get('baseline_input') or 'n/a'}",
        f"- Baseline paths: {baseline.get('baseline_path_count', 0)}",
        f"- Compromised paths compared: {baseline.get('compromised_path_count', 0)}",
        f"- New vs baseline paths: {baseline.get('status_counts', {}).get('new_vs_baseline', 0)}",
        f"- Changed vs baseline paths: {baseline.get('status_counts', {}).get('changed_vs_baseline', 0)}",
        f"- Present in baseline paths: {baseline.get('status_counts', {}).get('present_in_baseline', 0)}",
        f"- Unknown baseline status paths: {baseline.get('status_counts', {}).get('unknown_baseline_status', 0)}",
        f"- Candidate downgrades: {baseline.get('candidate_downgrades', 0)}",
        f"- Candidate suppressions: {baseline.get('candidate_suppressions', 0)}",
        "",
        "Limitations:",
        "",
        *[f"- {item}" for item in baseline.get('limitations', [])],
        "",
        "## Methodological Warnings / Unavailable Metrics",
        "",
        f"- final_reconstruction.precision label: {final.get('precision_label', 'n/a')}",
        f"- final_reconstruction.precision warning: {final.get('precision_warning', 'n/a')}",
        *[f"- {warning}" for warning in warnings],
        "",
        "## Class-level coverage",
        "",
        "Did an expectation's artifact class show up at all (instance or class match)?",
        "",
        f"- Class-level recall: {recon.get('class_level_recall', 0.0):.4f} "
        f"({recon.get('class_level_covered', 0)}/{recon.get('expectations_total', 0)})",
        f"- Class matches: {metrics['match_levels']['class']}",
        "",
        "## Instance-level reconstruction",
        "",
        "Did we recover the exact planted entity? Class hits count only as support. No final-claim precision is emitted because there is no final-claim selection layer.",
        "",
        f"- Strong instance recall: {recon_summary.get('strong_instance_recall', 0.0):.4f}",
        f"- Instance matches: {metrics['match_levels']['instance']}",
        "",
        "## Critical observables",
        "",
        f"- Critical strong instance recall: {recon_summary.get('critical_strong_instance_recall', 'n/a')}",
        f"- Candidate-supported critical recall (diagnostic): {critical['recall']:.4f} "
        f"({critical['critical_matched']}/{critical['critical_total']})",
        "",
        "## Raw ToolFinding Counts by Source/Type",
        "",
    ])
    if tool_findings:
        lines.extend(["| source | artifact class | count |", "|---|---|---:|"])
        for (source, artifact_class), count in _tool_finding_counts(tool_findings).items():
            lines.append(f"| {source} | {artifact_class} | {count} |")
    else:
        for source in ("disk", "memory", "timeline", "log", "unknown"):
            if source in sources:
                lines.append(f"- {source}: {sources[source]}")
    lines.extend([
        "",
        "## Candidate Evidence / DetectionClaim Counts",
        "",
    ])
    if detection_claims:
        lines.extend(["| rule | source | count |", "|---|---|---:|"])
        for (rule_id, source), count in _claim_counts_by_rule_source(detection_claims, finding_sources).items():
            lines.append(f"| {rule_id} | {source} | {count} |")
    else:
        lines.append("No DetectionClaim records were provided.")
    lines.extend([
        "",
        "## Memory Aggregation/Deduplication Summary",
        "",
        "| rule | before | after | collapsed |",
        "|---|---:|---:|---:|",
    ])
    for row in _memory_aggregation_summary(detection_claims):
        lines.append(
            f"| {row['rule_id']} | {row['before']} | {row['after']} | {row['collapsed']} |"
        )
    lines.extend([
        "",
        "## Matched Expectations / Reconstruction Evidence",
        "",
        "| strength | expectation | candidate | sources | score | fields |",
        "|---|---|---|---|---:|---|",
    ])
    for match in [*strong, *support]:
        lines.append(_match_evidence_row(match, claims_by_id, finding_sources))
    lines.extend([
        "",
        "## Strong Instance Matches",
        "",
        "| expectation | candidate | sources | score | fields |",
        "|---|---|---|---:|---|",
    ])
    for match in strong:
        lines.append(_match_evidence_row(match, claims_by_id, finding_sources, include_strength=False))
    lines.extend([
        "",
        "## Class-Only / Support Matches",
        "",
        "| expectation | candidate | sources | score | fields |",
        "|---|---|---|---:|---|",
    ])
    for match in support:
        lines.append(_match_evidence_row(match, claims_by_id, finding_sources, include_strength=False))
    lines.extend([
        "",
        "## Unmatched Candidate Claims",
        "",
        f"- Total: {len(unmatched)}",
        "",
    ])
    if detection_claims:
        lines.extend(["| rule | artifact class | count |", "|---|---|---:|"])
        for (rule_id, artifact_class), count in _unmatched_claim_counts(unmatched, claims_by_id).items():
            lines.append(f"| {rule_id} | {artifact_class} | {count} |")
    lines.extend([
        "",
        "## Missed Expected Artifacts",
        "",
    ])
    if missed:
        lines.extend(["| expectation |", "|---|"])
        for match in missed:
            lines.append(f"| {match.target_id} |")
    else:
        lines.append("No unmatched expected artifacts at candidate level.")
    lines.extend([
        "",
        "## Per Source",
        "",
        "| source | TP | FP | FN | precision | recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ])
    for source, row in metrics["per_source"].items():
        lines.append(
            f"| {source} | {row['tp']} | {row['fp']} | {row['fn']} | "
            f"{row['precision']:.4f} | {row['recall']:.4f} | {row['f1']:.4f} |"
        )
    lines.extend(["", "## Per Artifact Class", "", "| class | TP | FP | FN | F1 |", "|---|---:|---:|---:|---:|"])
    for artifact_class, row in metrics["per_artifact_class"].items():
        lines.append(f"| {artifact_class} | {row['tp']} | {row['fp']} | {row['fn']} | {row['f1']:.4f} |")
    lines.extend(["", "## Match Detail", "", "| relation | level | expectation | finding/claim | score | fields |", "|---|---|---|---|---:|---|"])
    for match in matches:
        lines.append(
            f"| {match.relation} | {match.match_level.value} | {match.target_id} | "
            f"{match.finding_or_claim_id} | {match.score:.4f} | {', '.join(match.fields_matched)} |"
        )
    return "\n".join(lines) + "\n"


def render_console_summary(metrics: dict[str, Any]) -> list[str]:
    """Short schema-v2 summary for active canonical CLI/run output."""
    _require_metrics_v2(metrics)
    candidate = metrics.get("candidate_diagnostics")
    reconstruction = metrics.get("reconstruction_summary")
    baseline = metrics.get("baseline_comparison") or {}
    warnings = metrics.get("methodology_warnings") or []
    if not isinstance(candidate, dict) or not isinstance(reconstruction, dict):
        raise ValueError(
            "metrics schema v2 is missing candidate_diagnostics or "
            "reconstruction_summary; regenerate with current matcher"
        )

    strong = int(reconstruction.get("strong_instance_matched_expected") or 0)
    expected = int(reconstruction.get("expected_total") or 0)
    class_support = int(reconstruction.get("class_only_supported_expected") or 0)
    missed = int(reconstruction.get("missed_expected") or 0)
    baseline_available = bool(baseline.get("available"))
    baseline_label = "available" if baseline_available else "unavailable"
    baseline_input = baseline.get("baseline_input")
    baseline_suffix = f" input={baseline_input}" if baseline_input else ""

    lines = [
        "candidate diagnostics: "
        f"precision={float(candidate.get('precision', 0.0)):.4f} "
        f"recall={float(candidate.get('recall', 0.0)):.4f} "
        f"f1={float(candidate.get('f1', 0.0)):.4f} "
        f"tp={int(candidate.get('tp', 0))} "
        f"fp={int(candidate.get('fp', 0))} "
        f"fn={int(candidate.get('fn', 0))}",
        "reconstruction: "
        f"strong_instance_recall={float(reconstruction.get('strong_instance_recall', 0.0)):.4f} "
        f"strong={strong}/{expected} "
        f"class_support={class_support} "
        f"missed={missed}",
        f"baseline: {baseline_label}{baseline_suffix}",
    ]
    if warnings:
        lines.append(f"warnings: {len(warnings)} methodology warning(s)")
    return lines


def _require_metrics_v2(metrics: dict[str, Any]) -> None:
    schema = metrics.get("schema")
    if schema != _METRICS_SCHEMA_V2:
        label = schema if schema not in (None, "") else "missing"
        raise ValueError(
            f"unsupported metrics schema '{label}'; regenerate with current "
            f"matcher (expected {_METRICS_SCHEMA_V2})"
        )


def _fmt_optional_float(value: Any) -> str:
    return "n/a" if value is None else f"{float(value):.4f}"


def _tool_finding_counts(tool_findings: list[ToolFinding]) -> dict[tuple[str, str], int]:
    counts: Counter[tuple[str, str]] = Counter(
        (finding.source_type.value, finding.artifact_class) for finding in tool_findings
    )
    return dict(sorted(counts.items()))


def _claim_counts_by_rule_source(
    claims: list[DetectionClaim],
    finding_sources: dict[str, str],
) -> dict[tuple[str, str], int]:
    counts: Counter[tuple[str, str]] = Counter()
    for claim in claims:
        source = "+".join(sorted({finding_sources.get(fid, "unknown") for fid in claim.source_findings}))
        counts[(claim.rule_id, source or "unknown")] += 1
    return dict(sorted(counts.items()))


def _memory_aggregation_summary(claims: list[DetectionClaim]) -> list[dict[str, Any]]:
    rule_ids = [
        "flab.memory.process_library_correlation",
        "flab.memory.process_socket_correlation",
    ]
    rows: list[dict[str, Any]] = []
    for rule_id in rule_ids:
        rule_claims = [claim for claim in claims if claim.rule_id == rule_id]
        before = sum(int(claim.entity.get("collapsed_candidate_count") or 1) for claim in rule_claims)
        after = len(rule_claims)
        rows.append({"rule_id": rule_id, "before": before, "after": after, "collapsed": before - after})
    return rows


def _match_evidence_row(
    match: MatchResult,
    claims_by_id: dict[str, DetectionClaim],
    finding_sources: dict[str, str],
    *,
    include_strength: bool = True,
) -> str:
    claim = claims_by_id.get(match.finding_or_claim_id)
    sources = "-"
    if claim:
        sources = "+".join(sorted({finding_sources.get(fid, "unknown") for fid in claim.source_findings}))
    fields = ", ".join(match.fields_matched)
    if include_strength:
        return (
            f"| {_match_strength(match)} | {match.target_id} | {match.finding_or_claim_id} | "
            f"{sources} | {match.score:.4f} | {fields} |"
        )
    return f"| {match.target_id} | {match.finding_or_claim_id} | {sources} | {match.score:.4f} | {fields} |"


def _match_strength(match: MatchResult) -> str:
    if match.relation == "tp" and match.match_level == MatchLevel.INSTANCE:
        return "strong_instance_match"
    if match.relation == "tp" and match.match_level == MatchLevel.CLASS:
        return "class_only_support"
    if match.relation == "fp":
        return "unmatched_candidate"
    return match.match_level.value


def _unmatched_claim_counts(
    unmatched: list[MatchResult],
    claims_by_id: dict[str, DetectionClaim],
) -> dict[tuple[str, str], int]:
    counts: Counter[tuple[str, str]] = Counter()
    for match in unmatched:
        claim = claims_by_id.get(match.finding_or_claim_id)
        if claim:
            counts[(claim.rule_id, claim.artifact_class)] += 1
    return dict(sorted(counts.items()))
