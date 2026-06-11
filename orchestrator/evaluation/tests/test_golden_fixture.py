# Phase 7.1 golden synthetic fixture: a 6-event manifest + 9 findings
# (5 matching, 1 duplicate-of-a-match, 2 in-window non-matching, 1 out-of-window).
# Expected exactly TP=5, FP=2, FN=1, recall=0.833, precision=0.714, plus the
# hand-computed order_pairwise and time_mae below.

from pathlib import Path

from orchestrator.evaluation.contracts.models import Finding, GtManifest
from orchestrator.evaluation.contracts.validate import load_findings, load_gt_manifest
from orchestrator.evaluation.match.matcher import match
from orchestrator.evaluation.metrics.compute import compute_row

_FIX = Path(__file__).parent / "fixtures"


def _load():
    manifest = GtManifest.from_dict(load_gt_manifest(_FIX / "gt_manifest.json"))
    findings = [Finding.from_dict(d) for d in load_findings(_FIX / "findings.jsonl")]
    return manifest, findings


def test_match_counts():
    manifest, findings = _load()
    m = match(manifest, findings)
    assert len(m.tp) == 5
    assert len(m.fp) == 2
    assert len(m.fn) == 1
    assert m.fn == ["G6"]
    assert len(m.background_noise) == 1


def test_duplicate_collapses_into_one_claim():
    manifest, findings = _load()
    m = match(manifest, findings)
    g1 = next(r for r in m.tp if r["gt_id"] == "G1")
    assert sorted(g1["finding_ids"]) == ["f-000001", "f-000006"]
    assert g1["primary_finding"] == "f-000001"


def test_metric_values():
    manifest, findings = _load()
    m = match(manifest, findings)
    row = compute_row(manifest, m)
    v = row.values
    assert v["gt_n"] == 6
    assert v["tp"] == 5 and v["fp"] == 2 and v["fn"] == 1
    assert round(v["recall"], 3) == 0.833
    assert round(v["precision"], 3) == 0.714
    assert v["order_pairwise"] == 1.0
    assert round(v["kendall_tau"], 6) == 1.0
    assert abs(v["time_mae_s"] - 0.34) < 1e-9
    # f1 = 2PR/(P+R) with P=5/7, R=5/6
    assert round(v["f1"], 3) == 0.769


def test_precision_excludes_background_noise():
    # The out-of-window finding (f-000009) must not inflate FP.
    manifest, findings = _load()
    m = match(manifest, findings)
    fp_ids = {fid for row in m.fp for fid in row["finding_ids"]}
    assert "f-000009" not in fp_ids
    bg_ids = {fid for row in m.background_noise for fid in row["finding_ids"]}
    assert bg_ids == {"f-000009"}
