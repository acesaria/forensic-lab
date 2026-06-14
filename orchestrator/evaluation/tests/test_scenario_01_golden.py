# Regression: scenario_01 (LD_PRELOAD persistence + reverse shell), NO-CLEANUP.
# Locks the CORRECTED confusion matrix after the four logic fixes (detector
# coverage, technique-anchored corroboration, known-good allowlist, claim-unit
# precision). In a no-cleanup run every primary artifact is still on the medium,
# so every GT event is recoverable -> recall = 1.0; the three preload channels
# fold into one TP and the benign hit is reclassified -> precision = 1.0.

from pathlib import Path

from orchestrator.evaluation.contracts.models import Finding, GtManifest
from orchestrator.evaluation.contracts.validate import load_findings, load_gt_manifest
from orchestrator.evaluation.match.matcher import match
from orchestrator.evaluation.metrics.compute import compute_row

_FIX = Path(__file__).parent / "fixtures" / "scenario_01"


def _load():
    manifest = GtManifest.from_dict(load_gt_manifest(_FIX / "gt_manifest.json"))
    findings = [Finding.from_dict(d) for d in load_findings(_FIX / "findings.jsonl")]
    return manifest, findings


def test_confusion_matrix():
    manifest, findings = _load()
    m = match(manifest, findings)
    assert len(m.tp) == 6
    assert len(m.fp) == 0
    assert m.fn == []
    assert len(m.background_noise) == 1


def test_preload_channels_fold_into_one_tp():
    # The auth.log / journal / sudo observations of the preload write carry a
    # process entity, not the /etc/ld.so.preload path; they corroborate G2 on
    # technique instead of becoming false positives.
    manifest, findings = _load()
    m = match(manifest, findings)
    g2 = next(r for r in m.tp if r["gt_id"] == "G2")
    assert g2["n_clusters"] == 4
    assert g2["primary_finding"] == "f-000003"
    assert set(g2["tools"]) == {"plaso", "tsk"}
    assert g2["finding_ids"] == ["f-000002", "f-000003", "f-000004", "f-000005"]


def test_benign_hit_is_background_not_fp():
    manifest, findings = _load()
    m = match(manifest, findings)
    bg_ids = {fid for r in m.background_noise for fid in r["finding_ids"]}
    assert bg_ids == {"f-000010"}


def test_metrics_row():
    manifest, findings = _load()
    row = compute_row(manifest, match(manifest, findings)).values
    assert row["gt_n"] == 6
    assert row["tp"] == 6 and row["fp"] == 0 and row["fn"] == 0
    assert row["recall"] == 1.0
    assert row["precision"] == 1.0
    # Single-tool catches: tsk uniquely covers G1/G3/G6, vol3 covers G4/G5.
    assert row["uniq_tsk"] == 3
    assert row["uniq_vol3"] == 2
    assert row["uniq_plaso"] == 0
