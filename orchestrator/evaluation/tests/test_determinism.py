# Phase 7.3 determinism: running match+metrics twice on the same inputs produces
# byte-identical matches.json and the same metrics row.

import json
from pathlib import Path

from orchestrator.evaluation.contracts.models import Finding, GtManifest
from orchestrator.evaluation.contracts.validate import load_findings, load_gt_manifest
from orchestrator.evaluation.match.matcher import match, write_matches
from orchestrator.evaluation.metrics.compute import compute_row

_FIX = Path(__file__).parent / "fixtures"


def _load():
    manifest = GtManifest.from_dict(load_gt_manifest(_FIX / "gt_manifest.json"))
    findings = [Finding.from_dict(d) for d in load_findings(_FIX / "findings.jsonl")]
    return manifest, findings


def test_matches_byte_identical(tmp_path: Path):
    manifest, findings = _load()
    out1 = write_matches(match(manifest, findings), tmp_path / "m1.json")
    out2 = write_matches(match(manifest, findings), tmp_path / "m2.json")
    assert out1.read_bytes() == out2.read_bytes()


def test_matches_insensitive_to_input_order(tmp_path: Path):
    manifest, findings = _load()
    a = json.dumps(match(manifest, findings).to_dict(), sort_keys=True)
    b = json.dumps(
        match(manifest, list(reversed(findings))).to_dict(), sort_keys=True
    )
    assert a == b


def test_metric_row_identical():
    manifest, findings = _load()
    r1 = compute_row(manifest, match(manifest, findings)).as_list()
    r2 = compute_row(manifest, match(manifest, findings)).as_list()
    assert r1 == r2
