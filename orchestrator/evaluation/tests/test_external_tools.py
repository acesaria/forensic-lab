# External-tool channels (Sigma over Plaso, YARA over files, bulk_extractor over
# the image) flow into the same detect -> match -> metrics pipeline and populate
# their (forensic_operation, source_tool) metric buckets. Drives the detectors
# with synthetic raw outputs so it needs none of the external binaries/libraries.

from pathlib import Path

from orchestrator.evaluation.contracts.models import Finding, GtManifest
from orchestrator.evaluation.contracts.validate import load_gt_manifest, validate_finding
from orchestrator.evaluation.detect.bulk_extractor_strings import detect as be_detect
from orchestrator.evaluation.detect.run import run_detection
from orchestrator.evaluation.detect.sigma_vendored import detect as sigma_detect
from orchestrator.evaluation.detect.yara_scan import detect as yara_detect
from orchestrator.evaluation.match.matcher import match
from orchestrator.evaluation.metrics.compute import compute_breakdown
from orchestrator.forensics import bulk_extractor_runner, sigma_runner

_FIX = Path(__file__).parent / "fixtures" / "scenario_01"
_G2_TS_US = 1781784005_000000  # 2026-06-13T12:00:05Z, near G2


def _raw():
    return {
        "plaso": [
            {"timestamp": _G2_TS_US, "filename": "/etc/ld.so.preload", "data_type": "fs:stat"},
        ],
        "yara": [
            {
                "path": "/tmp/T1574006.so",
                "rule": "SUSP_LD_PRELOAD_Hook_SharedObject",
                "tags": [],
                "meta": {"technique": "attack.t1574.006"},
            }
        ],
        "bulk_extractor": [
            {"offset": "0", "feature": "/etc/ld.so.preload", "context": ""},
            {"offset": "1", "feature": "/tmp/T1574006.so", "context": ""},
            {"offset": "2", "feature": "/tmp/T1082.txt", "context": ""},
        ],
    }


def test_sigma_runner_loads_vendored_rules_and_pin():
    rules = sigma_runner.load_rules()
    assert rules, "expected vendored Sigma rules to load"
    assert sigma_runner.pinned_commit()  # pin recorded


def test_detectors_emit_expected_source_and_operation():
    raw = _raw()
    cfg = {"sigma_vendored_dirs": [str(sigma_runner.vendored_rules_dir())]}

    s = list(sigma_detect(raw, cfg))
    assert s and all(f.source_tool == "plaso_sigma" and f.forensic_operation == "timeline" for f in s)
    assert any(f.entity.value == "/etc/ld.so.preload" and f.technique == "T1574.006" for f in s)

    y = list(yara_detect(raw, cfg))
    assert y and all(f.source_tool == "yara" and f.forensic_operation == "content_scan" for f in y)
    assert y[0].entity.value == "/tmp/T1574006.so"

    b = list(be_detect(raw, cfg))
    assert b and all(f.source_tool == "bulk_extractor" and f.forensic_operation == "string_search" for f in b)
    assert {str(f.entity.value) for f in b} == {"/etc/ld.so.preload", "/tmp/T1574006.so", "/tmp/T1082.txt"}

    # Every emitted finding is schema-valid (new source_tool enum members).
    for f in [*s, *y, *b]:
        validate_finding({**f.to_dict(), "finding_id": "f-000000"})


def test_buckets_nonzero_through_pipeline():
    raw = _raw()
    cfg = {"sigma_vendored_dirs": [str(sigma_runner.vendored_rules_dir())]}
    findings = run_detection(raw, cfg)
    manifest = GtManifest.from_dict(load_gt_manifest(_FIX / "gt_manifest.json"))
    m = match(manifest, findings)
    rows = {
        (r.values["forensic_operation"], r.values["source_tool"], r.values["rule_layer"]): r.values
        for r in compute_breakdown(manifest, m, findings)
    }
    # Each new (operation, source_tool) bucket is populated with true positives
    # and no false positives (all findings land on a GT observable). Keyed with
    # rule_layer "community" so the layer-agnostic FN aggregate row is distinct.
    sigma = rows[("timeline", "plaso_sigma", "community")]
    yara = rows[("content_scan", "yara", "community")]
    be = rows[("string_search", "bulk_extractor", "community")]
    assert sigma["tp"] >= 1 and sigma["fp"] == 0 and sigma["precision"] == 1.0
    assert yara["tp"] >= 1 and yara["fp"] == 0 and yara["precision"] == 1.0
    assert be["tp"] >= 1 and be["fp"] == 0 and be["precision"] == 1.0


def test_bulk_extractor_feature_parsing(tmp_path):
    feat = tmp_path / "wordlist.txt"
    feat.write_text(
        "# Banner line ignored\n"
        "4096\t/etc/ld.so.preload\tcontext-bytes\n"
        "8192\t/usr/bin/python3\tother\n",
        encoding="utf-8",
    )
    # Token filter keeps only matching features; parser stays generic.
    recs = bulk_extractor_runner.parse_feature_file(feat, tokens=["ld.so.preload"])
    assert [r["feature"] for r in recs] == ["/etc/ld.so.preload"]
    assert recs[0]["offset"] == "4096"
    # No filter -> every feature line.
    assert len(bulk_extractor_runner.parse_feature_file(feat)) == 2
