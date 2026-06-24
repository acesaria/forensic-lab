# External-tool channels (Sigma over Plaso, YARA over files) flow into the same
# detect -> match -> metrics pipeline and populate their (forensic_operation,
# source_tool) metric buckets. Drives the detectors with synthetic raw outputs so
# it needs none of the external binaries/libraries.

from pathlib import Path

from orchestrator.evaluation.contracts.models import Finding, GtManifest
from orchestrator.evaluation.contracts.validate import load_gt_manifest, validate_finding
from orchestrator.evaluation.detect.run import run_detection
from orchestrator.evaluation.detect.plaso_sigma import detect as sigma_detect
from orchestrator.evaluation.detect.yara_scan import detect as yara_detect
from orchestrator.evaluation.match.matcher import match
from orchestrator.evaluation.metrics.compute import compute_breakdown
from orchestrator.forensics import sigma_runner

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
    }


def test_sigma_runner_loads_vendored_rules_and_pin():
    rules = sigma_runner.load_rules()
    assert rules, "expected vendored Sigma rules to load"
    assert sigma_runner.pinned_commit()  # pin recorded


def test_detectors_emit_expected_source_and_operation():
    raw = _raw()
    cfg = {"sigma_vendored_dirs": [str(sigma_runner.vendored_rules_dir())]}

    # Sigma over the timeline: a vendored file_event rule (TripleCross
    # "ebpfbackdoor" persistence) compiles to SQL and fires on the matching
    # filesystem row. The scenario's own /etc/ld.so.preload rule is a Sigma
    # keyword rule, not expressible in SQL, so it is skipped (auditd; future work).
    sigma_raw = {"plaso": [
        {"timestamp": _G2_TS_US, "filename": "/etc/cron.d/ebpfbackdoor", "data_type": "fs:stat"},
    ]}
    s = list(sigma_detect(sigma_raw, cfg))
    assert s and all(f.source_tool == "plaso_sigma" and f.forensic_operation == "timeline" for f in s)
    assert any(f.entity.value == "/etc/cron.d/ebpfbackdoor" and f.technique == "T1053.003" for f in s)

    y = list(yara_detect(raw, cfg))
    assert y and all(f.source_tool == "yara" and f.forensic_operation == "content_scan" for f in y)
    assert y[0].entity.value == "/tmp/T1574006.so"

    # Every emitted finding is schema-valid (new source_tool enum members).
    for f in [*s, *y]:
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
    # YARA (content_scan) lands on a scenario_01 observable -> a populated TP
    # bucket, no false positives. The vendored Sigma rules do not cover scenario_01
    # on a filesystem-only timeline (its ld.so.preload rule is a keyword rule;
    # auditd would add coverage), so plaso_sigma is exercised in
    # test_detectors_emit..., not asserted here.
    yara = rows[("content_scan", "yara", "community")]
    assert yara["tp"] >= 1 and yara["fp"] == 0 and yara["precision"] == 1.0
