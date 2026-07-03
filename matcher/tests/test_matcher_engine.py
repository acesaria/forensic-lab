import json
import subprocess
from pathlib import Path

import pytest

from matcher.engine import render_console_summary, render_report, run_matcher_files
from orchestrator.canonical import MatchLevel, MatchResult, load_jsonl

FIXTURES = Path(__file__).parent / "fixtures"


def test_matcher_outputs_matches_metrics_and_report(tmp_path: Path):
    result = run_matcher_files(
        expectations_path=FIXTURES / "artifact_expectations.jsonl",
        tool_findings_path=Path("detectors/tests/fixtures/tool_findings.jsonl"),
        detection_claims_path=FIXTURES / "detection_claims.jsonl",
        out_dir=tmp_path,
        time_window_s=30,
    )

    matches = load_jsonl(result["matches_path"], MatchResult)
    metrics = json.loads(result["metrics_path"].read_text(encoding="utf-8"))
    report = result["report_path"].read_text(encoding="utf-8")

    assert result["matches_path"].name == "matches.jsonl"
    assert result["metrics_path"].name == "metrics.json"
    assert result["report_path"].name == "score_report.md"
    assert metrics["counts"] == {"tp": 4, "fp": 1, "fn": 1}
    assert metrics["micro"]["precision"] == 0.8
    assert metrics["micro"]["recall"] == 0.8
    assert metrics["critical_recall"]["recall"] == 0.6667
    assert metrics["match_levels"]["instance"] >= 2
    assert metrics["match_levels"]["class"] >= 1
    assert metrics["final_reconstruction"]["strong_instance_matches"] == metrics["match_levels"]["instance"]
    assert metrics["final_reconstruction"]["class_only_support"] == metrics["match_levels"]["class"]
    assert metrics["final_reconstruction"]["precision"] < metrics["candidate_diagnostics"]["precision"]
    assert any(m.match_level == MatchLevel.INSTANCE for m in matches)
    assert any(m.match_level == MatchLevel.CLASS for m in matches)
    assert "# Score Report" in report
    assert "Candidate Diagnostics" in report
    assert "Reconstruction over Expected Artifacts" in report
    assert "Source Coverage" in report
    assert "Multi-Source Corroboration" in report
    assert "Noise Reduction" in report
    assert "Baseline Comparison" in report
    assert "Methodological Warnings / Unavailable Metrics" in report
    assert "Raw ToolFinding Counts by Source/Type" in report
    assert "Candidate Evidence / DetectionClaim Counts" in report
    assert "Memory Aggregation/Deduplication Summary" in report
    assert "Matched Expectations / Reconstruction Evidence" in report
    assert "Strong Instance Matches" in report
    assert "Class-Only / Support Matches" in report
    assert "Unmatched Candidate Claims" in report
    assert "Per Artifact Class" in report
    assert "Final precision" not in report
    assert "Instance-only precision" not in report


def test_class_only_support_is_not_headline_reconstruction_quality(tmp_path: Path):
    result = run_matcher_files(
        expectations_path=FIXTURES / "artifact_expectations.jsonl",
        tool_findings_path=Path("detectors/tests/fixtures/tool_findings.jsonl"),
        detection_claims_path=FIXTURES / "detection_claims.jsonl",
        out_dir=tmp_path,
        time_window_s=30,
    )

    metrics = result["metrics"]

    assert metrics["match_levels"]["class"] >= 1
    assert metrics["candidate_diagnostics"]["tp"] == metrics["counts"]["tp"]
    assert metrics["final_reconstruction"]["tp"] == metrics["match_levels"]["instance"]
    assert metrics["final_reconstruction"]["fp"] == (
        metrics["counts"]["fp"] + metrics["match_levels"]["class"]
    )
    assert metrics["reconstruction_summary"]["strong_instance_matched_expected"] == metrics["match_levels"]["instance"]
    assert metrics["reconstruction_summary"]["class_only_supported_expected"] == metrics["match_levels"]["class"]
    assert metrics["reconstruction_summary"]["strong_instance_recall"] < metrics["candidate_diagnostics"]["recall"]
    assert metrics["reconstruction_summary"]["strong_instance_recall"] == 0.6
    assert metrics["reconstruction_summary"]["strong_or_supported_coverage"] == 0.8


def test_candidate_precision_is_labeled_diagnostic(tmp_path: Path):
    result = run_matcher_files(
        expectations_path=FIXTURES / "artifact_expectations.jsonl",
        tool_findings_path=Path("detectors/tests/fixtures/tool_findings.jsonl"),
        detection_claims_path=FIXTURES / "detection_claims.jsonl",
        out_dir=tmp_path,
        time_window_s=30,
    )

    metrics = result["metrics"]

    assert "detector/candidate-layer diagnostics" in metrics["candidate_diagnostics"]["description"]
    assert metrics["strict_candidate_stream_precision"] == metrics["final_reconstruction"]["precision"]
    assert metrics["final_reconstruction"]["precision_label"] == "strict_candidate_stream_precision"
    assert "not the thesis headline metric" in metrics["final_reconstruction"]["description"]
    assert any("pipeline_runtime_seconds is not emitted" in warning for warning in metrics["methodology_warnings"])
    assert any("evidence_latency is not emitted" in warning for warning in metrics["methodology_warnings"])


def test_schema_v2_console_summary_labels_candidate_and_reconstruction_layers(tmp_path: Path):
    result = run_matcher_files(
        expectations_path=FIXTURES / "artifact_expectations.jsonl",
        tool_findings_path=Path("detectors/tests/fixtures/tool_findings.jsonl"),
        detection_claims_path=FIXTURES / "detection_claims.jsonl",
        out_dir=tmp_path,
        time_window_s=30,
    )

    text = "\n".join(render_console_summary(result["metrics"]))

    assert "candidate diagnostics:" in text
    assert "reconstruction:" in text
    assert "baseline:" in text
    assert "warnings:" in text
    assert "canonical metrics: precision=" not in text
    assert "final precision" not in text.lower()


def test_old_or_unknown_metrics_schema_is_not_silently_formatted_as_canonical():
    v1_like = {"precision": 1.0, "recall": 1.0, "tp": 1, "fp": 0, "fn": 0}
    unknown = {"schema": "forensic-lab.matcher.metrics.v99"}

    with pytest.raises(ValueError, match="unsupported metrics schema 'missing'"):
        render_console_summary(v1_like)
    with pytest.raises(ValueError, match="unsupported metrics schema 'forensic-lab.matcher.metrics.v99'"):
        render_console_summary(unknown)
    with pytest.raises(ValueError, match="regenerate with current matcher"):
        render_report(v1_like, [])


def test_source_coverage_uses_strong_instance_matches_not_raw_counts_only(tmp_path: Path):
    tool_findings_path = tmp_path / "tool_findings.jsonl"
    original = Path("detectors/tests/fixtures/tool_findings.jsonl").read_text(encoding="utf-8")
    extra_log = {
        "adapter_version": "canonical-adapters-v1",
        "artifact_class": "log_event",
        "entity": {"type": "message", "value": "unlinked log noise"},
        "finding_id": "tf-unlinked-log",
        "provenance": {"adapter": "fixture"},
        "raw_ref": "log:fixture:line=1",
        "run_id": "run-detector-fixture",
        "source_type": "log",
        "temporal_quality": "none",
        "time": "unknown",
        "tool": "fixture-log",
        "tool_version": "fixture",
    }
    tool_findings_path.write_text(original + json.dumps(extra_log, sort_keys=True) + "\n", encoding="utf-8")

    result = run_matcher_files(
        expectations_path=FIXTURES / "artifact_expectations.jsonl",
        tool_findings_path=tool_findings_path,
        detection_claims_path=FIXTURES / "detection_claims.jsonl",
        out_dir=tmp_path / "out",
        time_window_s=30,
    )

    coverage = result["metrics"]["source_coverage"]

    assert coverage["available_sources"] == ["disk", "log", "memory"]
    assert coverage["strong_reconstruction_sources"] == ["disk", "memory"]
    assert coverage["source_coverage_ratio"] == 0.6667
    assert "baseline" not in coverage["available_sources"]
    assert "baseline" not in coverage["strong_reconstruction_sources"]


def test_baseline_metadata_is_reported_without_changing_source_coverage(tmp_path: Path):
    claims_path = tmp_path / "detection_claims.jsonl"
    rows = []
    for line in (FIXTURES / "detection_claims.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        row["entity"]["baseline"] = {
            "identity": "lab-ubuntu-22.04:baseline",
            "status": "present_in_baseline",
            "path": row["entity"].get("value"),
            "compared_fields": [],
            "baseline_record_count": 1,
            "baseline_path_count": 2,
            "compromised_path_count": 3,
            "status_counts": {
                "new_vs_baseline": 1,
                "changed_vs_baseline": 0,
                "present_in_baseline": 2,
                "unknown_baseline_status": 0,
            },
            "filter_action": "confidence_downgraded",
        }
        rows.append(json.dumps(row, sort_keys=True))
    claims_path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    result = run_matcher_files(
        expectations_path=FIXTURES / "artifact_expectations.jsonl",
        tool_findings_path=Path("detectors/tests/fixtures/tool_findings.jsonl"),
        detection_claims_path=claims_path,
        out_dir=tmp_path / "out",
        time_window_s=30,
    )

    baseline = result["metrics"]["baseline_comparison"]
    coverage = result["metrics"]["source_coverage"]

    assert baseline["available"] is True
    assert baseline["baseline_input"] == "lab-ubuntu-22.04:baseline"
    assert baseline["candidate_downgrades"] == 5
    assert baseline["status_counts"]["present_in_baseline"] == 2
    assert "baseline" not in coverage["available_sources"]


def test_noise_reduction_metrics_use_raw_candidate_and_strong_counts(tmp_path: Path):
    result = run_matcher_files(
        expectations_path=FIXTURES / "artifact_expectations.jsonl",
        tool_findings_path=Path("detectors/tests/fixtures/tool_findings.jsonl"),
        detection_claims_path=FIXTURES / "detection_claims.jsonl",
        out_dir=tmp_path,
        time_window_s=30,
    )

    noise = result["metrics"]["noise_reduction"]

    assert noise["raw_findings_count"] == 10
    assert noise["candidate_claim_count"] == 5
    assert noise["strong_instance_match_count"] == 3
    assert noise["raw_to_candidate_reduction"] == 0.5
    assert noise["raw_to_strong_reconstruction_reduction"] == 0.7


def test_matcher_requires_claims_for_canonical_scoring(tmp_path: Path):
    with pytest.raises(ValueError, match="requires --detection-claims"):
        run_matcher_files(
            expectations_path=FIXTURES / "artifact_expectations.jsonl",
            tool_findings_path=Path("detectors/tests/fixtures/tool_findings.jsonl"),
            detection_claims_path=None,
            out_dir=tmp_path,
            time_window_s=30,
        )


def test_matcher_raw_finding_fallback_is_debug_only(tmp_path: Path):
    result = run_matcher_files(
        expectations_path=FIXTURES / "artifact_expectations.jsonl",
        tool_findings_path=Path("detectors/tests/fixtures/tool_findings.jsonl"),
        detection_claims_path=None,
        out_dir=tmp_path,
        time_window_s=30,
        allow_raw_finding_fallback=True,
    )

    metrics = result["metrics"]
    report = result["report_path"].read_text(encoding="utf-8")
    assert metrics["counts"]["tp"] >= 3
    assert metrics["candidate_input"] == "debug_raw_tool_findings"
    assert metrics["debug_only"] is True
    assert "exclude this report from thesis metric reporting" in report


def test_match_canonical_cli_writes_cached_outputs(tmp_path: Path):
    result = subprocess.run(
        [
            ".venv/bin/python",
            "cli.py",
            "match-canonical",
            "--expectations",
            str(FIXTURES / "artifact_expectations.jsonl"),
            "--tool-findings",
            "detectors/tests/fixtures/tool_findings.jsonl",
            "--detection-claims",
            str(FIXTURES / "detection_claims.jsonl"),
            "--out-dir",
            str(tmp_path),
        ],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    assert (tmp_path / "matches.jsonl").is_file()
    assert (tmp_path / "metrics.json").is_file()
    assert (tmp_path / "score_report.md").is_file()


def test_match_canonical_cli_requires_claims_unless_debug(tmp_path: Path):
    result = subprocess.run(
        [
            ".venv/bin/python",
            "cli.py",
            "match-canonical",
            "--expectations",
            str(FIXTURES / "artifact_expectations.jsonl"),
            "--tool-findings",
            "detectors/tests/fixtures/tool_findings.jsonl",
            "--out-dir",
            str(tmp_path),
        ],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode == 2
    assert "requires --detection-claims" in result.stderr


def test_cli_help_labels_primary_thesis_path():
    result = subprocess.run(
        [".venv/bin/python", "cli.py", "--help"],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    assert "Primary thesis path" in result.stdout
    # Legacy score/pipeline/analyze commands were removed from the CLI surface.
    assert "LEGACY/CALIBRATION" not in result.stdout

    match_help = subprocess.run(
        [".venv/bin/python", "cli.py", "match-canonical", "--help"],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert match_help.returncode == 0, match_help.stderr or match_help.stdout
    assert "--debug-raw-findings" in match_help.stdout
    assert "DEBUG ONLY" in match_help.stdout


def test_detector_layer_does_not_import_matcher():
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [Path("detectors/engine.py"), *Path("detectors/rules").rglob("*.yml")]
    )

    assert "matcher" not in combined
    assert "run_matcher" not in combined
