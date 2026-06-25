import json
import subprocess
from pathlib import Path

import pytest

from matcher.engine import run_matcher_files
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
    assert any(m.match_level == MatchLevel.INSTANCE for m in matches)
    assert any(m.match_level == MatchLevel.CLASS for m in matches)
    assert "# Score Report" in report
    assert "Per Artifact Class" in report


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


def test_cli_help_labels_primary_and_legacy_paths():
    result = subprocess.run(
        [".venv/bin/python", "cli.py", "--help"],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    assert "Primary thesis path" in result.stdout
    assert "LEGACY/CALIBRATION" in result.stdout

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
