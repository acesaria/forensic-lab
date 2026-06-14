# orchestrator/evaluation/pipeline.py
#
# Wires the GT-blind detect layer to the GT-aware match + metrics layers. This
# is the seam where the two halves meet: detect() never sees ground truth, then
# match()/metrics() bring it in. Two entry points:
#   run_from_raw   raw_outputs -> findings -> matches -> metrics (+ report)
#   run_score      existing findings.jsonl + manifest -> matches -> metrics
# Both validate every artifact at the stage boundary and write deterministically.

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from orchestrator.evaluation.contracts.models import Finding, GtManifest, Matches
from orchestrator.evaluation.contracts.validate import (
    load_findings,
    load_gt_manifest,
    validate_finding,
    validate_matches,
)
from orchestrator.evaluation.detect.run import run_detection, write_findings
from orchestrator.evaluation.match.matcher import hash_matching_config, match, write_matches
from orchestrator.evaluation.metrics.compute import (
    MetricRow,
    compute_breakdown,
    compute_recovery_breakdown,
    compute_row,
    write_breakdown_csv,
    write_metrics_csv,
    write_recovery_csv,
)
from orchestrator.evaluation.metrics.legacy import write_legacy_csv
from orchestrator.evaluation.metrics.report import render_report, write_report

_PKG_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _PKG_DIR.parent.parent


def load_pipeline_config(path: str | Path | None = None) -> dict[str, Any]:
    p = Path(path) if path else _PKG_DIR / "config" / "pipeline.yaml"
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def build_rules_config(
    pipeline_cfg: dict[str, Any],
    *,
    repo_root: Path = _REPO_ROOT,
    case_window: dict[str, str] | None = None,
) -> dict[str, Any]:
    rs = pipeline_cfg.get("rulesets", {})
    detect_cfg = pipeline_cfg.get("detect", {})
    sigma_dirs = [
        str((repo_root / d).resolve()) for d in rs.get("sigma_rule_dirs", [])
    ]
    # Vendored SigmaHQ subset for the plaso_sigma detector (defaults applied by
    # the runner when not listed here).
    sigma_vendored = [
        str((repo_root / d).resolve())
        for d in rs.get("sigma_vendored_dirs", ["vendor/sigma/rules/linux"])
    ]
    cfg: dict[str, Any] = {
        "sigma_rule_dirs": sigma_dirs,
        "sigma_vendored_dirs": sigma_vendored,
        "vol3": detect_cfg.get("vol3", {}),
    }
    if case_window:
        cfg["case_window"] = case_window
    return cfg


def ruleset_hash(pipeline_cfg: dict[str, Any], repo_root: Path = _REPO_ROOT) -> str:
    # Stable hash over every rule file the detectors load, plus the pinned refs,
    # so a rule change is visible in matches.json / metrics.
    import hashlib

    rs = pipeline_cfg.get("rulesets", {})
    h = hashlib.sha256()
    h.update(str(rs.get("sigma_ref", "")).encode())
    files: list[Path] = []
    rule_dirs = list(rs.get("sigma_rule_dirs", [])) + list(rs.get("sigma_vendored_dirs", []))
    yara_dir = rs.get("yara_rules_dir")
    if yara_dir:
        rule_dirs.append(yara_dir)
    for d in rule_dirs:
        base = (repo_root / d)
        if base.is_dir():
            files.extend(sorted(base.rglob("*.yml")))
            files.extend(sorted(base.rglob("*.yaml")))
            files.extend(sorted(base.rglob("*.yar")))
            files.extend(sorted(base.rglob("*.yara")))
            commit = base.parent / "COMMIT.txt"  # pin file for vendored trees
            if commit.is_file():
                files.append(commit)
    for f in rs.get("tagging_files", []):
        p = repo_root / f
        if p.is_file():
            files.append(p)
    for f in sorted(set(files)):
        h.update(f.read_bytes())
    return "sha256:" + h.hexdigest()


def _write_outputs(
    manifest: GtManifest,
    findings: list[Finding],
    matches: Matches,
    out_dir: Path,
    *,
    legacy: bool,
    matching_config_path: str | Path | None,
) -> MetricRow:
    validate_matches(matches.to_dict())
    write_matches(matches, out_dir / "matches.json")
    row = compute_row(manifest, matches)
    write_metrics_csv([row], out_dir / "metrics.csv")
    write_breakdown_csv(
        compute_breakdown(manifest, matches, findings),
        out_dir / "metrics_by_operation.csv",
    )
    recovery_rows = compute_recovery_breakdown(findings)
    if recovery_rows:
        write_recovery_csv(recovery_rows, out_dir / "metrics_recovery.csv")
    report_text = render_report(
        manifest, matches, findings, row=row, config_path=matching_config_path
    )
    write_report(report_text, out_dir / "report.md")
    if legacy:
        write_legacy_csv([row], out_dir / "metrics_legacy.csv")
    return row


def run_from_raw(
    manifest: GtManifest,
    raw_outputs: dict[str, Any],
    out_dir: str | Path,
    *,
    pipeline_cfg: dict[str, Any] | None = None,
    matching_config_path: str | Path | None = None,
    case_window: dict[str, str] | None = None,
    legacy: bool = False,
) -> MetricRow:
    out = Path(out_dir)
    pipeline_cfg = pipeline_cfg or load_pipeline_config()
    rules_config = build_rules_config(pipeline_cfg, case_window=case_window)

    findings = run_detection(raw_outputs, rules_config)
    for f in findings:
        validate_finding(f.to_dict())
    write_findings(findings, out / "findings.jsonl")

    rs_hash = ruleset_hash(pipeline_cfg)
    matches = match(
        manifest,
        findings,
        config_path=matching_config_path,
        ruleset_hash=rs_hash,
    )
    return _write_outputs(
        manifest,
        findings,
        matches,
        out,
        legacy=legacy,
        matching_config_path=matching_config_path,
    )


def run_score(
    manifest_path: str | Path,
    findings_path: str | Path,
    out_dir: str | Path,
    *,
    matching_config_path: str | Path | None = None,
    ruleset_hash_value: str = "sha256:0",
    legacy: bool = False,
) -> MetricRow:
    out = Path(out_dir)
    manifest = GtManifest.from_dict(load_gt_manifest(manifest_path))
    findings = [Finding.from_dict(d) for d in load_findings(findings_path)]
    matches = match(
        manifest,
        findings,
        config_path=matching_config_path,
        ruleset_hash=ruleset_hash_value,
    )
    return _write_outputs(
        manifest,
        findings,
        matches,
        out,
        legacy=legacy,
        matching_config_path=matching_config_path,
    )
