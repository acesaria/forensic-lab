# Phase 7.5 end-to-end smoke test over the deterministic core: raw outputs ->
# detect -> match -> metrics, asserting a well-formed metrics.csv row with the
# Phase 2.4 columns. No live tools or images required.

import csv
from pathlib import Path

from orchestrator.evaluation.contracts.models import GtManifest
from orchestrator.evaluation.metrics.compute import METRICS_COLS
from orchestrator.evaluation.pipeline import run_from_raw, run_score


def _manifest() -> GtManifest:
    return GtManifest.from_dict(
        {
            "scenario_id": "smoke",
            "run_id": "smoke-run",
            "distro": "ubuntu-22.04",
            "cleanup": False,
            "events": [
                {
                    "gt_id": "G1",
                    "ts_utc": "2026-06-10T10:00:00.000Z",
                    "technique": "T1059.004",
                    "event_class": "file_created",
                    "entity": {"type": "path", "value": "/tmp/.payload.sh"},
                },
                {
                    "gt_id": "G2",
                    "ts_utc": "2026-06-10T10:00:05.000Z",
                    "technique": "T1071.001",
                    "event_class": "network_connection",
                    "entity": {"type": "socket", "value": "8.8.8.8:443"},
                },
            ],
        }
    )


def test_run_from_raw_writes_metrics(tmp_path: Path):
    # crtime within the case window; an external socket; a deleted temp file.
    raw = {
        "tsk": {
            "bodyfile": "\n".join(
                [
                    "0|/tmp/.payload.sh|55|r/rrwxr-xr-x|0|0|40|1781085600|1781085600|1781085600|1781085600",
                ]
            )
        },
        "vol3": {
            "linux.pslist": [],
            "linux.sockstat": [{"PID": 9, "ForeignAddr": "8.8.8.8", "ForeignPort": 443}],
        },
        "plaso": [],
    }
    case_window = {"start": "2026-06-10T09:00:00.000Z", "end": "2026-06-10T11:00:00.000Z"}
    row = run_from_raw(
        _manifest(), raw, tmp_path, case_window=case_window, legacy=True
    )
    # findings, matches, metrics, report, legacy all written.
    assert (tmp_path / "findings.jsonl").is_file()
    assert (tmp_path / "matches.json").is_file()
    assert (tmp_path / "report.md").is_file()
    assert (tmp_path / "metrics_legacy.csv").is_file()

    metrics_csv = tmp_path / "metrics.csv"
    assert metrics_csv.is_file()
    with metrics_csv.open() as fh:
        reader = csv.reader(fh)
        header = next(reader)
        data = next(reader)
    assert tuple(header) == METRICS_COLS
    assert len(data) == len(METRICS_COLS)

    # The external socket (vol3, ts_quality none) should match G2; the temp exec
    # (tsk, wallclock) should match G1. Both GT events recovered.
    assert row.values["gt_n"] == 2
    assert row.values["tp"] == 2
    assert row.values["recall"] == 1.0


def test_run_score_matches_run_from_raw_counts(tmp_path: Path):
    # Sanity: scoring prebuilt findings produces a consistent metrics row.
    from orchestrator.evaluation.detect.run import run_detection, write_findings
    from orchestrator.evaluation.pipeline import build_rules_config, load_pipeline_config

    raw = {"tsk": {"bodyfile": "0|/tmp/.payload.sh|1|r/rrwxr-xr-x|0|0|1|1781085600|1781085600|1781085600|1781085600"}}
    cfg = build_rules_config(load_pipeline_config(), case_window={
        "start": "2026-06-10T09:00:00.000Z", "end": "2026-06-10T11:00:00.000Z"})
    findings = run_detection(raw, cfg)
    fpath = write_findings(findings, tmp_path / "findings.jsonl")

    import json
    mpath = tmp_path / "gt_manifest.json"
    mpath.write_text(json.dumps(_manifest().to_dict()), encoding="utf-8")

    row = run_score(mpath, fpath, tmp_path / "out")
    assert row.values["gt_n"] == 2
    assert row.values["tp"] >= 1
