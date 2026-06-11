# Phase 7.4 schema validation: the JSON Schemas accept the well-formed fixtures
# and reject malformed artifacts at the stage boundary.

from pathlib import Path

import pytest

from orchestrator.evaluation.contracts.models import Finding, GtManifest
from orchestrator.evaluation.contracts.validate import (
    load_findings,
    load_gt_manifest,
    validate_finding,
    validate_gt_manifest,
    validate_matches,
)
from orchestrator.evaluation.match.matcher import match

try:
    import jsonschema

    _ValidationError = jsonschema.ValidationError
except ImportError:  # pragma: no cover
    _ValidationError = Exception

_FIX = Path(__file__).parent / "fixtures"


def test_fixtures_validate():
    load_gt_manifest(_FIX / "gt_manifest.json")
    load_findings(_FIX / "findings.jsonl")


def test_matches_validates():
    manifest = GtManifest.from_dict(load_gt_manifest(_FIX / "gt_manifest.json"))
    findings = [Finding.from_dict(d) for d in load_findings(_FIX / "findings.jsonl")]
    validate_matches(match(manifest, findings).to_dict())


def test_bad_event_class_rejected():
    bad = {
        "scenario_id": "x",
        "run_id": "r",
        "distro": "d",
        "events": [
            {
                "gt_id": "G1",
                "ts_utc": "2026-06-10T10:00:00.000Z",
                "technique": "T1059",
                "event_class": "not_a_class",
                "entity": {"type": "path", "value": "/tmp/x"},
            }
        ],
    }
    with pytest.raises(_ValidationError):
        validate_gt_manifest(bad)


def test_bad_ts_quality_rejected():
    bad = {
        "finding_id": "f1",
        "source_tool": "tsk",
        "detector": "d",
        "rule_layer": "community",
        "event_class": "file_created",
        "ts_quality": "approximate",
        "entity": {"type": "path", "value": "/tmp/x"},
    }
    with pytest.raises(_ValidationError):
        validate_finding(bad)


def test_bad_timestamp_format_rejected():
    bad = {
        "scenario_id": "x",
        "run_id": "r",
        "distro": "d",
        "events": [
            {
                "gt_id": "G1",
                "ts_utc": "2026-06-10 10:00:00",
                "technique": "T1059",
                "event_class": "file_created",
                "entity": {"type": "path", "value": "/tmp/x"},
            }
        ],
    }
    with pytest.raises(_ValidationError):
        validate_gt_manifest(bad)
