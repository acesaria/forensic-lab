# Observables + forensic_operation layer: a GT event may carry several
# observables (one per acceptable evidentiary locus) and every finding is tagged
# with the forensic operation that produced it. Old manifests/findings without
# the new fields still validate and round-trip.

from orchestrator.evaluation.contracts.models import Finding, GtManifest, Observable
from orchestrator.evaluation.contracts.validate import (
    validate_finding,
    validate_gt_manifest,
)
from orchestrator.evaluation.detect.base import make_finding
from orchestrator.evaluation.scenario.manifest import GtManifestBuilder


def test_event_observables_round_trip_and_validate():
    b = GtManifestBuilder("s01", "run-1", "ubuntu-22.04", seed=7)
    ev = b.record(
        technique="T1574.006",
        event_class="file_created",
        entity_type="path",
        entity_value=f"/etc/{b.params.token()}.so",
        observables=[
            {
                "operation": "timeline",
                "source_tool": "tsk",
                "entity_type": "path",
                "entity_value": "/etc/ld.so.preload",
                "time_hint": {"kind": "window", "window_s": 5},
            },
            {
                "operation": "memory_analysis",
                "source_tool": "vol3",
                "entity_type": "mapping",
                "entity_value": "libprocesshider.so",
            },
        ],
    )
    assert len(ev.observables) == 2
    assert all(isinstance(o, Observable) for o in ev.observables)

    obj = b.to_manifest().to_dict()
    validate_gt_manifest(obj)  # raises on malformed

    back = GtManifest.from_dict(obj)
    assert back.events[0].observables[0].source_tool == "tsk"
    assert back.events[0].observables[0].time_hint == {"kind": "window", "window_s": 5}
    assert back.events[0].observables[1].operation == "memory_analysis"


def test_event_without_observables_defaults_empty():
    # Manifests authored before this layer omit "observables" entirely.
    legacy = {
        "scenario_id": "x",
        "run_id": "r",
        "distro": "ubuntu-22.04",
        "events": [
            {
                "gt_id": "G1",
                "ts_utc": "2026-06-10T10:00:00.000Z",
                "technique": "T1059",
                "event_class": "file_created",
                "entity": {"type": "path", "value": "/tmp/x"},
            }
        ],
    }
    validate_gt_manifest(legacy)
    m = GtManifest.from_dict(legacy)
    assert m.events[0].observables == []


def test_finding_carries_forensic_operation():
    f = make_finding(
        source_tool="vol3",
        detector="vol3:hidden_process",
        event_class="process_exec",
        entity_type="process",
        entity_value="evil",
        ts_quality="none",
        forensic_operation="memory_analysis",
    )
    d = f.to_dict()
    assert d["forensic_operation"] == "memory_analysis"
    validate_finding({**d, "finding_id": "f-000000"})


def test_make_finding_rejects_unknown_operation():
    import pytest

    with pytest.raises(ValueError):
        make_finding(
            source_tool="vol3",
            detector="d",
            event_class="process_exec",
            entity_type="process",
            entity_value="x",
            ts_quality="none",
            forensic_operation="not_an_operation",
        )


def test_legacy_finding_without_operation_defaults_timeline():
    legacy = {
        "finding_id": "f-000001",
        "source_tool": "tsk",
        "detector": "d",
        "rule_layer": "community",
        "event_class": "file_created",
        "ts_quality": "wallclock",
        "entity": {"type": "path", "value": "/tmp/x"},
    }
    validate_finding(legacy)  # old findings still pass the schema
    assert Finding.from_dict(legacy).forensic_operation == "timeline"
