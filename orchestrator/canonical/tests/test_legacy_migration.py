import json
from pathlib import Path

from orchestrator.canonical import ArtifactExpectation, GroundTruthEvent, load_jsonl
from orchestrator.canonical.legacy import write_canonical_from_legacy


def test_legacy_gt_manifest_writes_three_canonical_files(tmp_path: Path):
    gt_manifest = {
        "scenario_id": "scenario_01",
        "run_id": "run-1",
        "distro": "ubuntu-22.04",
        "cleanup": False,
        "random_seed": 7,
        "timezone": "UTC",
        "events": [
            {
                "gt_id": "G1",
                "ts_utc": "2026-06-18T10:00:00.000Z",
                "technique": "T1574.006",
                "event_class": "file_created",
                "entity": {"type": "path", "value": "/tmp/payload.so"},
                "details": {"step": "compile_payload"},
                "expected_sources": ["disk_fs"],
                "observables": [
                    {
                        "operation": "timeline",
                        "source_tool": "tsk",
                        "entity_type": "path",
                        "entity_value": "/tmp/payload.so",
                    }
                ],
            }
        ],
    }
    acquisition = {
        "run_id": "run-1",
        "scenario_id": "scenario_01",
        "created_at": 1.0,
        "disk_acquisition_mode": "offline",
        "disk_preparation": "powered_off",
        "memory_image": {
            "path": "/tmp/mem.raw",
            "tool": "virsh",
            "sha256": "sha256:mem",
            "size_bytes": 10,
        },
        "disk_image": {
            "path": "/tmp/disk.E01",
            "tool": "ewfacquire",
            "sha256": "sha256:disk",
            "size_bytes": 20,
        },
    }
    gt_path = tmp_path / "gt_manifest.json"
    acq_path = tmp_path / "manifest.json"
    gt_path.write_text(json.dumps(gt_manifest), encoding="utf-8")
    acq_path.write_text(json.dumps(acquisition), encoding="utf-8")

    paths = write_canonical_from_legacy(
        gt_path,
        tmp_path,
        acquisition_manifest_path=acq_path,
        repo_root=Path.cwd(),
        tool_versions={"volatility3": "2.7.0"},
    )

    assert paths["execution_truth"].name == "execution_truth.jsonl"
    assert paths["artifact_expectations"].name == "artifact_expectations.jsonl"
    assert paths["reference_context"].name == "reference_context.json"

    truth = load_jsonl(tmp_path / "execution_truth.jsonl", GroundTruthEvent)
    expectations = load_jsonl(
        tmp_path / "artifact_expectations.jsonl",
        ArtifactExpectation,
    )
    context = json.loads((tmp_path / "reference_context.json").read_text())

    assert truth[0].step_id == "compile_payload"
    assert truth[0].object_identity == "/tmp/payload.so"
    assert expectations[0].instance_constraints["source_tool"] == "tsk"
    assert context["guest"]["distro"] == "ubuntu-22.04"
    assert context["acquisition"]["method"] == "offline"
    assert context["acquisition"]["memory_image"]["sha256"] == "sha256:mem"
    assert context["tool_versions"]["volatility3"] == "2.7.0"
