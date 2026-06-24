from pathlib import Path

import yaml

from orchestrator.canonical.legacy import write_canonical_from_legacy
from orchestrator.attacks import art_calibration
from orchestrator.evaluation.scenario.manifest import GtManifestBuilder


def test_art_calibration_selected_tests_are_small_and_recordable():
    data = art_calibration._load_selected_tests()
    tests = data["tests"]

    assert 3 <= len(tests) <= 5
    assert {test["technique"] for test in tests} == {
        "T1059.004",
        "T1105",
        "T1070.004",
    }

    for test in tests:
        assert test["guid"]
        assert test["calibration_goal"]
        truth = test["truth"]
        assert truth["event_class"] in {
            "file_created",
            "file_deleted",
            "file_modified",
            "process_exec",
            "persistence_installed",
            "network_connection",
            "auth_login",
            "log_tampering",
            "history_cleared",
        }
        assert truth["entity_type"]
        assert truth["entity_value"]
        assert truth["observables"]


def test_art_catalog_declares_calibration_layer_scope():
    catalog = yaml.safe_load(Path("attacks/art/catalog.lock.yml").read_text())

    assert catalog["scope"]["role"] == "calibration-layer"
    assert catalog["scope"]["full_corpus_required"] is False
    assert catalog["source"]["repository"] == "https://github.com/redcanaryco/atomic-red-team"
    assert catalog["version"]["commit"]


def test_art_calibration_truth_can_emit_canonical_files(tmp_path: Path):
    data = art_calibration._load_selected_tests()
    builder = GtManifestBuilder(
        "art_calibration",
        "art-calibration-test",
        "ubuntu-22.04",
        seed=0,
        cleanup=False,
    )
    for test in data["tests"]:
        art_calibration._record_truth(builder, test["id"], test)

    manifest = tmp_path / "gt_manifest.json"
    builder.write(manifest)
    out = write_canonical_from_legacy(manifest, tmp_path, repo_root=Path.cwd())

    assert out["execution_truth"].is_file()
    assert out["artifact_expectations"].is_file()
    assert out["reference_context"].is_file()
