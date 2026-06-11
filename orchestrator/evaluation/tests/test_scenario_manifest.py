# Phase 2.1: the scenario manifest builder emits a schema-valid manifest with
# exact timestamps, and parameter randomization is seed-reproducible but
# seed-sensitive (the anti-circularity guarantee).

from orchestrator.evaluation.contracts.validate import validate_gt_manifest
from orchestrator.evaluation.scenario.manifest import GtManifestBuilder, ScenarioParams


def test_params_reproducible_and_seed_sensitive():
    a = ScenarioParams(42)
    b = ScenarioParams(42)
    c = ScenarioParams(43)
    assert a.basename(ext=".so") == b.basename(ext=".so")
    # Fresh RNGs at the same seed agree; a different seed diverges.
    assert ScenarioParams(42).port() == ScenarioParams(42).port()
    assert ScenarioParams(42).token() != ScenarioParams(43).token()
    assert c.token() != ScenarioParams(42).token()


def test_builder_emits_valid_manifest(tmp_path):
    b = GtManifestBuilder("s01", "run-1", "ubuntu-22.04", seed=7, cleanup=True)
    b.record(
        technique="T1574.006",
        event_class="file_created",
        entity_type="path",
        entity_value=f"/tmp/{b.params.token()}.so",
        expected_sources=["disk_fs", "memory"],
    )
    b.record(
        technique="T1071.001",
        event_class="network_connection",
        entity_type="socket",
        entity_value=f"127.0.0.1:{b.params.port()}",
    )
    manifest = b.to_manifest()
    assert [e.gt_id for e in manifest.events] == ["G1", "G2"]
    assert manifest.random_seed == 7
    assert manifest.cleanup is True
    obj = manifest.to_dict()
    validate_gt_manifest(obj)  # raises on malformed
    # every event carries an ISO-8601 UTC ms timestamp
    for e in manifest.events:
        assert e.ts_utc.endswith("Z") and "." in e.ts_utc

    out = b.write(tmp_path / "gt_manifest.json")
    assert out.is_file()
