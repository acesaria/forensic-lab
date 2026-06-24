# Calibration GT for the two scenario_01 variants: the cleanup variant keeps the
# same events but prunes the observables the attacker's cleanup destroys, so it is
# strictly harder than the no-cleanup variant.

from pathlib import Path

from orchestrator.evaluation.contracts.models import Finding, GtManifest
from orchestrator.evaluation.contracts.validate import (
    load_findings,
    load_gt_manifest,
    validate_gt_manifest,
)
from orchestrator.evaluation.match.matcher import match
from orchestrator.evaluation.metrics.compute import compute_row
from orchestrator.evaluation.scenario.scenario_01 import (
    SCENARIO_CLEANUP,
    SCENARIO_NOCLEANUP,
    build_calibration_manifest,
)

_FIX = Path(__file__).parent / "fixtures"


def test_both_variants_build_and_validate():
    nocleanup = build_calibration_manifest(cleanup=False)
    cleanup = build_calibration_manifest(cleanup=True)
    assert nocleanup.scenario_id == SCENARIO_NOCLEANUP
    assert cleanup.scenario_id == SCENARIO_CLEANUP
    validate_gt_manifest(nocleanup.to_dict())
    validate_gt_manifest(cleanup.to_dict())


def test_cleanup_prunes_observables_per_event():
    nocleanup = {e.gt_id: e for e in build_calibration_manifest(cleanup=False).events}
    cleanup = {e.gt_id: e for e in build_calibration_manifest(cleanup=True).events}
    assert nocleanup.keys() == cleanup.keys()  # same events
    # Every event has at least one observable in both variants, and cleanup never
    # has MORE observables than no-cleanup; at least one event has strictly fewer.
    assert all(e.observables for e in cleanup.values())
    assert all(
        len(cleanup[k].observables) <= len(nocleanup[k].observables) for k in nocleanup
    )
    assert any(
        len(cleanup[k].observables) < len(nocleanup[k].observables) for k in nocleanup
    )


def _score(variant: str):
    fx = _FIX / variant
    m = GtManifest.from_dict(load_gt_manifest(fx / "gt_manifest.json"))
    findings = [Finding.from_dict(d) for d in load_findings(fx / "findings.jsonl")]
    return compute_row(m, match(m, findings)).values, match(m, findings)


def test_cleanup_fixture_is_harder_than_nocleanup():
    nc, _ = _score("scenario_01")
    cl, cl_m = _score("scenario_01_cleanup")
    # No-cleanup recovers everything; cleanup loses the deleted disk artifacts.
    assert nc["recall"] == 1.0 and nc["fn"] == 0
    assert cl["recall"] < nc["recall"]
    assert cl["fn"] > 0
    # The discovery output and the on-disk .so are the cleaned-away events.
    assert set(cl_m.fn) == {"G1", "G3"}


def test_cleanup_fixture_validates():
    validate_gt_manifest(load_gt_manifest(_FIX / "scenario_01_cleanup" / "gt_manifest.json"))
    load_findings(_FIX / "scenario_01_cleanup" / "findings.jsonl")
