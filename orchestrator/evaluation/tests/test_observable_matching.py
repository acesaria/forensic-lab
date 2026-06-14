# Observable-driven matching + per-operation/source/layer metrics.
#
# A cluster matches a GtEvent through any of the event's observables (operation +
# source_tool + entity), not only the canonical entity. Events without declared
# observables fall back to the canonical entity, so older manifests are unchanged
# (covered by the golden fixtures); these tests exercise the new path.

from pathlib import Path

from orchestrator.evaluation.contracts.models import (
    Entity,
    Finding,
    GtEvent,
    GtManifest,
    Observable,
)
from orchestrator.evaluation.contracts.validate import load_findings, load_gt_manifest
from orchestrator.evaluation.match.matcher import match
from orchestrator.evaluation.metrics.compute import compute_breakdown, compute_row

_CFG = {
    "tolerance_s": 60,
    "dedup_bucket_s": 60,
    "scope_margin_s": 1800,
    "corroboration_window_s": 120,
    "known_good": [],
    "entity": {"path_basename_fallback": False, "process_arg_prefix": True},
    "equivalence": {
        "process_exec": ["process_exec"],
        "network_connection": ["network_connection"],
    },
}


def _finding(fid, tool, cls, etype, eval_, op, ts=None):
    return Finding(
        finding_id=fid,
        source_tool=tool,
        detector=f"{tool}:x",
        rule_layer="community",
        event_class=cls,
        ts_quality="wallclock" if ts else "none",
        entity=Entity(type=etype, value=eval_),
        technique=None,
        ts_utc=ts,
        forensic_operation=op,
    )


def _event_with_observable():
    # Canonical entity is a path that no finding carries; the only way to match is
    # through the memory_analysis/vol3 observable on a process entity.
    return GtEvent(
        gt_id="G1",
        ts_utc="2026-06-13T12:00:00.000Z",
        technique="T1059.004",
        event_class="process_exec",
        entity=Entity(type="path", value="/tmp/never_seen.bin"),
        observables=[
            Observable(
                operation="memory_analysis",
                source_tool="vol3",
                entity_type="process",
                entity_value="evilproc",
            )
        ],
    )


def test_cluster_matches_via_observable_not_canonical_entity():
    manifest = GtManifest("s", "r", "ubuntu-22.04", events=[_event_with_observable()])
    findings = [_finding("f-000001", "vol3", "process_exec", "process", "evilproc", "memory_analysis")]
    m = match(manifest, findings, config=_CFG)
    assert [r["gt_id"] for r in m.tp] == ["G1"]
    assert m.fn == []
    assert m.tp[0]["finding_ids"] == ["f-000001"]


def test_observable_source_tool_is_enforced():
    # Same entity/operation but a different source_tool must NOT satisfy a vol3
    # observable; the event goes unmatched and the finding is a false positive.
    manifest = GtManifest("s", "r", "ubuntu-22.04", events=[_event_with_observable()])
    findings = [_finding("f-000001", "tsk", "process_exec", "process", "evilproc", "memory_analysis")]
    m = match(manifest, findings, config=_CFG)
    assert m.fn == ["G1"]
    assert {fid for r in m.fp for fid in r["finding_ids"]} == {"f-000001"}


def test_observable_operation_is_enforced():
    # Wrong operation (timeline vs the observable's memory_analysis) is ineligible.
    manifest = GtManifest("s", "r", "ubuntu-22.04", events=[_event_with_observable()])
    findings = [_finding("f-000001", "vol3", "process_exec", "process", "evilproc", "timeline")]
    m = match(manifest, findings, config=_CFG)
    assert m.fn == ["G1"]


_FIX = Path(__file__).parent / "fixtures" / "scenario_01"


def _load_scenario_01():
    manifest = GtManifest.from_dict(load_gt_manifest(_FIX / "gt_manifest.json"))
    findings = [Finding.from_dict(d) for d in load_findings(_FIX / "findings.jsonl")]
    return manifest, findings


def test_scenario_01_breakdown_has_per_operation_rows():
    manifest, findings = _load_scenario_01()
    m = match(manifest, findings)
    rows = {(_["forensic_operation"], _["source_tool"], _["rule_layer"]): _
            for _ in (r.values for r in compute_breakdown(manifest, m, findings))}

    # vol3 memory_analysis uniquely covers the two memory-only events (G4, G5).
    mem = rows[("memory_analysis", "vol3", "community")]
    assert mem["tp"] == 2 and mem["fp"] == 0
    assert mem["precision"] == 1.0 and mem["recall"] == 1.0

    # tsk timeline (community) covers G1, G2, G3, G6.
    tsk = rows[("timeline", "tsk", "community")]
    assert tsk["tp"] == 4 and tsk["fp"] == 0


def test_scenario_01_micro_matches_global_standard_metrics():
    manifest, findings = _load_scenario_01()
    m = match(manifest, findings)
    micro = next(
        r.values for r in compute_breakdown(manifest, m, findings)
        if r.values["forensic_operation"] == "__micro__"
    )
    row = compute_row(manifest, m).values
    # Global standard definitions: precision = tp/(tp+fp), recall = tp/n.
    assert micro["tp"] == row["tp"] and micro["fp"] == row["fp"] and micro["fn"] == row["fn"]
    assert micro["precision"] == row["precision"] == 1.0
    assert micro["recall"] == row["recall"] == 1.0
