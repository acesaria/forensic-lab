"""Pins the §10 guardrails the v2 matcher violated: many-to-one collection,
closed identity (no basename), identity regardless of ATT&CK, scored-only
denominators, corroboration across sources."""

from pathlib import Path

from matcher.engine import run_matcher
from orchestrator.canonical import (
    ArtifactExpectation,
    DetectionClaim,
    EvidenceSource,
    GroundTruthEvent,
    ToolFinding,
)


def _exp(ae_id: str, artifact_class: str, constraints: dict, *, scored: bool = True, attck=("T1574.006",)):
    return ArtifactExpectation(
        ae_id=ae_id,
        scenario_id="s",
        step_id="S1",
        artifact_class=artifact_class,
        source_eligibility=[EvidenceSource.DISK, EvidenceSource.TIMELINE],
        instance_constraints=constraints,
        attck=list(attck),
        required_for_scoring=scored,
    )


def _finding(fid: str, source: EvidenceSource, path: str, time: str | None = None):
    return ToolFinding(
        finding_id=fid,
        run_id="run-1",
        tool="t",
        tool_version="1",
        adapter_version="v1",
        source_type=source,
        artifact_class="file",
        entity={"type": "path", "value": path},
        time=time,
        raw_ref=fid,
        provenance={},
    )


def _claim(cid: str, path: str, source_findings: list[str], attck: list[str]):
    return DetectionClaim(
        claim_id=cid,
        run_id="run-1",
        rule_id=f"rule.{cid}",
        artifact_class="shared_object",
        entity={"type": "path", "value": path},
        source_findings=source_findings,
        attck=attck,
    )


def test_many_to_one_identity_and_scored_denominators(tmp_path: Path):
    expectations = [
        # Same object pinned by two expectations: one claim must match BOTH
        # (many-to-one, nothing consumed).
        _exp("AE-built", "shared_object", {"path": "/tmp/x/rk.so"}),
        _exp("AE-file", "file", {"path": "/tmp/x/rk.so"}),
        # Same basename, different directory: never identity; empty attck on
        # the expectation also blocks class support => missed.
        _exp("AE-other", "shared_object", {"path": "/opt/rk.so"}, attck=()),
        # Contextual: listed, never in denominators.
        _exp("AE-ctx", "file", {"path": "/tmp/x/rk.so"}, scored=False),
    ]
    findings = [
        _finding("tf-1", EvidenceSource.DISK, "/tmp/x/rk.so"),
        _finding("tf-2", EvidenceSource.TIMELINE, "/tmp/x/rk.so"),
    ]
    claims = [
        # Disjoint ATT&CK from the expectations: exact identity still wins (§10.4).
        _claim("c-disk", "/tmp/x/rk.so", ["tf-1"], ["T9999"]),
        _claim("c-timeline", "/tmp/x/rk.so", ["tf-2"], ["T1574.006"]),
        _claim("c-residual", "/var/unrelated.so", [], ["T1574.006"]),
    ]

    result = run_matcher(expectations, findings, claims, out_dir=tmp_path)
    rows = {r["ae_id"]: r for r in result["outcomes"]}

    assert rows["AE-built"]["outcome"] == "identified"
    assert rows["AE-file"]["outcome"] == "identified"
    assert rows["AE-built"]["matched_claims"] == ["c-disk", "c-timeline"]
    assert rows["AE-file"]["matched_claims"] == ["c-disk", "c-timeline"]  # not consumed
    assert rows["AE-built"]["sources"] == ["disk", "timeline"]
    assert rows["AE-other"]["outcome"] == "missed"  # basename is not identity
    assert rows["AE-other"]["funnel_gap"] == "acquisition_gap"
    assert rows["AE-ctx"]["outcome"] == "contextual"

    metrics = result["metrics"]
    assert metrics["expectations"] == {"scored": 3, "contextual": 1}
    assert metrics["coverage"]["identified"] == 2
    assert metrics["coverage"]["missed"] == 1
    assert metrics["sources"]["corroboration_rate"] == 1.0
    assert metrics["triage"]["residual_claims_per_rule"] == {"rule.c-residual": 1}
    assert metrics["triage"]["baseline_filter"] is None  # no baseline supplied
    # No detection-theoretic vocabulary anywhere in the output (§10.3).
    flat = str(metrics)
    assert "precision" not in flat and "f1" not in flat and "fp" not in flat
    assert (tmp_path / "outcomes.jsonl").is_file()
    assert (tmp_path / "metrics.json").is_file()
    assert (tmp_path / "report.md").is_file()


def test_baseline_filter_stats_pass_through_to_triage_block(tmp_path: Path):
    stats = {
        "identity": "lab-test:baseline",
        "per_source": {"disk": {"pre": 10, "post": 2}},
    }

    result = run_matcher([], [], [], out_dir=tmp_path, baseline_filter=stats)

    assert result["metrics"]["triage"]["baseline_filter"] == stats
    assert "lab-test:baseline" in (tmp_path / "report.md").read_text()


def test_stale_baseline_filter_stats_are_flagged(tmp_path: Path):
    stats = {
        "identity": "lab-test:baseline",
        "per_source": {"disk": {"pre": 2, "post": 1}},
    }
    findings = [_finding("tf-1", EvidenceSource.DISK, "/tmp/x/rk.so")]

    result = run_matcher([], findings, [], out_dir=tmp_path, baseline_filter=stats)

    warning = result["metrics"]["triage"]["baseline_filter_warning"]
    assert warning == "baseline_filter pre-total (2) != raw findings (1)"
    assert result["metrics"]["triage"]["baseline_filter"] == stats
    assert f"- clean-baseline warning: {warning}" in (tmp_path / "report.md").read_text()


def test_temporal_offset_only_from_identity_matching_truth_event(tmp_path: Path):
    # §6.D: GT action time is taken only from a truth event describing the
    # same object; a same-step event about a different object supplies nothing.
    expectations = [
        _exp("AE-lib", "file", {"path": "/tmp/x/rk.so"}),
        _exp("AE-cfg", "file", {"path": "/etc/ld.so.preload"}),
    ]
    findings = [
        _finding("tf-1", EvidenceSource.DISK, "/tmp/x/rk.so", time="2026-07-03T10:00:05.000Z"),
        _finding("tf-2", EvidenceSource.DISK, "/etc/ld.so.preload", time="2026-07-03T10:00:07.000Z"),
    ]
    claims = [
        _claim("c-lib", "/tmp/x/rk.so", ["tf-1"], ["T1574.006"]),
        _claim("c-cfg", "/etc/ld.so.preload", ["tf-2"], ["T1574.006"]),
    ]
    truth = [
        # Same step (S1) as both expectations; identity matches only AE-lib.
        GroundTruthEvent(
            run_id="run-1",
            scenario_id="s",
            step_id="S1",
            event_type="artifact_created",
            object_type="path",
            object_identity="/tmp/x/rk.so",
            action="create",
            actor="scenario",
            time="2026-07-03T10:00:00.000Z",
            evidence_basis=[EvidenceSource.DISK],
            attck=["T1574.006"],
        ),
    ]

    result = run_matcher(expectations, findings, claims, truth, out_dir=tmp_path)
    rows = {r["ae_id"]: r for r in result["outcomes"]}

    assert rows["AE-lib"]["outcome"] == "identified"
    assert rows["AE-lib"]["gt_time"] == "2026-07-03T10:00:00.000Z"
    assert rows["AE-lib"]["time_offset_s"] == 5.0
    assert rows["AE-cfg"]["outcome"] == "identified"  # outcome unaffected (§10.6)
    assert rows["AE-cfg"]["gt_time"] is None
    assert rows["AE-cfg"]["time_offset_s"] is None
