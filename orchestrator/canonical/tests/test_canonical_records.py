from pathlib import Path

import pytest

from orchestrator.canonical import (
    ArtifactExpectation,
    DetectionClaim,
    EvidenceSource,
    GroundTruthEvent,
    MatchLevel,
    MatchResult,
    ReferenceContext,
    ScenarioStep,
    TemporalQuality,
    ToolFinding,
    append_jsonl,
    load_json,
    load_jsonl,
    write_json,
)


def _truth() -> GroundTruthEvent:
    return GroundTruthEvent(
        run_id="run-1",
        scenario_id="scenario_01",
        step_id="S1",
        event_type="artifact_created",
        object_type="path",
        object_identity="/tmp/payload.so",
        action="create",
        actor="attacker",
        time="2026-06-18T10:00:00.000Z",
        evidence_basis=[EvidenceSource.DISK],
        attck=["T1574.006"],
        temporal_quality=TemporalQuality.EXACT,
    )


def _expectation() -> ArtifactExpectation:
    return ArtifactExpectation(
        ae_id="AE1",
        scenario_id="scenario_01",
        step_id="S1",
        artifact_class="ld_preload_payload",
        observable_kind="filesystem_path",
        source_eligibility=[EvidenceSource.DISK, EvidenceSource.TIMELINE],
        persistence="until_cleanup",
        observability="direct",
        instance_constraints={"path": "/tmp/payload.so"},
        critical=True,
        attck=["T1574.006"],
    )


def _finding() -> ToolFinding:
    return ToolFinding(
        finding_id="tf-1",
        run_id="run-1",
        tool="tsk",
        tool_version="4.12.1",
        adapter_version="canonical-v1",
        source_type=EvidenceSource.DISK,
        artifact_class="ld_preload_payload",
        entity={"type": "path", "value": "/tmp/payload.so"},
        time="2026-06-18T10:00:01.000Z",
        raw_ref="bodyfile:inode=42",
        provenance={"source": "bodyfile"},
        temporal_quality=TemporalQuality.BOUNDED,
    )


def test_execution_truth_jsonl_round_trip(tmp_path: Path):
    path = tmp_path / "execution_truth.jsonl"
    append_jsonl(path, _truth())

    loaded = load_jsonl(path, GroundTruthEvent)

    assert loaded == [_truth()]
    assert loaded[0].to_dict()["evidence_basis"] == ["disk"]


def test_artifact_expectations_jsonl_round_trip(tmp_path: Path):
    path = tmp_path / "artifact_expectations.jsonl"
    append_jsonl(path, _expectation())

    loaded = load_jsonl(path, ArtifactExpectation)

    assert loaded == [_expectation()]
    assert loaded[0].source_eligibility == [EvidenceSource.DISK, EvidenceSource.TIMELINE]


def test_tool_findings_jsonl_round_trip(tmp_path: Path):
    path = tmp_path / "tool_findings.jsonl"
    append_jsonl(path, _finding())

    loaded = load_jsonl(path, ToolFinding)

    assert loaded == [_finding()]
    assert loaded[0].source_type == EvidenceSource.DISK


def test_json_round_trip_for_reference_context(tmp_path: Path):
    record = ReferenceContext(
        ref_id="raw-1",
        run_id="run-1",
        scenario_id="scenario_01",
        source=EvidenceSource.TIMELINE,
        locator="timeline.jsonl:10",
    )
    path = write_json(tmp_path / "reference_context.json", record)

    assert load_json(path, ReferenceContext) == record


def test_other_canonical_records_validate_and_serialize():
    step = ScenarioStep(
        scenario_id="scenario_01",
        step_id="S1",
        action="create_ld_preload_payload",
        command="touch /tmp/payload.so",
        attck=["T1574.006"],
    )
    claim = DetectionClaim(
        claim_id="dc-1",
        run_id="run-1",
        rule_id="tsk:temp_exec_created",
        artifact_class="ld_preload_payload",
        entity={"type": "path", "value": "/tmp/payload.so"},
        confidence=0.9,
        source_findings=["tf-1"],
        attck=["T1574.006"],
    )
    match = MatchResult(
        match_id="m-1",
        run_id="run-1",
        target_id="AE1",
        finding_or_claim_id="dc-1",
        match_level=MatchLevel.INSTANCE,
        relation="supports",
        score=1.0,
        fields_matched=["artifact_class", "entity.path"],
        notes="",
    )
    assert step.to_dict()["executor"] == "shell"
    assert claim.to_dict()["confidence"] == 0.9
    assert match.to_dict()["match_level"] == "instance"


def test_missing_required_field_rejected():
    with pytest.raises(ValueError):
        GroundTruthEvent(
            run_id="run-1",
            scenario_id="scenario_01",
            step_id="S1",
            event_type="artifact_created",
            object_type="path",
            object_identity="",
            action="create",
            actor="attacker",
            time="2026-06-18T10:00:00.000Z",
            evidence_basis=[EvidenceSource.DISK],
            attck=["T1574.006"],
        )


def test_score_bounds_rejected():
    with pytest.raises(ValueError):
        DetectionClaim(
            claim_id="dc-1",
            run_id="run-1",
            rule_id="rule",
            artifact_class="class",
            entity={},
            confidence=2.0,
            source_findings=[],
            attck=[],
        )
