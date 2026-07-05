from pathlib import Path

import pytest

from orchestrator.canonical import (
    ArtifactExpectation,
    DetectionClaim,
    EvidenceSource,
    GroundTruthEvent,
    TemporalQuality,
    ToolFinding,
    append_jsonl,
    load_jsonl,
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
        required_for_scoring=True,
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
    assert loaded[0].required_for_scoring is True


def test_required_for_scoring_fails_safe():
    # METHODOLOGY 10.2: missing or null never scores.
    data = _expectation().to_dict()
    del data["required_for_scoring"]
    assert ArtifactExpectation.from_dict(data).required_for_scoring is False
    data["required_for_scoring"] = None
    assert ArtifactExpectation.from_dict(data).required_for_scoring is False


def test_tool_findings_jsonl_round_trip(tmp_path: Path):
    path = tmp_path / "tool_findings.jsonl"
    append_jsonl(path, _finding())

    loaded = load_jsonl(path, ToolFinding)

    assert loaded == [_finding()]
    assert loaded[0].source_type == EvidenceSource.DISK


def test_tool_finding_accepts_missing_time():
    # METHODOLOGY 10.6: findings without a time are normal (memory is
    # point-in-time); a JSONL row may omit the key entirely.
    data = _finding().to_dict()
    del data["time"]
    assert ToolFinding.from_dict(data).time is None


def test_other_canonical_records_validate_and_serialize():
    claim = DetectionClaim(
        claim_id="dc-1",
        run_id="run-1",
        rule_id="tsk:temp_exec_created",
        artifact_class="ld_preload_payload",
        entity={"type": "path", "value": "/tmp/payload.so"},
        source_findings=["tf-1"],
        attck=["T1574.006"],
    )
    assert claim.to_dict()["entity"]["value"] == "/tmp/payload.so"


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


