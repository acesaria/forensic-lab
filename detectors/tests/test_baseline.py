from detectors.baseline import (
    BASELINE_CHANGED,
    BASELINE_NEW,
    BASELINE_PRESENT,
    apply_baseline_to_claims,
    compare_path_baseline,
)
from orchestrator.canonical import (
    DetectionClaim,
    EvidenceSource,
    TemporalQuality,
    ToolFinding,
)


def test_baseline_comparison_classifies_new_changed_and_present_paths():
    baseline = [
        _finding("b-present", "/etc/demo.conf", sha256="same", size=10),
        _finding("b-changed", "/etc/changed.conf", sha256="old", size=10),
    ]
    compromised = [
        _finding("c-new", "/etc/new.conf", sha256="new", size=1),
        _finding("c-present", "/etc/demo.conf", sha256="same", size=10),
        _finding("c-changed", "/etc/changed.conf", sha256="new", size=10),
    ]

    comparison = compare_path_baseline(
        baseline,
        compromised,
        identity="lab-test:baseline",
    )

    assert comparison.status_by_path["/etc/new.conf"].status == BASELINE_NEW
    assert comparison.status_by_path["/etc/demo.conf"].status == BASELINE_PRESENT
    assert comparison.status_by_path["/etc/changed.conf"].status == BASELINE_CHANGED
    assert comparison.status_counts[BASELINE_NEW] == 1
    assert comparison.status_counts[BASELINE_PRESENT] == 1
    assert comparison.status_counts[BASELINE_CHANGED] == 1


def test_present_in_baseline_timeline_only_candidate_is_downgraded():
    baseline = [_finding("b-service", "/etc/systemd/system/demo.service")]
    compromised = [
        _finding(
            "c-service",
            "/etc/systemd/system/demo.service",
            source=EvidenceSource.TIMELINE,
            artifact_class="service_unit_file",
        )
    ]
    claim = _claim("c-service", "/etc/systemd/system/demo.service", confidence=0.84)

    claims = apply_baseline_to_claims(
        [claim],
        compromised,
        baseline,
        identity="lab-test:baseline",
    )

    assert len(claims) == 1
    assert claims[0].confidence == 0.35
    assert claims[0].entity["baseline"]["status"] == BASELINE_PRESENT
    assert claims[0].entity["baseline"]["filter_action"] == "confidence_downgraded"


def test_present_in_baseline_disk_candidate_is_not_downgraded():
    baseline = [_finding("b-service", "/etc/systemd/system/demo.service")]
    compromised = [
        _finding(
            "c-service",
            "/etc/systemd/system/demo.service",
            source=EvidenceSource.DISK,
            artifact_class="service_unit_file",
        )
    ]
    claim = _claim("c-service", "/etc/systemd/system/demo.service", confidence=0.84)

    claims = apply_baseline_to_claims(
        [claim],
        compromised,
        baseline,
        identity="lab-test:baseline",
    )

    assert claims[0].confidence == 0.84
    assert claims[0].entity["baseline"]["status"] == BASELINE_PRESENT
    assert claims[0].entity["baseline"]["filter_action"] == "none"


def _finding(
    finding_id: str,
    path: str,
    *,
    sha256: str | None = None,
    size: int | None = None,
    source: EvidenceSource = EvidenceSource.DISK,
    artifact_class: str = "file",
) -> ToolFinding:
    entity = {"type": "path", "value": path}
    if sha256 is not None:
        entity["sha256"] = sha256
    if size is not None:
        entity["size"] = size
    return ToolFinding(
        finding_id=finding_id,
        run_id="run-baseline-test",
        tool="fixture",
        tool_version="fixture",
        adapter_version="fixture",
        source_type=source,
        artifact_class=artifact_class,
        entity=entity,
        time="unknown",
        raw_ref=f"fixture:{finding_id}",
        provenance={"adapter": "fixture"},
        temporal_quality=TemporalQuality.NONE,
    )


def _claim(finding_id: str, path: str, *, confidence: float) -> DetectionClaim:
    return DetectionClaim(
        claim_id=f"dc-{finding_id}",
        run_id="run-baseline-test",
        rule_id="flab.filesystem.userland_persistence",
        artifact_class="service_unit_file",
        entity={"type": "path", "value": path},
        confidence=confidence,
        source_findings=[finding_id],
        attck=["T1543.002"],
        notes="fixture claim",
    )
