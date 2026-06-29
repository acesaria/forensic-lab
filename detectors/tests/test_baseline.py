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


def test_size_and_size_bytes_are_compared_across_adapter_naming():
    # Baseline records the file size as ``size`` while the run's adapter records
    # it as ``size_bytes``. The two names are one logical field, so a real size
    # change must surface as changed_vs_baseline rather than present_in_baseline.
    baseline = [_finding("b-lib", "/usr/lib/x.so", size=100)]
    grown = [_finding("c-lib", "/usr/lib/x.so", size_bytes=200)]
    same = [_finding("c-lib", "/usr/lib/x.so", size_bytes=100)]

    changed = compare_path_baseline(baseline, grown, identity="lab-test:baseline")
    unchanged = compare_path_baseline(baseline, same, identity="lab-test:baseline")

    assert changed.status_by_path["/usr/lib/x.so"].status == BASELINE_CHANGED
    assert unchanged.status_by_path["/usr/lib/x.so"].status == BASELINE_PRESENT


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


def test_memory_correlation_claim_classifies_on_nested_library_path():
    # The correlation detector stores a composite "<process> -> <library>" in
    # entity['value'], and the process value can itself be a path. _claim_path
    # must ignore the composite and classify on the nested library path so the
    # claim is recognised as present_in_baseline rather than unknown.
    baseline = [_finding("b-lib", "/usr/lib/x.so", sha256="same")]
    compromised = [_finding("c-lib", "/usr/lib/x.so", sha256="same")]
    claim = DetectionClaim(
        claim_id="dc-corr",
        run_id="run-baseline-test",
        rule_id="flab.memory.process_library_correlation",
        artifact_class="library_mapping",
        entity={
            "type": "process_library",
            "value": "/usr/sbin/sshd -> /usr/lib/x.so",
            "process": {"type": "path", "value": "/usr/sbin/sshd"},
            "library": {"type": "path", "value": "/usr/lib/x.so"},
        },
        confidence=0.6,
        source_findings=["c-lib"],
        attck=["T1574.006"],
        notes="fixture correlation claim",
    )

    claims = apply_baseline_to_claims(
        [claim], compromised, baseline, identity="lab-test:baseline"
    )

    assert claims[0].entity["baseline"]["status"] == BASELINE_PRESENT
    assert claims[0].entity["baseline"]["path"] == "/usr/lib/x.so"


def test_downgrade_is_noop_when_confidence_already_at_cap():
    # A present_in_baseline timeline-only candidate already at/below the 0.35 cap
    # must not be flagged as downgraded, or candidate_downgrades is inflated.
    baseline = [_finding("b-service", "/etc/systemd/system/demo.service")]
    compromised = [
        _finding(
            "c-service",
            "/etc/systemd/system/demo.service",
            source=EvidenceSource.TIMELINE,
            artifact_class="service_unit_file",
        )
    ]
    claim = _claim("c-service", "/etc/systemd/system/demo.service", confidence=0.35)

    claims = apply_baseline_to_claims(
        [claim], compromised, baseline, identity="lab-test:baseline"
    )

    assert claims[0].confidence == 0.35
    assert claims[0].entity["baseline"]["status"] == BASELINE_PRESENT
    assert claims[0].entity["baseline"]["filter_action"] == "none"


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
    size_bytes: int | None = None,
    source: EvidenceSource = EvidenceSource.DISK,
    artifact_class: str = "file",
) -> ToolFinding:
    entity = {"type": "path", "value": path}
    if sha256 is not None:
        entity["sha256"] = sha256
    if size is not None:
        entity["size"] = size
    if size_bytes is not None:
        entity["size_bytes"] = size_bytes
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
