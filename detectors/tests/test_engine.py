import subprocess
from pathlib import Path

import yaml

from detectors.engine import load_rules, run_detectors, run_detectors_file, write_detection_claims
from orchestrator.canonical import DetectionClaim, EvidenceSource, ToolFinding, load_jsonl

FIXTURES = Path(__file__).parent / "fixtures"


def test_rules_have_sigma_lite_metadata():
    rules = load_rules()

    assert {rule.id for rule in rules} >= {
        "flab.filesystem.suspicious_temp_path",
        "flab.filesystem.userland_persistence",
        "flab.timeline.suspicious_shell_history",
        "flab.memory.process_from_unusual_path",
        "flab.memory.process_socket_correlation",
        "flab.filesystem.ebpf_kernel_like_object",
        "flab.filesystem.ld_preload_configuration",
        "flab.filesystem.suspicious_shared_object",
        "flab.filesystem.deleted_artifact_cleanup",
        "flab.memory.process_library_correlation",
    }
    for rule in rules:
        assert rule.name
        assert rule.description
        assert rule.source_types
        assert rule.artifact_classes
        assert rule.attck
        assert yaml.safe_load(rule.path.read_text(encoding="utf-8"))["id"] == rule.id


def test_engine_produces_detection_claims_without_ground_truth(tmp_path: Path):
    claims = run_detectors_file(FIXTURES / "tool_findings.jsonl")
    out = write_detection_claims(tmp_path / "detection_claims.jsonl", claims)
    loaded = load_jsonl(out, DetectionClaim)

    rule_ids = {claim.rule_id for claim in loaded}
    assert "flab.filesystem.suspicious_temp_path" in rule_ids
    assert "flab.filesystem.userland_persistence" in rule_ids
    assert "flab.timeline.suspicious_shell_history" in rule_ids
    assert "flab.memory.process_from_unusual_path" in rule_ids
    assert "flab.memory.process_socket_correlation" in rule_ids
    assert "flab.filesystem.ebpf_kernel_like_object" in rule_ids
    assert "flab.filesystem.ld_preload_configuration" in rule_ids
    assert "flab.filesystem.suspicious_shared_object" in rule_ids
    assert "flab.filesystem.deleted_artifact_cleanup" in rule_ids
    assert "flab.memory.process_library_correlation" in rule_ids
    assert all(claim.run_id == "run-detector-fixture" for claim in loaded)
    assert all(claim.source_findings for claim in loaded)


def test_run_detectors_cli_writes_claims(tmp_path: Path):
    out = tmp_path / "detection_claims.jsonl"
    result = subprocess.run(
        [
            ".venv/bin/python",
            "cli.py",
            "run-detectors",
            "--findings",
            str(FIXTURES / "tool_findings.jsonl"),
            "--out",
            str(out),
        ],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    claims = load_jsonl(out, DetectionClaim)
    assert claims


def test_noisy_filesystem_rules_are_gated_to_specific_evidence():
    findings = [
        _finding(
            "tf-workspace",
            "disk",
            "file",
            {"type": "path", "value": "/tmp/work/preload_kit/src/config.h"},
        ),
        _finding(
            "tf-preload",
            "disk",
            "preload_configuration",
            {"type": "path", "value": "/tmp/work/run/ld.so.preload"},
        ),
        _finding(
            "tf-temp-dir",
            "disk",
            "file",
            {"type": "path", "value": "/tmp/.X11-unix", "mode": "d/drwxrwxrwt"},
        ),
        _finding(
            "tf-temp-exec",
            "disk",
            "file",
            {"type": "path", "value": "/tmp/run.sh", "mode": "r/rrwxr-xr-x"},
        ),
        _finding(
            "tf-temp-deleted",
            "disk",
            "deleted_file_candidate",
            {"type": "path", "value": "/tmp/gone", "deleted": True},
        ),
        _finding(
            "tf-service-timeline",
            "timeline",
            "service_unit_file",
            {"type": "path", "value": "/etc/systemd/system/cloud-init.service"},
        ),
        _finding(
            "tf-service-disk",
            "disk",
            "service_unit_file",
            {"type": "path", "value": "/etc/systemd/system/new.service"},
        ),
    ]

    by_rule = {}
    for claim in run_detectors(findings):
        by_rule.setdefault(claim.rule_id, []).append(claim)

    preload_values = {
        claim.entity["value"]
        for claim in by_rule["flab.filesystem.ld_preload_configuration"]
    }
    assert preload_values == {"/tmp/work/run/ld.so.preload"}

    temp_values = {
        claim.entity["value"]
        for claim in by_rule["flab.filesystem.suspicious_temp_path"]
    }
    assert temp_values == {"/tmp/run.sh", "/tmp/gone"}

    persistence_values = {
        claim.entity["value"]
        for claim in by_rule["flab.filesystem.userland_persistence"]
    }
    assert persistence_values == {"/etc/systemd/system/new.service"}


def test_duplicate_process_library_memory_claims_collapse_to_logical_candidate():
    findings = [
        _memory_finding(
            "tf-proc-pslist",
            "process",
            {"type": "process", "value": "payload", "pid": 4321, "path": "/tmp/payload"},
        ),
        _memory_finding(
            "tf-proc-psscan",
            "process",
            {"type": "process", "value": "payload", "pid": 4321, "path": "/tmp/payload"},
        ),
        _memory_finding(
            "tf-map-1",
            "library_mapping",
            {"type": "path", "value": "/tmp/libpayload.so", "path": "/tmp/libpayload.so", "pid": 4321},
        ),
        _memory_finding(
            "tf-map-2",
            "library_mapping",
            {"type": "path", "value": "/tmp/libpayload.so", "path": "/tmp/libpayload.so", "pid": 4321},
        ),
    ]

    claims = [
        claim for claim in run_detectors(findings)
        if claim.rule_id == "flab.memory.process_library_correlation"
    ]

    assert len(claims) == 1
    assert set(claims[0].source_findings) == {finding.finding_id for finding in findings}


def test_duplicate_process_socket_memory_claims_collapse_to_logical_candidate():
    findings = [
        _memory_finding(
            "tf-proc-pslist",
            "process",
            {"type": "process", "value": "payload", "pid": 4321, "path": "/tmp/payload"},
        ),
        _memory_finding(
            "tf-proc-psscan",
            "process",
            {"type": "process", "value": "payload", "pid": 4321, "path": "/tmp/payload"},
        ),
        _memory_finding(
            "tf-sock-1",
            "socket",
            {
                "type": "socket",
                "value": "198.51.100.2:4444",
                "pid": 4321,
                "remote": {"address": "198.51.100.2", "port": 4444},
            },
        ),
        _memory_finding(
            "tf-sock-2",
            "socket",
            {
                "type": "socket",
                "value": "198.51.100.2:4444",
                "pid": 4321,
                "remote": {"address": "198.51.100.2", "port": 4444},
            },
        ),
    ]

    claims = [
        claim for claim in run_detectors(findings)
        if claim.rule_id == "flab.memory.process_socket_correlation"
    ]

    assert len(claims) == 1
    assert set(claims[0].source_findings) == {finding.finding_id for finding in findings}


def test_detectors_do_not_import_ground_truth_modules():
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [Path("detectors/engine.py"), *Path("detectors/rules").rglob("*.yml")]
    )
    lower = combined.lower()

    assert "gt_manifest" not in lower
    assert "ground_truth" not in lower
    assert "evaluation.scenario" not in lower
    assert "artifactexpectation" not in lower
    assert "father" not in lower


def _memory_finding(finding_id: str, artifact_class: str, entity: dict) -> ToolFinding:
    return ToolFinding(
        finding_id=finding_id,
        run_id="run-memory-dedupe",
        tool="volatility3",
        tool_version="fixture",
        adapter_version="fixture",
        source_type=EvidenceSource.MEMORY,
        artifact_class=artifact_class,
        entity=entity,
        time=None,
        raw_ref=f"vol3:{finding_id}",
        provenance={"adapter": "fixture"},
    )


def _finding(finding_id: str, source: str, artifact_class: str, entity: dict) -> ToolFinding:
    return ToolFinding(
        finding_id=finding_id,
        run_id="run-detector-gates",
        tool="fixture",
        tool_version="fixture",
        adapter_version="fixture",
        source_type=EvidenceSource(source),
        artifact_class=artifact_class,
        entity=entity,
        time=None,
        raw_ref=f"fixture:{finding_id}",
        provenance={"adapter": "fixture"},
    )
