import json
from pathlib import Path

from orchestrator.canonical import (
    DetectionClaim,
    EvidenceSource,
    TemporalQuality,
    ToolFinding,
    write_jsonl,
)
from orchestrator.core.baseline_cache import (
    BaselineCacheEntry,
    baseline_identity,
    cache_dir_for_identity,
    expected_manifest,
    load_compatible_cache,
    write_cache_manifest,
)
from orchestrator.core.orchestrator import ForensicOrchestrator
from orchestrator.core.paths import ProjectPaths


def test_clean_baseline_cache_manifest_is_written_and_reused_with_identity(tmp_path):
    paths = _paths(tmp_path)
    identity = baseline_identity("ubuntu-22.04", vm_prefix="lab", snapshot="baseline")
    expected = _expected(identity)
    cache_dir = cache_dir_for_identity(paths, identity)
    tf_path = write_jsonl(
        cache_dir / "tool_findings.jsonl",
        [_finding("tf-1", "/etc/ld.so.preload", sha256="abc", size=12)],
    )

    entry = write_cache_manifest(
        paths,
        expected,
        tool_findings_path=tf_path,
        acquisition_manifest_path=tmp_path / "manifest.json",
    )

    assert entry is not None
    assert entry.identity == identity
    assert entry.manifest["baseline_identity"] == identity
    assert entry.manifest["comparable_path_count"] == 1
    manifest = json.loads(entry.manifest_path.read_text(encoding="utf-8"))
    assert manifest["tool_findings"] == str(tf_path)

    reused = load_compatible_cache(paths, expected)

    assert reused is not None
    assert reused.reused is True
    assert reused.tool_findings_path == tf_path


def test_clean_baseline_cache_rejects_incompatible_identity_fields(tmp_path):
    paths = _paths(tmp_path)
    identity = baseline_identity("ubuntu-22.04", vm_prefix="lab", snapshot="baseline")
    expected = _expected(identity)
    cache_dir = cache_dir_for_identity(paths, identity)
    tf_path = write_jsonl(cache_dir / "tool_findings.jsonl", [_finding("tf-1", "/etc/a")])
    assert (
        write_cache_manifest(
            paths,
            expected,
            tool_findings_path=tf_path,
            acquisition_manifest_path=None,
        )
        is not None
    )

    changed_tools = dict(expected)
    changed_tools["tool_versions"] = {"sleuthkit": "different"}

    assert load_compatible_cache(paths, changed_tools) is None


def test_clean_baseline_cache_without_comparable_paths_is_not_reused(tmp_path):
    paths = _paths(tmp_path)
    identity = baseline_identity("ubuntu-22.04", vm_prefix="lab", snapshot="baseline")
    expected = _expected(identity)
    cache_dir = cache_dir_for_identity(paths, identity)
    tf_path = write_jsonl(
        cache_dir / "tool_findings.jsonl",
        [
            ToolFinding(
                finding_id="tf-proc",
                run_id="baseline-run",
                tool="fixture",
                tool_version="fixture",
                adapter_version="fixture",
                source_type=EvidenceSource.MEMORY,
                artifact_class="process",
                entity={"type": "pid", "value": "1"},
                time="unknown",
                raw_ref="fixture:tf-proc",
                provenance={"adapter": "fixture"},
                temporal_quality=TemporalQuality.NONE,
            )
        ],
    )

    entry = write_cache_manifest(
        paths,
        expected,
        tool_findings_path=tf_path,
        acquisition_manifest_path=None,
    )

    assert entry is None
    assert load_compatible_cache(paths, expected) is None


def test_declarative_evaluation_passes_verified_baseline_to_detector(
    tmp_path, monkeypatch
):
    paths = _paths(tmp_path)
    run_id = "ubuntu-22.04_userland_father_ldpreload_20260629-120000"
    run_dir = paths.experiments_dir / run_id / "dumps"
    run_dir.mkdir(parents=True)
    (run_dir / "artifact_expectations.jsonl").write_text("{}\n", encoding="utf-8")
    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "memory_image": {"path": str(tmp_path / "memory.raw")},
                "disk_image": {"path": str(tmp_path / "disk.E01")},
            }
        ),
        encoding="utf-8",
    )
    baseline_tf = tmp_path / "baseline_tool_findings.jsonl"
    baseline_tf.write_text("", encoding="utf-8")
    baseline_entry = BaselineCacheEntry(
        identity="lab-ubuntu-22.04:baseline",
        cache_dir=tmp_path,
        manifest_path=tmp_path / "baseline_manifest.json",
        tool_findings_path=baseline_tf,
        manifest={"warnings": []},
        reused=True,
    )
    orch = ForensicOrchestrator(
        vm_manager=None,
        dumper=_DummyDumper(paths),
        vol_runner=None,
        sleuth_runner=None,
        paths=paths,
        role_defaults={},
    )

    monkeypatch.setattr(
        orch,
        "_collect_tool_findings",
        lambda *args, **kwargs: [_finding("tf-1", "/etc/ld.so.preload")],
    )
    captured: dict[str, object] = {}

    def fake_run_detectors_file(path, **kwargs):
        captured["findings_path"] = path
        captured.update(kwargs)
        return [
            DetectionClaim(
                claim_id="dc-1",
                run_id=run_id,
                rule_id="fixture",
                artifact_class="preload_configuration",
                entity={"type": "path", "value": "/etc/ld.so.preload"},
                source_findings=["tf-1"],
                attck=[],
                notes="fixture",
            )
        ]

    monkeypatch.setattr(
        "orchestrator.core.orchestrator.run_detectors_file", fake_run_detectors_file
    )
    monkeypatch.setattr(
        "orchestrator.core.orchestrator.run_matcher_files",
        lambda **kwargs: {"metrics": {"schema": "forensic-lab.matcher.metrics.v2"}},
    )
    monkeypatch.setattr(
        "orchestrator.core.orchestrator.render_console_summary", lambda metrics: []
    )

    orch._evaluate_declarative_run(
        run_id,
        "ubuntu-22.04",
        str(manifest_path),
        baseline_cache=baseline_entry,
    )

    assert captured["baseline_findings_path"] == baseline_tf
    assert captured["baseline_identity"] == "lab-ubuntu-22.04:baseline"


class _DummyDumper:
    def __init__(self, paths: ProjectPaths) -> None:
        self._paths = paths

    def run_dir(self, run_id: str) -> Path:
        return self._paths.experiments_dir / run_id / "dumps"


def _paths(tmp_path: Path) -> ProjectPaths:
    return ProjectPaths(
        repo_root=tmp_path,
        shared_dir=tmp_path / "shared",
        state_dir=tmp_path / "state",
        ssh_key=tmp_path / "id",
        ssh_pub_key=tmp_path / "id.pub",
    )


def _expected(identity: str) -> dict:
    return expected_manifest(
        distro_id="ubuntu-22.04",
        vm_name="lab-ubuntu-22.04",
        snapshot="baseline",
        identity=identity,
        profile={
            "image": {
                "url": "file:///image.qcow2",
                "checksum_url": "file:///SHA256SUMS",
                "checksum_algo": "sha256",
            }
        },
        guest={"kernel": "5.15.0-fixture"},
        tool_versions={"sleuthkit": "4.12.1"},
        volatility={"symbols": "/tmp/ubuntu.json", "profile": "ubuntu.json"},
    )


def _finding(
    finding_id: str,
    path: str,
    *,
    sha256: str | None = None,
    size: int | None = None,
) -> ToolFinding:
    entity = {"type": "path", "value": path}
    if sha256 is not None:
        entity["sha256"] = sha256
    if size is not None:
        entity["size"] = size
    return ToolFinding(
        finding_id=finding_id,
        run_id="baseline-run",
        tool="fixture",
        tool_version="fixture",
        adapter_version="fixture",
        source_type=EvidenceSource.DISK,
        artifact_class="file",
        entity=entity,
        time="unknown",
        raw_ref=f"fixture:{finding_id}",
        provenance={"adapter": "fixture"},
        temporal_quality=TemporalQuality.NONE,
    )
