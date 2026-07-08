import json
from pathlib import Path

from orchestrator.canonical import (
    DetectionClaim,
    EvidenceSource,
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
    (cache_dir / "analysis").mkdir(parents=True)
    (cache_dir / "analysis" / "bodyfile").write_text("0|/etc|2|d|0|0|4096|1|1|1|1\n")

    entry = write_cache_manifest(
        paths,
        expected,
        tool_findings_path=tf_path,
        acquisition_manifest_path=tmp_path / "manifest.json",
    )

    assert entry is not None
    assert entry.identity == identity
    assert entry.manifest["baseline_identity"] == identity
    assert entry.manifest["source_counts"] == {"disk": 1}
    assert entry.manifest["adapter_version"]
    manifest = json.loads(entry.manifest_path.read_text(encoding="utf-8"))
    assert manifest["tool_findings"] == str(tf_path)
    assert set(manifest["raw_channels"]) == {"bodyfile"}
    assert len(manifest["raw_channels"]["bodyfile"]["sha256"]) == 64

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


def test_clean_baseline_cache_without_disk_findings_is_not_reused(tmp_path):
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
                time=None,
                raw_ref="fixture:tf-proc",
                provenance={"adapter": "fixture"},
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


def test_declarative_evaluation_filters_findings_against_verified_baseline(
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
    baseline_tf = write_jsonl(
        tmp_path / "baseline_tool_findings.jsonl",
        [_finding("b-1", "/etc/hosts", size=12)],
    )
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
        lambda *args, **kwargs: [
            _finding("tf-known", "/etc/hosts", size=12),
            _finding("tf-new", "/etc/ld.so.preload"),
        ],
    )
    captured: dict[str, object] = {}

    def fake_run_detectors_file(path, **kwargs):
        captured["findings_path"] = Path(path)
        return [
            DetectionClaim(
                claim_id="dc-1",
                run_id=run_id,
                rule_id="fixture",
                artifact_class="preload_configuration",
                entity={"type": "path", "value": "/etc/ld.so.preload"},
                source_findings=["tf-new"],
                attck=[],
                notes="fixture",
            )
        ]

    def fake_run_matcher_files(**kwargs):
        captured["matcher_kwargs"] = kwargs
        return {"metrics": {"schema": "forensic-lab.matcher.metrics.v3"}}

    monkeypatch.setattr(
        "orchestrator.core.orchestrator.run_detectors_file", fake_run_detectors_file
    )
    monkeypatch.setattr(
        "orchestrator.core.orchestrator.run_matcher_files", fake_run_matcher_files
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

    analysis_dir = paths.run_analysis_dir(run_id)
    stats = json.loads((analysis_dir / "baseline_filter.json").read_text())
    filtered = [
        json.loads(line)
        for line in (analysis_dir / "tool_findings_filtered.jsonl").read_text().splitlines()
    ]

    # Detectors consume the filtered stream; the matcher keeps the unfiltered
    # one plus the filter stats.
    assert captured["findings_path"] == analysis_dir / "tool_findings_filtered.jsonl"
    assert [f["entity"]["value"] for f in filtered] == ["/etc/ld.so.preload"]
    # Filtered rows keep their canonical ids so claim.source_findings resolve
    # against the unfiltered stream the matcher loads.
    unfiltered_ids = {
        json.loads(line)["finding_id"]
        for line in (analysis_dir / "tool_findings.jsonl").read_text().splitlines()
    }
    assert {f["finding_id"] for f in filtered} <= unfiltered_ids
    assert stats["per_source"]["disk"] == {"pre": 2, "post": 1}
    matcher_kwargs = captured["matcher_kwargs"]
    assert matcher_kwargs["tool_findings_path"] == analysis_dir / "tool_findings.jsonl"
    assert matcher_kwargs["baseline_filter"] == stats


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
        time=None,
        raw_ref=f"fixture:{finding_id}",
        provenance={"adapter": "fixture"},
    )
