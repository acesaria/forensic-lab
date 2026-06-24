# Escalating deleted-file recovery: runner escalation/outcomes, the detect
# adapter -> Finding mapping, matcher exclusion, and the per-level recovery
# breakdown. Tool execution is monkeypatched so no real binaries are needed.

from pathlib import Path

from orchestrator.evaluation.contracts.models import Entity, GtEvent, GtManifest, Observable
from orchestrator.evaluation.contracts.validate import validate_finding
from orchestrator.evaluation.detect.deleted_file_recovery import detect as recovery_detect
from orchestrator.evaluation.match.matcher import match
from orchestrator.evaluation.metrics.compute import compute_recovery_breakdown
from orchestrator.forensics import deleted_file_runner as dfr

_PARTITION = {
    "fs_type": "ext4",
    "offset_bytes": 0,
    "part_start_sector": 2048,
    "part_count_sectors": 1000000,
    "is_tmpfs": False,
    "tmpfs_mounts": ["/tmp", "/dev/shm", "/run"],
}
_TARGETS = [
    {"entity_type": "path", "entity_value": "/etc/ld.so.preload"},   # found at L2
    {"entity_type": "path", "entity_value": "/tmp/T1574006.so"},     # tmpfs -> n/a
    {"entity_type": "path", "entity_value": "/etc/cron.d/backdoor"}, # never found -> L2 gap
]


def _patch_tools(monkeypatch):
    monkeypatch.setattr(dfr, "_which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(dfr, "_probe_version", lambda cmd: f"{cmd[0]} 1.0")

    def fake_tsk(image, pinfo, out):
        out.mkdir(parents=True, exist_ok=True)  # recovers nothing of interest
        return out, None

    def fake_prep(image, pinfo, work_dir):
        return Path("/fake/disk_part.raw"), None  # no real ewfexport/dd

    def fake_ext4(part_raw, pinfo, relpath, out):
        # L2 recovers only the preload target; ext4magic -f takes a relative path.
        if relpath == "etc/ld.so.preload":
            f = out / "etc" / "ld.so.preload"
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("hooked")
            return str(f), None
        return None, None

    monkeypatch.setattr(dfr, "_run_tsk_recover", fake_tsk)
    monkeypatch.setattr(dfr, "_prepare_partition_raw", fake_prep)
    monkeypatch.setattr(dfr, "_run_ext4magic", fake_ext4)


def _run(monkeypatch, tmp_path):
    _patch_tools(monkeypatch)
    return dfr.run(Path("/img.E01"), _PARTITION, _TARGETS, tmp_path, "run-x")


def test_runner_escalates_and_reports_outcomes(monkeypatch, tmp_path):
    payload = _run(monkeypatch, tmp_path)
    by = {(r["target"], r["recovery_level"]): r for r in payload["results"]}

    # tmpfs target: not_applicable at L1, never escalates.
    na = by[("/tmp/T1574006.so", 1)]
    assert na["recovery_outcome"] == "not_applicable" and "tmpfs" in na["note"]
    assert not any(r["target"] == "/tmp/T1574006.so" and r["recovery_level"] in (2, 3)
                   for r in payload["results"])

    # preload: L1 not_found then L2 found (stopped once found).
    assert by[("/etc/ld.so.preload", 1)]["recovery_outcome"] == "not_found"
    assert by[("/etc/ld.so.preload", 2)]["recovery_outcome"] == "found"

    # cron backdoor: exhausts both levels -> L2 gap (terminal, no carving level).
    assert by[("/etc/cron.d/backdoor", 2)]["recovery_outcome"] == "not_found"

    assert set(payload["tool_versions"]) == {"tsk_recover", "ext4magic"}


def test_adapter_emits_valid_findings(monkeypatch, tmp_path):
    payload = _run(monkeypatch, tmp_path)
    findings = list(recovery_detect({"deleted_file": payload}, {}))
    for f in findings:
        assert f.forensic_operation == "deleted_file"
        validate_finding(f.to_dict())  # new source_tool + recovery_* fields valid
    outcomes = {(f.source_tool, f.recovery_level, f.recovery_outcome) for f in findings}
    assert ("ext4magic", 2, "found") in outcomes
    assert ("tsk_recover", 1, "not_applicable") in outcomes
    assert ("ext4magic", 2, "not_found") in outcomes  # terminal gap, no carving level


def test_recovery_findings_excluded_from_matcher(monkeypatch, tmp_path):
    payload = _run(monkeypatch, tmp_path)
    findings = list(recovery_detect({"deleted_file": payload}, {}))
    manifest = GtManifest(
        "s", "r", "ubuntu-22.04",
        events=[GtEvent(
            gt_id="G1", ts_utc="2026-06-13T12:00:00.000Z", technique="T1574.006",
            event_class="file_deleted", entity=Entity("path", "/etc/ld.so.preload"),
            observables=[Observable("deleted_file", "tsk_recover", "path", "/etc/ld.so.preload")],
        )],
    )
    m = match(manifest, findings)
    # recovery findings never become matcher TP/FP; the gap is owned by the
    # recovery breakdown instead.
    assert m.tp == [] and m.fp == []


def test_recovery_breakdown_per_level(monkeypatch, tmp_path):
    payload = _run(monkeypatch, tmp_path)
    findings = list(recovery_detect({"deleted_file": payload}, {}))
    rows = {(_["recovery_level"], _["source_tool"]): _
            for _ in (r.values for r in compute_recovery_breakdown(findings))}

    assert rows[(2, "ext4magic")]["found"] == 1
    # one target found at L2, one a terminal L2 gap -> ext4magic recall 0.5
    assert rows[(2, "ext4magic")]["recall"] == 0.5
    assert rows[(2, "ext4magic")]["not_found"] == 1
    assert rows[("n/a", "tsk_recover")]["not_applicable"] == 1
    assert rows[("n/a", "tsk_recover")]["scope"] == "unsupported_fs"

    total = rows[("__total__", "*")]
    assert total["found"] == 1 and total["not_found"] == 1 and total["not_applicable"] == 1
    assert total["recall"] == 0.5  # not_applicable excluded from the denominator


def test_tmpfs_path_detection():
    assert dfr._is_tmpfs_target("/tmp/x.so", _PARTITION) is True
    assert dfr._is_tmpfs_target("/etc/ld.so.preload", _PARTITION) is False
    assert dfr._is_tmpfs_target("/anything", {"is_tmpfs": True}) is True
