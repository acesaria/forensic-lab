from detectors.baseline import filter_findings_against_baseline
from orchestrator.canonical import EvidenceSource, ToolFinding


def test_disk_filtering_drops_exact_rows_and_keeps_new_or_changed():
    baseline = [
        _disk("b-same", "/etc/demo.conf", size=10, mtime="2026-01-01T00:00:00.000Z"),
        _disk("b-grown", "/etc/grown.conf", size=10, mtime="2026-01-01T00:00:00.000Z"),
    ]
    run = [
        _disk("c-same", "/etc/demo.conf", size=10, mtime="2026-01-01T00:00:00.000Z"),
        _disk("c-grown", "/etc/grown.conf", size=99, mtime="2026-01-01T00:00:00.000Z"),
        _disk("c-new", "/etc/new.conf", size=1),
    ]

    kept, stats = filter_findings_against_baseline(
        run, baseline, identity="lab-test:baseline"
    )

    assert [f.finding_id for f in kept] == ["c-grown", "c-new"]
    assert stats["identity"] == "lab-test:baseline"
    assert stats["per_source"]["disk"] == {"pre": 3, "post": 2}


def test_atime_only_change_is_still_known_good_but_mtime_change_is_kept():
    baseline = [
        _disk("b", "/usr/bin/tool", size=5,
              atime="2026-01-01T00:00:00.000Z", mtime="2026-01-01T00:00:00.000Z"),
    ]
    read_only = _disk("c-read", "/usr/bin/tool", size=5,
                      atime="2026-06-01T12:00:00.000Z", mtime="2026-01-01T00:00:00.000Z")
    modified = _disk("c-mod", "/usr/bin/tool", size=5,
                     atime="2026-06-01T12:00:00.000Z", mtime="2026-06-01T12:00:00.000Z")

    kept, _ = filter_findings_against_baseline(
        [read_only, modified], baseline, identity="lab-test:baseline"
    )

    assert [f.finding_id for f in kept] == ["c-mod"]


def test_symlink_value_string_participates_and_retarget_is_kept():
    baseline = [_disk("b-link", "/bin -> usr/bin", size=7)]
    unchanged = _disk("c-link", "/bin -> usr/bin", size=7)
    retargeted = _disk("c-evil", "/bin -> /tmp/evil", size=9)

    kept, _ = filter_findings_against_baseline(
        [unchanged, retargeted], baseline, identity="lab-test:baseline"
    )

    assert [f.finding_id for f in kept] == ["c-evil"]


def test_sources_are_never_merged_and_memory_passes_through():
    # A baseline timeline event for a path must not vouch for a disk object at
    # the same path, and memory rows are never filtered.
    baseline = [
        _event("b-ev", "/etc/demo.conf", time="2026-01-01T00:00:00.000Z"),
    ]
    disk_row = _disk("c-disk", "/etc/demo.conf", size=10)
    same_event = _event("c-ev-same", "/etc/demo.conf", time="2026-01-01T00:00:00.000Z")
    new_event = _event("c-ev-new", "/etc/demo.conf", time="2026-06-01T12:00:00.000Z")
    memory_row = _memory("c-mem")

    kept, stats = filter_findings_against_baseline(
        [disk_row, same_event, new_event, memory_row],
        baseline,
        identity="lab-test:baseline",
    )

    assert [f.finding_id for f in kept] == ["c-disk", "c-ev-new", "c-mem"]
    assert stats["per_source"]["timeline"] == {"pre": 2, "post": 1}
    assert stats["per_source"]["memory"] == {"pre": 1, "post": 1}


def _disk(
    finding_id: str,
    path: str,
    *,
    size: int | None = None,
    atime: str | None = None,
    mtime: str | None = None,
) -> ToolFinding:
    entity = {"type": "path", "value": path, "size": size, "deleted": False}
    timestamps = {k: v for k, v in (("atime", atime), ("mtime", mtime)) if v}
    if timestamps:
        entity["timestamps"] = timestamps
    return _finding(finding_id, EvidenceSource.DISK, "file", entity, time=None)


def _event(finding_id: str, value: str, *, time: str) -> ToolFinding:
    return _finding(
        finding_id,
        EvidenceSource.TIMELINE,
        "file",
        {"type": "path", "value": value, "time_kind": "mtime"},
        time=time,
    )


def _memory(finding_id: str) -> ToolFinding:
    return _finding(
        finding_id,
        EvidenceSource.MEMORY,
        "process",
        {"type": "pid", "value": "1234"},
        time=None,
    )


def _finding(
    finding_id: str,
    source: EvidenceSource,
    artifact_class: str,
    entity: dict,
    *,
    time: str | None,
) -> ToolFinding:
    return ToolFinding(
        finding_id=finding_id,
        run_id="run-baseline-test",
        tool="fixture",
        tool_version="fixture",
        adapter_version="fixture",
        source_type=source,
        artifact_class=artifact_class,
        entity=entity,
        time=time,
        raw_ref=f"fixture:{finding_id}",
        provenance={"adapter": "fixture"},
    )
