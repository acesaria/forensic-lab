from pathlib import Path

from orchestrator.adapters import write_tool_findings
from orchestrator.adapters.plaso import adapt_plaso_jsonl_file
from orchestrator.adapters.sleuthkit import adapt_bodyfile_file
from orchestrator.adapters.volatility3 import adapt_volatility_json_file
from orchestrator.adapters.yara import adapt_yara_matches_file
from orchestrator.canonical import EvidenceSource, TemporalQuality, ToolFinding, load_jsonl

FIXTURES = Path(__file__).parent / "fixtures"


def test_sleuthkit_bodyfile_adapter_converts_file_and_deleted_candidate(tmp_path: Path):
    findings = adapt_bodyfile_file(FIXTURES / "bodyfile.txt", run_id="run-adapter")
    out = write_tool_findings(tmp_path / "tool_findings.jsonl", findings)
    loaded = load_jsonl(out, ToolFinding)

    # one object finding per bodyfile row; MACB stays on the object
    assert len(loaded) == 4
    assert {finding.artifact_class for finding in loaded} >= {
        "file",
        "service_unit_file",
        "deleted_file_candidate",
    }
    assert all(f.time is None for f in loaded)
    assert all("time_kind" not in f.entity for f in loaded)

    payload = next(f for f in loaded if f.entity["value"] == "/tmp/payload.sh")
    assert set(payload.entity["timestamps"]) == {"atime", "mtime", "ctime", "crtime"}
    assert all(isinstance(ts, str) and ts for ts in payload.entity["timestamps"].values())

    deleted = next(f for f in loaded if f.entity["value"] == "/tmp/deleted.txt")
    assert deleted.artifact_class == "deleted_file_candidate"
    assert deleted.entity["deleted"] is True
    assert deleted.tool == "sleuthkit"
    assert deleted.source_type == EvidenceSource.DISK
    assert deleted.raw_ref.startswith("bodyfile:")

    realloc = next(f for f in loaded if f.entity["value"] == "/tmp/realloc.txt")
    assert realloc.artifact_class == "deleted_file_candidate"
    assert realloc.entity["deleted"] is True
    assert realloc.entity["reallocated"] is True
    assert "timestamps" not in realloc.entity
    assert realloc.time is None
    assert realloc.temporal_quality == TemporalQuality.NONE


def test_volatility3_adapter_converts_process_socket_and_bash_history(tmp_path: Path):
    findings = adapt_volatility_json_file(
        FIXTURES / "volatility3.json",
        run_id="run-adapter",
    )
    out = write_tool_findings(tmp_path / "tool_findings.jsonl", findings)
    loaded = load_jsonl(out, ToolFinding)

    assert {finding.artifact_class for finding in loaded} == {
        "process",
        "socket",
        "shell_history_log_event",
    }
    socket = next(f for f in loaded if f.artifact_class == "socket")
    assert socket.tool == "volatility3"
    assert socket.source_type == EvidenceSource.MEMORY
    assert socket.entity["value"] == "192.168.100.1:4444"
    assert socket.raw_ref.startswith("vol3:linux.sockstat")


def test_volatility3_adapter_accepts_single_renderer_rows_file(tmp_path: Path):
    single = tmp_path / "linux.pslist.json"
    single.write_text(
        '{"rows": [{"PID": 7, "Comm": "systemd"}]}\n',
        encoding="utf-8",
    )

    findings = adapt_volatility_json_file(
        single,
        run_id="run-adapter",
        plugin="linux.pslist",
    )

    assert len(findings) == 1
    assert findings[0].artifact_class == "process"
    assert findings[0].raw_ref.startswith("vol3:linux.pslist")


def test_plaso_and_yara_adapters_convert_cached_outputs():
    plaso = adapt_plaso_jsonl_file(FIXTURES / "plaso.jsonl", run_id="run-adapter")
    yara = adapt_yara_matches_file(FIXTURES / "yara_matches.json", run_id="run-adapter")

    assert plaso[0].tool == "plaso"
    assert plaso[0].artifact_class == "file"
    assert plaso[0].source_type == EvidenceSource.TIMELINE
    assert plaso[0].entity["time_kind"] == "Content Modification Time"
    assert "time_kind" not in plaso[1].entity
    assert yara[0].tool == "yara"
    assert yara[0].entity["rule"] == "Suspicious_Linux_SO"
    assert yara[0].raw_ref.startswith("yara:")


def test_adapters_do_not_import_ground_truth_modules():
    adapter_files = [
        Path("orchestrator/adapters/common.py"),
        Path("orchestrator/adapters/sleuthkit/bodyfile.py"),
        Path("orchestrator/adapters/volatility3/json_output.py"),
        Path("orchestrator/adapters/plaso/jsonl.py"),
        Path("orchestrator/adapters/yara/matches.py"),
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in adapter_files)

    assert "gt_manifest" not in combined
    assert "evaluation.scenario" not in combined
    assert "ground_truth" not in combined
