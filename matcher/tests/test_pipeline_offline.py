from pathlib import Path

from detectors.engine import run_detectors
from matcher.engine import run_matcher
from orchestrator.adapters.common import write_tool_findings
from orchestrator.adapters.plaso import adapt_plaso_events
from orchestrator.adapters.sleuthkit import adapt_bodyfile
from orchestrator.adapters.volatility3 import adapt_plugin_rows
from orchestrator.canonical import ArtifactExpectation, EvidenceSource, ToolFinding, load_jsonl


def test_offline_pipeline_adapters_to_detectors_to_matcher(tmp_path: Path):
    run_id = "run-offline"
    bodyfile_lines = [
        "0|/tmp/x/rk.so|42|100644|1000|1000|4096|1783339200|1783339201|1783339202|1783339203"
    ]
    vol3_rows = {
        "linux.pslist": [{"PID": 7, "COMM": "payload"}],
        "linux.proc.Maps": [{"PID": 7, "Path": "/tmp/x/rk.so"}],
    }
    plaso_events = [
        {
            "filename": "/tmp/x/rk.so",
            "parser": "filestat",
            "data_type": "fs:stat",
            "timestamp": 1783339203000000,
            "timestamp_desc": "crtime",
        }
    ]

    findings = []
    findings += adapt_bodyfile(bodyfile_lines, run_id=run_id)
    findings += adapt_plugin_rows(vol3_rows, run_id=run_id)
    findings += adapt_plaso_events(plaso_events, run_id=run_id)
    findings_path = write_tool_findings(tmp_path / "tool_findings.jsonl", findings)
    loaded = load_jsonl(findings_path, ToolFinding)
    claims = run_detectors(loaded)
    expectations = [
        ArtifactExpectation(
            ae_id="AE-shared-object",
            scenario_id="scenario",
            step_id="S1",
            artifact_class="shared_object",
            instance_constraints={"path": "/tmp/x/rk.so"},
            source_eligibility=[
                EvidenceSource.DISK,
                EvidenceSource.TIMELINE,
                EvidenceSource.MEMORY,
            ],
            attck=["T1574.006"],
            required_for_scoring=True,
        )
    ]

    result = run_matcher(expectations, loaded, claims, out_dir=tmp_path / "match")
    row = result["outcomes"][0]

    assert row["outcome"] == "identified"
    assert len(row["sources"]) >= 2
    assert result["metrics"]["expectations"]["scored"] == 1
