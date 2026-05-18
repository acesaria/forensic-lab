"""ART-based scenario for ATT&CK T1070.003 test execution."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from orchestrator.core.art_runner import ArtRunner
from orchestrator.core.ssh_client import SSHClient

SCENARIO: dict[str, Any] = {
    "id": "art-T1070.003-clear-bash-history-rm",
    "mitre": {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1070",
        "sub_technique_id": "003",
        "technique_name": "Indicator Removal on Host: Clear Command History",
    },
}


def _resolve_test_guid(atomics_path: Path) -> str:
    technique_path = atomics_path / "T1070.003" / "T1070.003.yaml"
    data = yaml.safe_load(technique_path.read_text()) or {}
    tests = data.get("atomic_tests") or []
    if tests:
        return str(tests[0].get("auto_generated_guid", ""))
    return ""


def run(ssh: SSHClient, scenario_id: str) -> dict:
    repo_root = Path(__file__).resolve().parents[2]
    atomics_path = repo_root / "atomics"
    test_guid = _resolve_test_guid(atomics_path)

    runner = ArtRunner(
        host=ssh._ip,
        username=ssh._user,
        ssh_key_path=ssh._key_path,
        atomics_path=atomics_path,
    )
    runner.run_test("T1070.003", test_guid)
    runner.run_cleanup("T1070.003", test_guid)

    ground_truth: dict[str, Any] = {
        "scenario_id": scenario_id,
        "scenario": {
            "id": SCENARIO["id"],
            "mitre": SCENARIO["mitre"],
        },
    }
    return ground_truth
