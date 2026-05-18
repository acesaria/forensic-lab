"""
ART-based scenario for ATT&CK T1059.004 (Command and Scripting Interpreter: Bash).
Executes real ART tests from atomics/T1059.004/T1059.004.yaml via atomic-operator.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from orchestrator.core.art_runner import ArtRunner
from orchestrator.core.config import ATOMICS_DIR
from orchestrator.core.ssh_client import SSHClient

SCENARIO: dict[str, Any] = {
    "id": "atomic-T1059.004-bash",
    "mitre": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059",
        "sub_technique_id": "004",
        "technique_name": "Command and Scripting Interpreter: Bash",
    },
}


def _select_tests(atomics_path: Path) -> list[str]:
    """
    Select 2 simple Linux-compatible ART tests that don't require external downloads.
    Returns list of test GUIDs.
    """
    path = atomics_path / "T1059.004" / "T1059.004.yaml"
    data = yaml.safe_load(path.read_text()) or {}
    tests = data.get("atomic_tests", [])

    selected = []
    for test in tests:
        platforms = test.get("supported_platforms", [])
        if "linux" not in platforms:
            continue

        deps = test.get("dependencies", [])
        if deps:
            continue

        cmd = test.get("executor", {}).get("command", "")
        if "curl" in cmd or "wget" in cmd or "http" in cmd:
            continue

        guid = test.get("auto_generated_guid")
        if guid:
            selected.append(guid)
            if len(selected) >= 2:
                break

    return selected


def run(ssh: SSHClient, scenario_id: str) -> dict[str, Any]:
    """
    Execute ART T1059.004 tests over SSH via atomic-operator.

    Args:
        ssh: Connected SSH client.
        scenario_id: Scenario execution identifier.

    Returns:
        Ground truth dict with scenario metadata and executed tests.
    """
    repo_root = Path(__file__).resolve().parents[2]
    atomics_path = repo_root / ATOMICS_DIR

    runner = ArtRunner(
        host=ssh._ip,
        username=ssh._user,
        ssh_key_path=ssh._key_path,
        atomics_path=atomics_path,
    )

    test_guids = _select_tests(atomics_path)

    tests_run: list[dict[str, Any]] = []
    for guid in test_guids:
        result = runner.run_test("T1059.004", guid)
        tests_run.append(
            {
                "guid": result["guid"],
                "name": result["name"],
                "technique": "T1059.004",
                "stdout": result["stdout"],
                "stderr": result["stderr"],
            }
        )

    ground_truth: dict[str, Any] = {
        "scenario_id": scenario_id,
        "scenario": {
            "id": SCENARIO["id"],
            "mitre": SCENARIO["mitre"],
        },
        "tests_run": tests_run,
    }

    return ground_truth
