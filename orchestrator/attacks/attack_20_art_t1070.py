"""ART-based scenario for ATT&CK T1070.003 test execution via atomic-operator."""

from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import yaml
from atomic_operator import AtomicOperator

from orchestrator.core.config import LAB_USER
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

_TEST_NAME = "Clear Bash history (rm)"
_TEST_GUID_FALLBACK = "878b7a33-5e18-4054-b8f7-e1e73e5ebbf4"


def _build_operator_inventory(ssh: SSHClient) -> dict[str, Any]:
    return {
        "inventory": {
            "victim": {
                "executor": "ssh",
                "authentication": {
                    "username": LAB_USER,
                    "ssh_key_path": str(Path(ssh._key_path).expanduser()),
                    "port": int(ssh._port),
                    "timeout": 5,
                },
                "hosts": [ssh._ip],
            }
        }
    }


def _resolve_test_guid(atomics_path: Path) -> str:
    technique_path = atomics_path / "T1070.003" / "T1070.003.yaml"
    data = yaml.safe_load(technique_path.read_text()) or {}
    tests = data.get("atomic_tests") or []
    for test in tests:
        if test.get("name") == _TEST_NAME and test.get("auto_generated_guid"):
            return str(test["auto_generated_guid"])
    return _TEST_GUID_FALLBACK


def run(ssh: SSHClient, scenario_id: str) -> dict:
    repo_root = Path(__file__).resolve().parents[2]
    atomics_path = repo_root / "atomics"
    test_guid = _resolve_test_guid(atomics_path)
    operator = AtomicOperator()
    config_data = _build_operator_inventory(ssh)

    with NamedTemporaryFile(mode="w", suffix=".yaml", encoding="utf-8", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        yaml.safe_dump(config_data, tmp, sort_keys=False)

    try:
        operator.run(
            atomics_path=str(atomics_path),
            techniques=["T1070.003"],
            test_guids=[test_guid],
            config_file=str(tmp_path),
            cleanup=True,
        )
    finally:
        tmp_path.unlink(missing_ok=True)

    ground_truth: dict[str, Any] = {
        "scenario_id": scenario_id,
        "scenario": {
            "id": SCENARIO["id"],
            "mitre": SCENARIO["mitre"],
        },
    }
    return ground_truth
