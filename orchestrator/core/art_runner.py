"""Atomic Red Team (ART) test runner via atomic-operator and atomic_operator_runner over SSH."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from atomic_operator import AtomicOperator


class ArtRunner:
    """Thin adapter over atomic-operator for executing ART tests via SSH."""

    def __init__(
        self,
        host: str,
        username: str,
        ssh_key_path: str | Path,
        atomics_path: Path,
    ) -> None:
        """
        Initialize ART runner.

        Args:
            host: Remote VM IP or hostname.
            username: SSH username on remote VM.
            ssh_key_path: Path to SSH private key.
            atomics_path: Path to atomics directory containing YAML files.
        """
        self._host = host
        self._username = username
        self._ssh_key_path = str(Path(ssh_key_path).expanduser())
        self._private_key_string = Path(self._ssh_key_path).read_text()
        self._atomics_path = Path(atomics_path)

    def run_test(
        self,
        technique_id: str,
        test_guid: str,
        input_arguments: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """
        Execute a single ART test on the remote VM.

        Args:
            technique_id: MITRE ATT&CK technique (e.g., "T1059.004").
            test_guid: UUID of the test within the technique.
            input_arguments: Optional test input arguments.

        Returns:
            Dict with keys: guid, name, stdout, stderr.
        """
        test_name = self._get_test_name(technique_id, test_guid)

        operator = AtomicOperator()
        operator.run(
            techniques=[technique_id],
            test_guids=[test_guid],
            atomics_path=str(self._atomics_path),
            hosts=[self._host],
            username=self._username,
            ssh_key_path=None,
            private_key_string=self._private_key_string,
            cleanup=False,
            command_timeout=60,
            input_arguments=input_arguments or {},
        )

        return {
            "guid": test_guid,
            "name": test_name,
            "stdout": "",
            "stderr": "",
        }

    def run_cleanup(
        self,
        technique_id: str,
        test_guid: str,
        input_arguments: dict[str, str] | None = None,
    ) -> None:
        """
        Execute cleanup commands for a test.

        Args:
            technique_id: MITRE ATT&CK technique (e.g., "T1059.004").
            test_guid: UUID of the test.
            input_arguments: Optional cleanup arguments.
        """
        operator = AtomicOperator()
        operator.run(
            techniques=[technique_id],
            test_guids=[test_guid],
            atomics_path=str(self._atomics_path),
            hosts=[self._host],
            username=self._username,
            ssh_key_path=None,
            private_key_string=self._private_key_string,
            cleanup=True,
            command_timeout=60,
            input_arguments=input_arguments or {},
        )

    def _get_test_name(self, technique_id: str, test_guid: str) -> str:
        """
        Look up test name from YAML metadata.

        Args:
            technique_id: MITRE ATT&CK technique.
            test_guid: Test UUID.

        Returns:
            Test name string, or empty if not found.
        """
        path = self._atomics_path / technique_id / f"{technique_id}.yaml"
        if not path.exists():
            return ""

        data = yaml.safe_load(path.read_text()) or {}
        for test in data.get("atomic_tests", []):
            if test.get("auto_generated_guid") == test_guid:
                return test.get("name", "")

        return ""
