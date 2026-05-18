"""Atomic Red Team (ART) test runner via atomic-operator over SSH."""

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
        self._host = host
        self._username = username
        # atomic-operator expects a plain string, not a Path
        self._ssh_key_path = str(Path(ssh_key_path).expanduser().resolve())
        # atomics_path must point to the atomics/ directory itself, as a string
        self._atomics_path = str(Path(atomics_path).expanduser().resolve())

    def run_test(
        self,
        technique_id: str,
        test_guid: str,
        input_arguments: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Execute a single ART test on the remote VM."""
        test_name = self._get_test_name(technique_id, test_guid)

        operator = AtomicOperator()
        operator.run(
            techniques=[technique_id],
            test_guids=[test_guid],
            atomics_path=self._atomics_path,
            hosts=[self._host],
            username=self._username,
            ssh_key_path=self._ssh_key_path,
            # never pass private_key_string: the PKey() constructor is broken
            # for Ed25519 keys; key_filename= works correctly in paramiko
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
        """Execute cleanup commands for a test."""
        operator = AtomicOperator()
        operator.run(
            techniques=[technique_id],
            test_guids=[test_guid],
            atomics_path=self._atomics_path,
            hosts=[self._host],
            username=self._username,
            ssh_key_path=self._ssh_key_path,
            cleanup=True,
            command_timeout=60,
            input_arguments=input_arguments or {},
        )

    def _get_test_name(self, technique_id: str, test_guid: str) -> str:
        """Look up test name from YAML metadata."""
        path = Path(self._atomics_path) / technique_id / f"{technique_id}.yaml"
        if not path.exists():
            return ""
        data = yaml.safe_load(path.read_text()) or {}
        for test in data.get("atomic_tests", []):
            if test.get("auto_generated_guid") == test_guid:
                return test.get("name", "")
        return ""
