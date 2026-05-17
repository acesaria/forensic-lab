"""Minimal ART (Atomic Red Team) test runner via SSH."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from orchestrator.core.ssh_client import SSHClient


class ArtRunner:
    def __init__(self, ssh: SSHClient, atomics_path: Path) -> None:
        self._ssh = ssh
        self._atomics_path = Path(atomics_path)

    def run_test(
        self,
        technique_id: str,
        test_guid: str,
        input_arguments: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        test = self._find_test(technique_id, test_guid)
        if not test:
            raise RuntimeError(f"Test {test_guid} not found in {technique_id}")
        return {
            "guid": test.get("auto_generated_guid"),
            "name": test.get("name"),
            "stdout": self._ssh.run(self._resolve_command(test, input_arguments or {})),
        }

    def run_cleanup(
        self,
        technique_id: str,
        test_guid: str,
        input_arguments: dict[str, str] | None = None,
    ) -> None:
        test = self._find_test(technique_id, test_guid)
        if test and test.get("executor", {}).get("cleanup_command"):
            cmd = test["executor"]["cleanup_command"].strip()
            if cmd:
                self._ssh.run_checked(
                    self._resolve_command_string(cmd, test, input_arguments or {})
                )

    def _find_test(self, technique_id: str, test_guid: str) -> dict | None:
        path = self._atomics_path / technique_id / f"{technique_id}.yaml"
        for test in (yaml.safe_load(path.read_text()) or {}).get("atomic_tests") or []:
            if test.get("auto_generated_guid") == test_guid:
                return test
        return None

    def _resolve_command(self, test: dict, args: dict[str, str]) -> str:
        return self._resolve_command_string(
            test.get("executor", {}).get("command", "").strip(), test, args
        )

    def _resolve_command_string(
        self, command: str, test: dict, args: dict[str, str]
    ) -> str:
        for key, spec in (test.get("input_arguments") or {}).items():
            val = args.get(key, spec.get("default", ""))
            command = command.replace(f"#{{{key}}}", str(val))
        return command
