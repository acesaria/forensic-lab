"""
orchestrator/attacks/art_runner.py

Executes ART atomic tests on a remote VM via SSHClient.
Parses YAML, resolves input arguments, builds the shell command,
and delegates execution to the already-connected SSHClient.

Prerequisites are NOT run automatically. Call run_prerequisites()
explicitly before run_test() when a test needs them.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml

from orchestrator.core.ssh_client import SSHClient

_log = logging.getLogger(__name__)

# Matches both ${arg} and #{arg} placeholder styles used in ART YAMLs.
_PLACEHOLDER = re.compile(r"[\$#]\{([^}]+)\}")


class ArtRunner:
    """
    Executes a single ART atomic test on a remote VM.

    Usage:
        with SSHClient(ip, user, key) as ssh:
            runner = ArtRunner(ssh, Path("atomics"))
            runner.run_test("T1574.006", "<guid>")
    """

    def __init__(self, ssh: SSHClient, atomics_path: Path) -> None:
        self._ssh = ssh
        self._atomics_path = Path(atomics_path).expanduser().resolve()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_test(
        self,
        technique_id: str,
        test_guid: str,
        input_arguments: dict[str, str] | None = None,
        timeout: int = 60,
        raise_on_error: bool = True,
    ) -> dict[str, Any]:
        test = self._load_test(technique_id, test_guid)
        cmd = self._build_command(test["executor"]["command"], test, input_arguments)
        _log.info("[*] %s/%s  %s", technique_id, test_guid, test.get("name", ""))
        code, out, err = self._ssh.run(cmd, timeout=timeout)
        if code != 0:
            _log.warning(
                "[!] exit %d for %s/%s: %s", code, technique_id, test_guid, err.strip()
            )
            if raise_on_error:
                raise RuntimeError(
                    f"ART test {technique_id}/{test_guid} exited {code}.\n{err.strip()}"
                )
        return {
            "guid": test_guid,
            "name": test.get("name", ""),
            "exit_code": code,
            "stdout": out,
            "stderr": err,
        }

    def run_cleanup(
        self,
        technique_id: str,
        test_guid: str,
        input_arguments: dict[str, str] | None = None,
        timeout: int = 60,
    ) -> None:
        """Run executor.cleanup_command if present. Failure is logged, not raised."""
        test = self._load_test(technique_id, test_guid)
        cleanup_cmd = test.get("executor", {}).get("cleanup_command")
        if not cleanup_cmd:
            _log.debug("No cleanup defined for %s/%s", technique_id, test_guid)
            return
        cmd = self._build_command(cleanup_cmd, test, input_arguments)
        code, out, err = self._ssh.run(cmd, timeout=timeout)
        if code != 0:
            _log.warning(
                "[!] Cleanup exited %d for %s/%s: %s",
                code,
                technique_id,
                test_guid,
                err.strip(),
            )

    def run_prerequisites(
        self,
        technique_id: str,
        test_guid: str,
        input_arguments: dict[str, str] | None = None,
        timeout: int = 120,
    ) -> None:
        """
        Run all prereq_command entries whose check_prereq_command fails.

        Each prerequisite is: run check, skip if exit 0, run prereq if non-zero.
        Raises RuntimeError if a prereq_command itself fails.

        Not called automatically – invoke explicitly before run_test()
        when a YAML lists dependencies (get_prereq_command sections).
        """
        test = self._load_test(technique_id, test_guid)
        prereqs = test.get("dependencies", [])
        if not prereqs:
            return

        for i, dep in enumerate(prereqs):
            check_cmd = dep.get("prereq_command")
            install_cmd = dep.get("get_prereq_command")
            if not check_cmd or not install_cmd:
                continue

            check = self._build_command(check_cmd, test, input_arguments)
            code, _, _ = self._ssh.run(check, timeout=timeout)
            if code == 0:
                _log.debug(
                    "Prereq %d already satisfied for %s/%s", i, technique_id, test_guid
                )
                continue

            _log.info("[*] Installing prereq %d for %s/%s", i, technique_id, test_guid)
            install = self._build_command(install_cmd, test, input_arguments)
            self._ssh.run_checked(install, timeout=timeout)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_test(self, technique_id: str, guid: str) -> dict[str, Any]:
        yaml_path = self._atomics_path / technique_id / f"{technique_id}.yaml"
        data = yaml.safe_load(yaml_path.read_text()) or {}
        for test in data.get("atomic_tests", []):
            if test.get("auto_generated_guid") == guid:
                return test
        raise ValueError(f"GUID {guid} not found in {technique_id} ({yaml_path})")

    @staticmethod
    def _build_command(
        raw: str,
        test: dict[str, Any],
        overrides: dict[str, str] | None,
    ) -> str:
        """Substitute ${arg} / #{arg} placeholders with defaults + overrides."""
        defaults = {
            k: str(v.get("default", ""))
            for k, v in (test.get("input_arguments") or {}).items()
        }
        args = {**defaults, **(overrides or {})}
        return _PLACEHOLDER.sub(lambda m: args.get(m.group(1), m.group(0)), raw)
