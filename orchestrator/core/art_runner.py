"""Atomic Red Team test runner using atomic-operator CLI via subprocess."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)


class ArtRunner:
    """Executes ART tests via atomic-operator CLI subprocess wrapper."""

    def __init__(
        self,
        host: str,
        username: str,
        ssh_key_path: str | Path,
        atomics_path: Path,
        art_bin: str = ".venv-art/bin/atomic-operator",
    ) -> None:
        self._host = host
        self._username = username
        self._ssh_key_path = str(Path(ssh_key_path).expanduser().resolve())
        self._atomics_path = str(Path(atomics_path).expanduser().resolve())
        self._art_bin = art_bin

    def run_test(
        self,
        technique_id: str,
        test_guid: str,
        input_arguments: dict[str, str] | None = None,
        cleanup: bool = False,
    ) -> dict[str, Any]:
        """
        Execute an ART test via atomic-operator CLI.

        Args:
            technique_id: e.g., "T1059.004"
            test_guid: Test GUID from YAML
            input_arguments: Optional override arguments
            cleanup: If True, run cleanup instead of test

        Returns:
            Dict with guid, name, stdout, stderr, and full result

        Raises:
            RuntimeError: If subprocess fails and no JSON found
        """
        cmd = [
            self._art_bin,
            "run",
            "--techniques",
            technique_id,
            "--test-guids",
            test_guid,
            "--atomics-path",
            self._atomics_path,
            "--hosts",
            self._host,
            "--username",
            self._username,
            "--ssh-key-path",
            self._ssh_key_path,
            "--cleanup",
            str(cleanup),
            "--command-timeout",
            "60",
        ]

        if input_arguments:
            for name, value in input_arguments.items():
                cmd.extend(["--input-argument", f"{name}={value}"])

        _log.debug("[*] Running: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"atomic-operator timed out after 120s: {exc}") from exc
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"atomic-operator binary not found: {self._art_bin}"
            ) from exc

        if result.returncode != 0:
            _log.warning("[!] atomic-operator exit code: %d", result.returncode)
            _log.debug("[!] stderr: %s", result.stderr)

        parsed_result = self._parse_json_result(result.stdout, test_guid)
        if parsed_result is None:
            parsed_result = {}

        if result.returncode != 0 and not parsed_result:
            raise RuntimeError(
                f"atomic-operator failed with exit code {result.returncode}. "
                f"stderr: {result.stderr}"
            )

        return {
            "guid": test_guid,
            "name": parsed_result.get("name", ""),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "result": parsed_result,
        }

    def run_cleanup(
        self,
        technique_id: str,
        test_guid: str,
        input_arguments: dict[str, str] | None = None,
    ) -> None:
        """Run cleanup for a test (calls run_test with cleanup=True)."""
        self.run_test(
            technique_id,
            test_guid,
            input_arguments=input_arguments,
            cleanup=True,
        )

    @staticmethod
    def _parse_json_result(stdout: str, test_guid: str) -> dict[str, Any] | None:
        """
        Parse JSON result from atomic-operator stdout.

        The output format is: <guid> <json_object>
        Returns the parsed JSON object or None if not found.
        """
        for line in stdout.split("\n"):
            line = line.strip()
            if not line:
                continue

            if line.startswith(test_guid):
                json_part = line[len(test_guid) :].strip()
                if json_part:
                    try:
                        return json.loads(json_part)
                    except json.JSONDecodeError as exc:
                        _log.warning("[!] Failed to parse JSON: %s", exc)
                        return None

        return None
