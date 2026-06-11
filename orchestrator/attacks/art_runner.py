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
import shlex
from pathlib import Path
from typing import Any, Callable

# An executor runs one resolved command and returns (exit_code, merged_output).
# Scenarios inject SSHClient.run_shell here so the test command is typed into an
# interactive shell (recorded in ~/.bash_history); the default routes through
# SSHClient.run (one-shot exec, no history).
Executor = Callable[[str, int], "tuple[int, str]"]

import yaml

from orchestrator.core import console
from orchestrator.core.ssh_client import SSHClient

_log = logging.getLogger(__name__)

# Matches both ${arg} and #{arg} placeholder styles used in ART YAMLs.
_PLACEHOLDER = re.compile(r"[\$#]\{([^}]+)\}")

# Where ART asset trees (T<id>/src/...) are SFTP'd on the lab VM. The literal
# token "PathToAtomicsFolder" embedded in YAML defaults is rewritten to this
# path inside _build_command, mirroring upstream atomic-operator behavior.
# /tmp is writeable without sudo and is wiped by the baseline snapshot revert,
# so each experiment starts from a clean upload.
_REMOTE_ATOMICS_ROOT = "/tmp/atomics"


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
        # atomics_path is already absolute -- normalization happens in load_config().
        self._atomics_path = atomics_path

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
        executor: Executor | None = None,
    ) -> dict[str, Any]:
        test = self._load_test(technique_id, test_guid)
        self._ensure_assets(technique_id)
        cmd = self._build_command(test["executor"]["command"], test, input_arguments)
        short_guid = test_guid.split("-", 1)[0] if test_guid else ""
        label = f"{technique_id}/{short_guid}  {test.get('name', '')}".rstrip()
        console.step(label)
        if executor is not None:
            code, out = executor(cmd, timeout)
            err = ""
        else:
            code, out, err = self._ssh.run(cmd, timeout=timeout)
        if code != 0:
            console.warn(f"exit {code}: {err.strip()}")
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
        executor: Executor | None = None,
    ) -> bool:
        """Run executor.cleanup_command if present. Failure is logged, not raised.

        Returns True when a cleanup_command existed and was executed, False when
        the test defines no cleanup. Callers iterating over several tests use the
        return to record which techniques were actually reverted.
        """
        test = self._load_test(technique_id, test_guid)
        cleanup_cmd = test.get("executor", {}).get("cleanup_command")
        if not cleanup_cmd:
            _log.debug("no cleanup defined for %s/%s", technique_id, test_guid)
            return False
        self._ensure_assets(technique_id)
        cmd = self._build_command(cleanup_cmd, test, input_arguments)
        if executor is not None:
            code, err = executor(cmd, timeout)
        else:
            code, _, err = self._ssh.run(cmd, timeout=timeout)
        if code != 0:
            console.warn(
                f"cleanup exited {code} for {technique_id}: {err.strip()}"
            )
        return True

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

        Not called automatically -- invoke explicitly before run_test()
        when a YAML lists dependencies (get_prereq_command sections).
        """
        test = self._load_test(technique_id, test_guid)
        prereqs = test.get("dependencies", [])
        if not prereqs:
            return
        self._ensure_assets(technique_id)

        for i, dep in enumerate(prereqs):
            check_cmd = dep.get("prereq_command")
            install_cmd = dep.get("get_prereq_command")
            if not check_cmd or not install_cmd:
                continue

            check = self._build_command(check_cmd, test, input_arguments)
            code, _, _ = self._ssh.run(check, timeout=timeout)
            if code == 0:
                _log.debug(
                    "prereq %d already satisfied for %s/%s",
                    i, technique_id, test_guid,
                )
                continue

            console.step(f"installing prereq {i}...")
            install = self._build_command(install_cmd, test, input_arguments)
            self._ssh.run_checked(install, timeout=timeout)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_test(self, technique_id: str, guid: str) -> dict[str, Any]:
        yaml_path = self._atomics_path / technique_id / f"{technique_id}.yaml"
        data = yaml.safe_load(yaml_path.read_text()) or {}
        tests = data.get("atomic_tests", []) or []
        # Empty guid: pick the first test defined for the technique.
        # Used by scenarios.yaml entries that don't pin a specific guid.
        if not guid:
            if not tests:
                raise ValueError(f"No atomic_tests defined in {yaml_path}")
            return tests[0]
        for test in tests:
            if test.get("auto_generated_guid") == guid:
                return test
        raise ValueError(f"GUID {guid} not found in {technique_id} ({yaml_path})")

    def _ensure_assets(self, technique_id: str) -> None:
        """
        SFTP the local atomics/<technique_id>/src/ tree to the VM under
        _REMOTE_ATOMICS_ROOT so that ART YAML defaults referencing
        `PathToAtomicsFolder/...` resolve on the test target.

        No-op if the technique has no src/ subtree locally, or if the tree
        is already present on the VM (cheap re-check via `test -d`).
        """
        src_root = self._atomics_path / technique_id / "src"
        if not src_root.is_dir():
            return
        remote_tech_root = f"{_REMOTE_ATOMICS_ROOT}/{technique_id}"
        code, _, _ = self._ssh.run(
            f"test -d {shlex.quote(remote_tech_root)}/src", timeout=10
        )
        if code == 0:
            return
        self._ssh.run_checked(
            f"mkdir -p {shlex.quote(remote_tech_root)}", timeout=10
        )
        uploaded = 0
        for path in sorted(src_root.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(self._atomics_path / technique_id)
            remote = f"{remote_tech_root}/{rel.as_posix()}"
            # Compute the parent in Python instead of shelling out to
            # `dirname` so the remote command takes a single quoted literal.
            remote_dir = f"{remote_tech_root}/{rel.parent.as_posix()}"
            self._ssh.run_checked(
                f"mkdir -p {shlex.quote(remote_dir)}", timeout=10
            )
            self._ssh.put(path, remote)
            uploaded += 1
        console.ok(
            f"uploaded {uploaded} atomics asset(s) for {technique_id} "
            f"to {remote_tech_root}"
        )

    @staticmethod
    def _build_command(
        raw: str,
        test: dict[str, Any],
        overrides: dict[str, str] | None,
    ) -> str:
        """Substitute ${arg} / #{arg} placeholders with defaults + overrides."""
        # YAML `default: null` would otherwise be str()'d into the literal
        # token "None" and spliced into the shell. Coerce explicit nulls and
        # missing defaults to the empty string here.
        defaults: dict[str, str] = {}
        for k, v in (test.get("input_arguments") or {}).items():
            raw_default = v.get("default")
            defaults[k] = "" if raw_default is None else str(raw_default)
        args = {**defaults, **(overrides or {})}

        def _sub(m: re.Match[str]) -> str:
            name = m.group(1)
            if name not in args:
                # Leave the placeholder literal so the surfaced shell error
                # mentions it explicitly instead of silently expanding to "".
                _log.warning(
                    "ART placeholder %r left unresolved (no default or override)",
                    m.group(0),
                )
                return m.group(0)
            return args[name]

        cmd = _PLACEHOLDER.sub(_sub, raw)
        # ART YAML defaults embed the literal token "PathToAtomicsFolder" to
        # mean "the atomics tree on the test target". Map it to the location
        # _ensure_assets uploads to. Mirrors upstream atomic-operator behavior.
        return cmd.replace("PathToAtomicsFolder", _REMOTE_ATOMICS_ROOT)
