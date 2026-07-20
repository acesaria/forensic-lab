#!/usr/bin/env python3
"""Direct live calibration; intentionally not collected by pytest."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from infra.provider import Provider
from orchestrator.core.config import BASELINE_SNAPSHOT, LAB_VM_PREFIX, load_config
from orchestrator.core.paths import ProjectPaths
from orchestrator.core.vm_manager import VMManager
from scenarios.interactive_shell.runner import (
    ARTIFACT_FILE,
    COMMANDS,
    EXPECTED_FAILURE,
    run_interactive_shell,
)


DISTRO = "ubuntu-22.04"
TRANSCRIPT = ROOT / "shared" / "live_interactive_shell_terminal_transcript.txt"


def _history(ssh) -> list[str]:
    code, output, error = ssh.run(
        "test ! -e ~/.bash_history || cat ~/.bash_history",
        timeout=30,
    )
    if code != 0:
        raise RuntimeError(f"failed to read .bash_history: {error.strip()}")
    return output.splitlines()


def _ordered_entries(lines: list[str], expected: tuple[str, ...]) -> list[str]:
    found: list[str] = []
    offset = 0
    for command in expected:
        try:
            index = lines.index(command, offset)
        except ValueError as exc:
            raise RuntimeError(
                f".bash_history is missing the new scenario command: {command}"
            ) from exc
        found.append(lines[index])
        offset = index + 1
    return found


def main() -> None:
    cfg = load_config(ROOT)
    host = cfg["host"]
    paths = ProjectPaths.from_config(ROOT, host)
    provider = Provider(
        libvirt_uri=host["libvirt_uri"],
        pool_name=host["pool_name"],
        pool_path=paths.pool_dir,
        network_name=host["isolated_network_name"],
    )
    vm = VMManager(provider=provider, paths=paths)
    vm_name = f"{LAB_VM_PREFIX}-{DISTRO}"

    try:
        print(f"restoring {vm_name} snapshot {BASELINE_SNAPSHOT}")
        vm.revert_to_baseline(DISTRO)
        vm.start_vm(vm_name)
        vm.wait_ssh_ready(vm_name, reason="live interactive shell calibration")

        with vm.open_ssh(vm_name) as ssh:
            before_history = _history(ssh)
            results = run_interactive_shell(ssh, TRANSCRIPT)
            after_history = _history(ssh)

            if after_history[: len(before_history)] != before_history:
                raise RuntimeError(".bash_history was not naturally appended")
            added_history = after_history[len(before_history) :]
            relevant_history = _ordered_entries(added_history, COMMANDS)

            by_command = {result.command: result for result in results}
            failed = by_command[EXPECTED_FAILURE]
            if failed.exit_code == 0 or "command not found" not in failed.combined_output:
                raise RuntimeError("nonexistent command did not produce the expected failure")

            continued = by_command[COMMANDS[3]]
            if continued.exit_code != 0:
                raise RuntimeError("the shell did not continue after the expected failure")

            first_pid = re.search(r"Bash PID: (\d+)", results[0].combined_output)
            later_pid = re.search(
                r"Bash PID after failure: (\d+)",
                continued.combined_output,
            )
            if (
                first_pid is None
                or later_pid is None
                or first_pid.group(1) != later_pid.group(1)
            ):
                raise RuntimeError("Bash PID changed after the expected failure")

            file_contents = ssh.run_checked(f"cat {ARTIFACT_FILE}", timeout=30)
            if file_contents != "Interactive shell artifact":
                raise RuntimeError(f"unexpected artifact contents: {file_contents!r}")

            print(f"nonexistent command exit: {failed.exit_code}")
            print(f"Bash PID before/after failure: {first_pid.group(1)}")
            print(f"artifact: {ARTIFACT_FILE}: {file_contents}")
            print(f"transcript: {TRANSCRIPT}")
            print(".bash_history entries:")
            for entry in relevant_history:
                print(f"  {entry}")
    finally:
        try:
            if provider.is_running(vm_name):
                vm.shutdown_vm(vm_name)
        finally:
            final_off = not provider.is_running(vm_name)
            print(f"final VM state: {'off' if final_off else 'not off'}")
            provider.close()
        if not final_off:
            raise RuntimeError(f"{vm_name} did not power off")


if __name__ == "__main__":
    main()
