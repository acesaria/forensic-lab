"""Four host-side steps for the Father system-wide preload calibration."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from orchestrator.core import console
from orchestrator.core.provenance import excerpt, file_sha256
from orchestrator.scenarios.executors import SSHClientExecutor


SCENARIO_ROOT = Path(__file__).resolve().parent
FATHER_ARCHIVE = SCENARIO_ROOT / "files/father-upstream-4eb2712.tar"
FATHER_LOCK = SCENARIO_ROOT / "father.lock.yml"
ACTIVATION_HELPER = SCENARIO_ROOT / "files/activate_system_preload.py"
FATHER_REPOSITORY = "https://github.com/mav8557/Father"
FATHER_COMMIT = "4eb2712caf612a7dc55fd4f34ff5c72b74c7c332"


def prepare_father_source(ctx, step):
    """Copy the pinned source and the small activation helper into the guest."""
    paths = _vm_parameters(ctx)
    console.step("1/4 Staging pinned Father source...")

    for source, destination in (
        (FATHER_ARCHIVE, paths["upstream_archive_path"]),
        (FATHER_LOCK, paths["father_lock_path"]),
        (ACTIVATION_HELPER, paths["activation_helper_path"]),
    ):
        _upload(ctx, step, source, destination)

    ctx.log_step(
        {
            "step_id": step["id"],
            "record_type": "source_provenance",
            "actor": "lab",
            "repository": FATHER_REPOSITORY,
            "commit": FATHER_COMMIT,
            "archive_sha256": file_sha256(FATHER_ARCHIVE),
            "status": "success",
            "ended_at": ctx.now(),
        }
    )


def configure_father(ctx, step):
    """Extract Father and set the fixed calibration values in its config.h."""
    paths = _vm_parameters(ctx)
    console.step("2/4 Configuring the extracted Father copy...")

    values = {
        "PRELOAD": paths["preload_hide_token"],
        "INSTALL_LOCATION": paths["installed_library_path"],
    }
    replacements = " ".join(
        f"-e {shlex.quote(f's|^#define {key} .*|#define {key} \"{value}\"|')}"
        for key, value in values.items()
    )
    _run(
        ctx,
        step,
        f"rm -rf {shlex.quote(paths['father_source_tree'])} && "
        f"mkdir -p {shlex.quote(paths['source_dir'])} && "
        f"tar -xf {shlex.quote(paths['upstream_archive_path'])} "
        f"-C {shlex.quote(paths['source_dir'])} && "
        f"test -f {shlex.quote(paths['father_config_path'])}",
        actor="lab",
        record_type="source_prepare",
    )
    _run(
        ctx,
        step,
        f"sed -i {replacements} {shlex.quote(paths['father_config_path'])}",
        actor="scenario",
        record_type="scenario_command",
    )
    _run(
        ctx,
        step,
        f"sha256sum {shlex.quote(paths['father_config_path'])}",
        actor="lab",
        record_type="measurement",
    )


def build_father_rootkit(ctx, step):
    """Verify build prerequisites, then build the pinned rk.so."""
    paths = _vm_parameters(ctx)
    console.step(
        "3/4 Verifying baseline build prerequisites and building pinned Father "
        "rk.so (no scenario-time package installation)..."
    )
    _ensure_build_dependencies(ctx, step)

    _run(
        ctx,
        step,
        f"cd {shlex.quote(paths['father_source_tree'])} && "
        "(make clean >/dev/null 2>&1 || true) && make father",
        timeout=120,
        actor="scenario",
        record_type="scenario_command",
    )
    _run(
        ctx,
        step,
        f"test -f {shlex.quote(paths['father_built_library_path'])} && "
        f"sha256sum {shlex.quote(paths['father_built_library_path'])}",
        actor="lab",
        record_type="measurement",
    )


def install_activate_and_validate(ctx, step):
    """Run the guest transaction that installs, activates, and validates Father."""
    paths = _vm_parameters(ctx)
    console.step("4/4 Activating system-wide preload...")

    helper_args = [
        "/usr/bin/python3",
        paths["activation_helper_path"],
        "--built-library",
        paths["father_built_library_path"],
        "--installed-library",
        paths["installed_library_path"],
        "--preload-config",
        paths["preload_config_path"],
        "--backup-path",
        paths["preload_backup_path"],
        "--absent-marker",
        paths["preload_absent_marker_path"],
        "--duration",
        str(paths["process_duration_seconds"]),
    ]
    result = _run(
        ctx,
        step,
        "sudo -n " + shlex.join(helper_args),
        timeout=60,
        actor="scenario",
        record_type="scenario_command",
        check=False,
    )
    facts = _last_json(result.stdout if result.exit_code == 0 else result.stderr)
    if facts:
        ctx.record_scenario_facts(facts)
    if result.exit_code != 0:
        raise RuntimeError((result.stderr or result.stdout).strip())
    if facts.get("validation_result", {}).get("status") != "passed":
        raise RuntimeError("Father activation did not report successful validation")


def _vm_parameters(ctx) -> dict:
    if not isinstance(ctx.executor, SSHClientExecutor):
        raise RuntimeError(
            "userland_father_ldpreload requires the VM-backed SSH executor; "
            "local execution is refused"
        )
    return ctx.parameters


def _upload(ctx, step, source: Path, destination: str) -> None:
    ctx.executor.put(source, destination)
    ctx.log_step(
        {
            "step_id": step["id"],
            "record_type": "upload",
            "actor": "lab",
            "action": "put",
            "src": str(source),
            "dest": destination,
            "status": "success",
            "ended_at": ctx.now(),
        }
    )


def _run(
    ctx,
    step,
    command: str,
    *,
    actor: str,
    record_type: str,
    timeout: int = 120,
    check: bool = True,
):
    started = ctx.now()
    result = ctx.executor.run(command, timeout=timeout)
    ctx.log_step(
        {
            "step_id": step["id"],
            "record_type": record_type,
            "actor": actor,
            "action": "run",
            "command": command,
            "exit_code": result.exit_code,
            "stdout_excerpt": excerpt(result.stdout),
            "stderr_excerpt": excerpt(result.stderr),
            "status": "success" if result.exit_code == 0 else "failure",
            "started_at": started,
            "ended_at": ctx.now(),
        }
    )
    if check and result.exit_code != 0:
        raise RuntimeError((result.stderr or result.stdout).strip())
    return result


def _ensure_build_dependencies(ctx, step) -> None:
    prerequisites = ctx.prerequisites.get("father_build") or {}
    items = [
        item
        for group in ("tools", "headers", "libraries")
        for item in prerequisites.get(group) or []
    ]
    checks = " && ".join(f"({item['check']})" for item in items)
    result = _run(
        ctx,
        step,
        checks,
        actor="lab",
        record_type="prerequisite",
        check=False,
    )
    if result.exit_code == 0:
        return
    raise RuntimeError("VM baseline is missing Father build prerequisites")


def _last_json(output: str) -> dict:
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return {}
