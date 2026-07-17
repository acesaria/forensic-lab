"""Thin host hook for the Father system-wide preload calibration."""
import json
import shlex
from pathlib import Path

import yaml

from orchestrator.core.provenance import excerpt, file_sha256
from orchestrator.scenarios.executors import SSHClientExecutor

ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / "files/father-upstream-4eb2712.tar"
LOCK = ROOT / "father.lock.yml"
SCRIPT = ROOT / "files/run_father_calibration.sh"
HELPER = ROOT / "files/activate_system_preload.py"


def run_father_calibration(ctx, step):
    if not isinstance(ctx.executor, SSHClientExecutor):
        raise RuntimeError("userland_father_ldpreload requires the VM-backed SSH executor; local execution is refused")
    paths = ctx.parameters
    lock = yaml.safe_load(LOCK.read_text(encoding="utf-8"))
    archive_hash = file_sha256(ARCHIVE)
    expected_hash = lock["retrieval"]["archive_sha256"]
    if archive_hash != expected_hash:
        raise RuntimeError(f"Father archive SHA-256 mismatch: expected {expected_hash}, got {archive_hash}")

    assets = (
        (ARCHIVE, paths["upstream_archive_path"]),
        (SCRIPT, paths["run_script_path"]),
        (HELPER, paths["activation_helper_path"]),
    )
    for source, destination in assets:
        ctx.executor.put(source, destination)

    command = shlex.join(
        ["bash", paths["run_script_path"], paths["root"],
         paths["installed_library_path"], paths["preload_config_path"],
         paths["preload_backup_path"], paths["preload_absent_marker_path"],
         str(paths["process_duration_seconds"])]
    )
    started = ctx.now()
    result = ctx.executor.run_in_terminal(command, timeout=180)
    ctx.log_step(
        {
            "step_id": step["id"],
            "record_type": "scenario_command",
            "actor": "scenario",
            "command": command,
            "uploads": [destination for _source, destination in assets],
            "source": {"repository": lock["upstream"]["url"],
                       "commit": lock["upstream"]["pinned_commit"],
                       "archive_sha256": archive_hash},
            "exit_code": result.exit_code,
            "terminal_transcript_excerpt": excerpt(result.stdout),
            "status": "success" if result.exit_code == 0 else "failure",
            "started_at": started,
            "ended_at": ctx.now(),
        }
    )
    if result.exit_code != 0:
        raise RuntimeError(f"Father terminal exited {result.exit_code}: {excerpt(result.stdout)}")
    facts = {}
    for line in reversed(result.stdout.splitlines()):
        try:
            facts = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(facts, dict):
            break
    validation = facts.get("validation_result", {})
    if validation.get("status") != "passed" or len(facts.get("affected_pids", [])) != 3:
        raise RuntimeError("Father script did not return three validated mappings")
    validation.update(system_wide_mapping="passed", file_hiding="passed")
    facts["file_hiding_validation"] = {
        "status": "passed", "marker_path": paths["hiding_marker_path"],
        "before_output": paths["hiding_before_path"],
        "after_output": paths["hiding_after_path"],
    }
    ctx.record_scenario_facts(facts)
