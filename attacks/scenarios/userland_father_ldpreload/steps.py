from __future__ import annotations

import hashlib
import shlex
from pathlib import Path


SCENARIO_ROOT = Path(__file__).resolve().parent
FILES_DIR = SCENARIO_ROOT / "files"
FATHER_REPOSITORY = "https://github.com/mav8557/Father"
FATHER_COMMIT = "4eb2712caf612a7dc55fd4f34ff5c72b74c7c332"
FATHER_LICENSE = "Unlicense"
FATHER_ARCHIVE = FILES_DIR / "father-upstream-4eb2712.tar"
LAB_SAFE_MODE = "lab-safe-harness"


def prepare_sample(ctx, step):
    source = FILES_DIR / "father_lab_preload.c"
    metadata = FILES_DIR / "father_sample.lock.yml"
    archive_path = _param(ctx, "upstream_archive_path")
    source_path = _param(ctx, "source_path")
    metadata_path = _param(ctx, "metadata_path")
    _put(ctx, FATHER_ARCHIVE, archive_path)
    _put(ctx, source, source_path)
    _put(ctx, metadata, metadata_path)

    archive_sha = _sha256_local(FATHER_ARCHIVE)
    source_sha = _sha256_local(source)
    metadata_sha = _sha256_local(metadata)
    ctx.record_truth(
        _step_id(step),
        {
            "event_type": "sample_prepared",
            "object_type": "external_sample_reference",
            "object_identity": FATHER_REPOSITORY,
            "action": "prepare",
            "actor": "lab",
            "evidence_basis": ["disk"],
            "attck": ["T1014"],
            "details": {
                "repository": FATHER_REPOSITORY,
                "upstream_commit": FATHER_COMMIT,
                "license": FATHER_LICENSE,
                "lab_safe_mode": LAB_SAFE_MODE,
                "vendored_original_source": True,
                "executed_original_source": False,
                "upstream_archive_path": archive_path,
                "upstream_archive_sha256": archive_sha,
                "source_path": source_path,
                "source_sha256": source_sha,
                "metadata_path": metadata_path,
                "metadata_sha256": metadata_sha,
                "safety_disabled": [
                    "remote_backdoor",
                    "reverse_shell",
                    "privilege_escalation",
                    "gnupg_tampering",
                    "logic_bomb",
                    "destructive_anti_detection",
                    "propagation",
                    "exfiltration",
                ],
            },
        },
    )


def deploy_library(ctx, step):
    source_path = _param(ctx, "source_path")
    library_path = _param(ctx, "library_path")
    cmd = (
        f"mkdir -p {shlex.quote(str(Path(library_path).parent))} && "
        f"(cc -shared -fPIC -DLAB_SAFE=1 -o {shlex.quote(library_path)} "
        f"{shlex.quote(source_path)} || "
        f"gcc -shared -fPIC -DLAB_SAFE=1 -o {shlex.quote(library_path)} "
        f"{shlex.quote(source_path)}) && "
        f"chmod 0644 {shlex.quote(library_path)} && "
        f"sha256sum {shlex.quote(library_path)} && "
        f"stat -c '%s|%U|%G|%a' {shlex.quote(library_path)}"
    )
    result = _run_checked(ctx, cmd, timeout=60)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    sha256 = lines[-2].split()[0] if len(lines) >= 2 else ""
    size, owner, group, mode = _split_stat(lines[-1] if lines else "0|unknown|unknown|unknown")
    ctx.record_truth(
        _step_id(step),
        {
            "event_type": "library_deployed",
            "object_type": "path",
            "object_identity": library_path,
            "action": "deploy",
            "actor": "attacker",
            "evidence_basis": ["disk"],
            "attck": ["T1574.006", "T1014"],
            "details": {
                "sha256": sha256,
                "size": size,
                "owner": owner,
                "group": group,
                "mode": mode,
                "source_path": source_path,
                "lab_safe_mode": LAB_SAFE_MODE,
            },
        },
    )


def modify_preload_config(ctx, step):
    library_path = _param(ctx, "library_path")
    config_path = _param(ctx, "preload_config_path")
    cmd = (
        f"mkdir -p {shlex.quote(str(Path(config_path).parent))} && "
        f"printf '%s\\n' {shlex.quote(library_path)} > {shlex.quote(config_path)} && "
        f"chmod 0644 {shlex.quote(config_path)} && "
        f"sha256sum {shlex.quote(config_path)}"
    )
    result = _run_checked(ctx, cmd)
    content_sha = result.stdout.split()[0] if result.stdout.split() else ""
    ctx.record_truth(
        _step_id(step),
        {
            "event_type": "preload_config_modified",
            "object_type": "path",
            "object_identity": config_path,
            "action": "modify",
            "actor": "attacker",
            "evidence_basis": ["disk", "timeline"],
            "attck": ["T1574.006"],
            "details": {
                "library_path": library_path,
                "content_sha256": content_sha,
                "lab_only": True,
                "note": "Lab-only preload configuration artifact; /etc/ld.so.preload is not modified by default.",
            },
        },
    )


def start_benign_process(ctx, step):
    library_path = _param(ctx, "library_path")
    cwd = _param(ctx, "process_cwd")
    stdout_path = _param(ctx, "process_stdout_path")
    pid_path = _param(ctx, "process_pid_path")
    duration = str(_param(ctx, "process_duration_seconds"))
    # nohup + redirected stdin/stdout detaches the benign process from the SSH
    # exec channel so it survives the channel closing and stays alive through the
    # memory-acquisition window. This is the documented keep-after-logout idiom,
    # not stealth: the process remains a plainly visible child of init.
    cmd = (
        f"mkdir -p {shlex.quote(cwd)} && "
        f"cd {shlex.quote(cwd)} && "
        f"(nohup env LD_PRELOAD={shlex.quote(library_path)} /bin/sleep {shlex.quote(duration)} "
        f"</dev/null > {shlex.quote(stdout_path)} 2>&1 & echo $! > {shlex.quote(pid_path)}) && "
        f"sleep 0.3 && pid=$(cat {shlex.quote(pid_path)}) && "
        f"ps -o pid=,ppid=,uid=,args= -p \"$pid\""
    )
    result = _run_checked(ctx, cmd)
    proc = _parse_ps(result.stdout)
    pid = proc.get("pid") or _read_remote(ctx, pid_path).strip()
    ctx.record_truth(
        _step_id(step),
        {
            "event_type": "benign_process_started",
            "object_type": "process",
            "object_identity": str(pid),
            "action": "execute",
            "actor": "attacker",
            "evidence_basis": ["memory", "log"],
            "attck": ["T1059.004"],
            "details": {
                "pid": pid,
                "ppid": proc.get("ppid"),
                "uid": proc.get("uid"),
                "argv": proc.get("argv") or f"/bin/sleep {duration}",
                "cwd": cwd,
                "library_path": library_path,
                "stdout_path": stdout_path,
                "pid_path": pid_path,
            },
        },
    )

    maps = _run(ctx, f"grep -F {shlex.quote(library_path)} /proc/{shlex.quote(str(pid))}/maps || true")
    observed = bool(maps.stdout.strip())
    ctx.record_truth(
        "library_observed_in_process",
        {
            "event_type": "library_observed_in_process",
            "object_type": "path",
            "object_identity": library_path,
            "action": "observe",
            "actor": "lab",
            "evidence_basis": ["memory"] if observed else ["unknown"],
            "attck": ["T1574.006", "T1014"],
            "details": {
                "pid": pid,
                "library_path": library_path,
                "maps_excerpt": maps.stdout.strip(),
                "observed": observed,
            },
        },
    )


def observe_or_mark_hiding_feature(ctx, step):
    marker_path = _param(ctx, "hiding_marker_path")
    cleanup_marker = _param(ctx, "cleanup_marker_path")
    text = (
        "Father hiding behavior represented as forensic_marker_only. "
        "No file/process hiding hooks are enabled in this lab-safe harness."
    )
    cmd = (
        f"mkdir -p {shlex.quote(str(Path(marker_path).parent))} && "
        f"printf '%s\\n' {shlex.quote(text)} > {shlex.quote(marker_path)} && "
        f"printf 'transient cleanup marker\\n' > {shlex.quote(cleanup_marker)}"
    )
    _run_checked(ctx, cmd)
    ctx.record_truth(
        _step_id(step),
        {
            "event_type": "hiding_feature_demonstrated_or_marked",
            "object_type": "path",
            "object_identity": marker_path,
            "action": "mark",
            "actor": "lab",
            "evidence_basis": ["disk", "timeline"],
            "attck": ["T1014"],
            "details": {
                "mode": "forensic_marker_only",
                "marker_path": marker_path,
                "cleanup_marker_path": cleanup_marker,
                "note": text,
            },
        },
    )


def partial_cleanup(ctx, step):
    cleanup_marker = _param(ctx, "cleanup_marker_path")
    remaining = [
        _param(ctx, "library_path"),
        _param(ctx, "preload_config_path"),
        _param(ctx, "hiding_marker_path"),
    ]
    _run_checked(ctx, f"rm -f {shlex.quote(cleanup_marker)}")
    ctx.record_truth(
        _step_id(step),
        {
            "event_type": "partial_cleanup",
            "object_type": "path",
            "object_identity": cleanup_marker,
            "action": "delete",
            "actor": "attacker",
            "evidence_basis": ["disk", "timeline"],
            "attck": ["T1070.004"],
            "details": {
                "deleted_paths": [cleanup_marker],
                "remaining_paths": remaining,
                "cleanup_scope": "partial",
            },
        },
    )


def _param(ctx, name: str):
    return ctx.render(ctx.parameters[name])


def _put(ctx, src: Path, dest: str) -> None:
    ctx.executor.put(src, str(dest))


def _run(ctx, command: str, timeout: int = 120):
    return ctx.executor.run(command, timeout=timeout)


def _run_checked(ctx, command: str, timeout: int = 120):
    result = _run(ctx, command, timeout=timeout)
    if result.exit_code != 0:
        raise RuntimeError((result.stderr or result.stdout).strip())
    return result


def _read_remote(ctx, path: str) -> str:
    result = _run_checked(ctx, f"cat {shlex.quote(path)}")
    return result.stdout


def _sha256_local(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _split_stat(line: str):
    parts = line.split("|")
    while len(parts) < 4:
        parts.append("unknown")
    return parts[0], parts[1], parts[2], parts[3]


def _parse_ps(text: str) -> dict[str, str]:
    for line in text.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) >= 4 and parts[0].isdigit():
            return {"pid": parts[0], "ppid": parts[1], "uid": parts[2], "argv": parts[3]}
    return {}


def _step_id(step) -> str:
    return str(step.get("id") or "scenario")
