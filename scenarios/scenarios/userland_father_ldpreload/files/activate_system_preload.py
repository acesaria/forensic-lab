#!/usr/bin/env python3
"""Install Father, activate /etc/ld.so.preload, and roll back only on failure."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


PROCESS_COUNT = 3
MAP_CHECK = (
    "from pathlib import Path; import sys; "
    "wanted=sys.argv[1]; maps=Path('/proc/self/maps').read_text(); "
    "raise SystemExit(0 if wanted in maps else 1)"
)


def atomic_write(path: Path, content: bytes, mode: int) -> None:
    """Write a root-owned file with a same-directory atomic replacement."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_path, mode)
        os.chown(temporary_path, 0, 0)
        os.replace(temporary_path, path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def restore(path: Path, existed: bool, original: bytes) -> None:
    if existed:
        atomic_write(path, original, 0o644)
    else:
        path.unlink(missing_ok=True)


def stop_processes(processes: list[subprocess.Popen]) -> None:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        if process.poll() is None:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--built-library", required=True, type=Path)
    parser.add_argument("--installed-library", required=True, type=Path)
    parser.add_argument("--preload-config", required=True, type=Path)
    parser.add_argument("--backup-path", required=True, type=Path)
    parser.add_argument("--absent-marker", required=True, type=Path)
    parser.add_argument("--duration", required=True, type=int)
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("activation helper requires effective UID 0")

    library_existed = args.installed_library.exists()
    original_library = args.installed_library.read_bytes() if library_existed else b""
    preload_existed = args.preload_config.exists()
    original_preload = args.preload_config.read_bytes() if preload_existed else b""
    activation_attempted = False
    processes: list[subprocess.Popen] = []

    try:
        # Install first, then prove that one explicitly preloaded process can map it.
        atomic_write(args.installed_library, args.built_library.read_bytes(), 0o644)
        preflight_environment = dict(os.environ)
        preflight_environment["LD_PRELOAD"] = str(args.installed_library)
        preflight = subprocess.run(
            [sys.executable, "-c", MAP_CHECK, str(args.installed_library)],
            env=preflight_environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if preflight.returncode != 0:
            detail = (preflight.stderr or preflight.stdout).strip()
            raise RuntimeError(f"explicit LD_PRELOAD validation failed: {detail}")

        # Preserve the exact old configuration before replacing it.
        args.backup_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(args.backup_path.parent, 0o700)
        if preload_existed:
            atomic_write(args.backup_path, original_preload, 0o600)
            args.absent_marker.unlink(missing_ok=True)
            recovery_artifact = args.backup_path
        else:
            args.backup_path.unlink(missing_ok=True)
            atomic_write(args.absent_marker, b"preload file was absent\n", 0o600)
            recovery_artifact = args.absent_marker

        configured_entries = {
            line.strip()
            for line in original_preload.splitlines()
            if line.strip() and not line.lstrip().startswith(b"#")
        }
        library_line = str(args.installed_library).encode()
        final_preload = original_preload
        if library_line not in configured_entries:
            if final_preload and not final_preload.endswith(b"\n"):
                final_preload += b"\n"
            final_preload += library_line + b"\n"

        activation_attempted = True
        atomic_write(args.preload_config, final_preload, 0o644)

        # These children inherit no LD_PRELOAD variable, so their mapping proves
        # that /etc/ld.so.preload is active system-wide.
        child_environment = dict(os.environ)
        child_environment.pop("LD_PRELOAD", None)
        for _ in range(PROCESS_COUNT):
            processes.append(
                subprocess.Popen(
                    ["/usr/bin/sleep", str(args.duration)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                    close_fds=True,
                    env=child_environment,
                )
            )
        time.sleep(1)

        affected_pids = []
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(f"controlled process {process.pid} exited early")
            maps = Path(f"/proc/{process.pid}/maps").read_text(encoding="utf-8")
            if str(args.installed_library) not in maps:
                raise RuntimeError(f"controlled process {process.pid} lacks Father mapping")
            affected_pids.append(process.pid)

        facts = {
            "deployed_files": [
                str(args.installed_library),
                str(args.preload_config),
                str(recovery_artifact),
            ],
            "preload_activation": {
                "active": True,
                "atomic_write": True,
                "mode": "system-wide",
                "path": str(args.preload_config),
                "preexisting_content_preserved_at": str(recovery_artifact),
            },
            "affected_pids": affected_pids,
            "privilege_used": "sudo -n to effective UID 0",
            "validation_result": {"status": "passed"},
        }
        print(json.dumps(facts, sort_keys=True))
        return 0
    except Exception as error:
        stop_processes(processes)
        recovery_errors = []
        if activation_attempted:
            try:
                restore(args.preload_config, preload_existed, original_preload)
            except Exception as recovery_error:
                recovery_errors.append(f"preload restore failed: {recovery_error}")
        try:
            restore(args.installed_library, library_existed, original_library)
        except Exception as recovery_error:
            recovery_errors.append(f"library restore failed: {recovery_error}")

        facts = {
            "deployed_files": [],
            "preload_activation": {
                "active": False,
                "failure_only_recovery_attempted": True,
                "path": str(args.preload_config),
                "recovery_errors": recovery_errors,
            },
            "affected_pids": [],
            "privilege_used": "sudo -n to effective UID 0",
            "validation_result": {"error": str(error), "status": "failed"},
        }
        print(json.dumps(facts, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
