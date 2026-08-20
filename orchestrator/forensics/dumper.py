"""
orchestrator/forensics/dumper.py

RAM and disk acquisition pipeline. Pure I/O -- no VM lifecycle management.

Caller contract (enforced by orchestrator._run_acquisition):
  - acquire_memory: domain must be ON (virsh dump --memory-only)
  - acquire_disk:   host-side acquisition of the qcow2; the orchestrator shuts
                    the VM down first so the image is read with no QEMU lock held.
The dumper itself does no VM state transitions.
"""

import glob
import json
import logging
import os
import re
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from orchestrator.core import console
from orchestrator.core.paths import ProjectPaths
from orchestrator.core.provenance import command_output, command_result, file_sha256

# tmpfs staging area for the intermediate raw image produced by
# qemu-img convert. RAM-backed on every distro the project targets.
_RAW_STAGING_DIR = Path("/dev/shm")

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ImageMetadata:
    path: str
    segments: list[str]
    segment_metadata: list[dict[str, Any]]
    tool: str
    sha256: str
    size_bytes: int | None
    timestamp: float
    acquisition_seconds: float
    commands: list[dict[str, Any]]
    verification: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _format_bytes(size: int | None) -> str:
    if size is None:
        return "unknown"
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    value = float(size)
    unit = units[0]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            break
        value /= 1024
    if unit == "B":
        return f"{int(value)} {unit}"
    return f"{value:.1f} {unit}"


class Dumper:
    def __init__(self, paths: ProjectPaths) -> None:
        self._paths = paths
        paths.experiments_dir.mkdir(parents=True, exist_ok=True)

    def _display(self, path: Path | str) -> str:
        return os.path.relpath(path, self._paths.repo_root)

    # --- directory layout ------------------------------------------------

    def run_dir(self, run_id: str) -> Path:
        d = self._paths.run_dumps_dir(run_id)
        (d / "memory").mkdir(parents=True, exist_ok=True)
        (d / "disk").mkdir(parents=True, exist_ok=True)
        return d

    @staticmethod
    def _relative_to_dumps(path: Path) -> str:
        # dest lives at <dumps>/{memory,disk}/<file>; two parents up is <dumps>.
        # acquisition.json lives at <dumps>/acquisition.json, so this is the
        # path a reader of that file should join against its own location.
        p = Path(path)
        return str(p.relative_to(p.parent.parent))

    @staticmethod
    def _write_hashes_file(directory: Path, entries: list[tuple[str, str]]) -> None:
        # sha256sum -c compatible: "<hash>  <filename>" per line.
        lines = "".join(f"{sha256}  {name}\n" for name, sha256 in entries)
        (directory / "hashes.txt").write_text(lines, encoding="utf-8")

    # --- memory (VM must be ON) ------------------------------------------

    def acquire_memory(self, domain: str, dest: Path) -> dict[str, Any]:
        """
        Dump live RAM via virsh. Domain must be ON.
        dest is pre-created by the calling user so libvirt preserves its ownership.
        """
        if dest.exists():
            dest.unlink()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.touch(mode=0o600, exist_ok=False)
        dest.chmod(0o600)

        started = time.time()
        console.step(f"acquiring memory from '{domain}'...")
        command = ["virsh", "dump", domain, str(dest), "--memory-only"]
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
        tool_version = self._tool_version(["virsh", "--version"])
        status_path = dest.parent / "virsh_dump_status.json"
        record = command_result(command, result, tool_version=tool_version)
        if result.returncode != 0:
            self._write_status(status_path, record)
            raise RuntimeError(
                f"virsh dump failed (rc={result.returncode})\n"
                f"{result.stdout or ''}\n{result.stderr or ''}"
            )
        if _log.isEnabledFor(logging.DEBUG):
            _log.debug("%s", result.stdout or "")

        if not dest.exists() or dest.stat().st_size == 0:
            record.update(
                {"status": "failed", "error": "output file not created or empty"}
            )
            self._write_status(status_path, record)
            raise RuntimeError("Memory dump failed: output file not created or empty")
        if not os.access(dest, os.R_OK):
            record.update(
                {
                    "status": "failed",
                    "error": "output file is not readable by the current process",
                }
            )
            self._write_status(status_path, record)
            raise RuntimeError("Memory dump failed: output file is not readable")

        # status_path is a failure sidecar only: on success, the same
        # command record isn't kept anywhere else, since there's nothing
        # else to cross-check it against for memory (unlike disk, which
        # gets an independent ewfverify pass).
        elapsed = time.time() - started
        size_bytes = dest.stat().st_size
        sha256 = file_sha256(dest)
        self._write_hashes_file(dest.parent, [(dest.name, sha256)])
        console.ok(
            f"memory dump done ({elapsed:.1f}s): "
            f"{self._display(dest)}, {_format_bytes(size_bytes)}"
        )
        return {
            "path": self._relative_to_dumps(dest),
            "tool": "virsh dump --memory-only",
            "tool_version": tool_version,
            "size_bytes": size_bytes,
            "sha256": sha256,
            # No independent re-read verification pass exists for memory
            # (unlike disk's ewfverify) -- this hash is recorded at
            # acquisition time, not independently confirmed.
            "verified": False,
        }

    # --- disk (VM must be OFF) -------------------------------------------

    def acquire_disk(self, source_image_path: Path, dest: Path) -> ImageMetadata:
        """
        Host-side disk acquisition (offline mode): qemu-img convert -> raw, then
        ewfacquire -> EWF. Assumes the source qcow2 is safe to read (VM off).
        VM lifecycle preparation is the caller's responsibility.
        """
        ewf_prefix = str(dest.with_suffix(""))
        # Stage the raw intermediate on tmpfs so we don't pay a full second
        # write to spinning storage. /dev/shm is RAM-backed on systemd
        # distros; ewfacquire reads it back compressed. Safe here because a
        # sparse qcow2 convert writes only its allocated bytes.
        raw_path = _RAW_STAGING_DIR / f"{dest.stem}-{os.getpid()}.raw"
        self._clean_previous_output(ewf_prefix, raw_path)

        started = time.time()
        virtual_size = self._qemu_virtual_size(source_image_path)
        console.step(f"acquiring disk from '{Path(source_image_path).stem}'...")
        try:
            qemu_result = self._convert_to_raw(
                source_image_path,
                raw_path,
                status_path=dest.parent / "qemu_img_status.json",
            )
            return self._wrap_raw_to_ewf(
                raw_path, ewf_prefix, started, virtual_size,
                tool=(
                    "qemu-img convert -O raw; ewfacquire -u -d sha256 "
                    "-c empty-block -j nproc; ewfverify"
                ),
                prior_commands=[qemu_result],
            )
        finally:
            # _run_ewfacquire unlinks raw_path itself, but a failure inside
            # _convert_to_raw would otherwise leak a multi-GB file in tmpfs.
            if raw_path.exists():
                raw_path.unlink()

    def _wrap_raw_to_ewf(
        self,
        raw_path: Path,
        ewf_prefix: str,
        started: float,
        virtual_size: int | None,
        tool: str,
        prior_commands: list[dict[str, Any]] | None = None,
    ) -> ImageMetadata:
        # Wrap the staged raw image to EWF, validate the segments, and build
        # the manifest metadata. ewfacquire runs as the calling user.
        ewfacquire_result = self._run_ewfacquire(raw_path, ewf_prefix)
        ewf_segments = sorted(glob.glob(f"{ewf_prefix}.E??"))
        self._validate_ewf_segments(ewf_segments, ewf_prefix)
        segment_metadata = [
            {
                "path": self._relative_to_dumps(Path(segment)),
                "size_bytes": Path(segment).stat().st_size,
                "sha256": file_sha256(Path(segment)),
            }
            for segment in ewf_segments
        ]
        verification = self._run_ewfverify(
            Path(ewf_segments[0]),
            ewf_prefix,
            segment_metadata=segment_metadata,
        )

        elapsed = time.time() - started
        ewf_total_size = sum(int(segment["size_bytes"]) for segment in segment_metadata)
        self._log_disk_result(elapsed, ewf_segments, virtual_size, ewf_total_size)
        self._write_hashes_file(
            Path(ewf_prefix).parent,
            [(Path(segment).name, meta["sha256"])
             for segment, meta in zip(ewf_segments, segment_metadata)],
        )

        return ImageMetadata(
            path=self._relative_to_dumps(Path(ewf_segments[0])),
            segments=[self._relative_to_dumps(Path(s)) for s in ewf_segments],
            segment_metadata=segment_metadata,
            tool=tool,
            sha256=verification["calculated_sha256"],
            size_bytes=virtual_size,
            timestamp=time.time(),
            acquisition_seconds=elapsed,
            commands=[*(prior_commands or []), ewfacquire_result, verification],
            verification=verification,
        )

    # --- manifest --------------------------------------------------------

    def write_manifest(
        self,
        run_id: str,
        memory: dict[str, Any],
        disk: ImageMetadata,
    ) -> str:
        """
        Write the acquisition record to disk. Returns the manifest path as str.
        Only called after both memory and disk acquisition have already
        succeeded, so status is always "completed" here -- a failed
        acquisition's diagnostics live in the *_status.json sidecars instead,
        since this file is never reached.
        """
        manifest = {
            "status": "completed",
            "memory": memory,
            "disk": disk.to_dict(),
        }
        manifest_path = self.run_dir(run_id) / "acquisition.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        console.ok(f"acquisition manifest written: {self._display(manifest_path)}")
        return str(manifest_path)

    # --- private: disk acquisition steps ---------------------------------

    def _clean_previous_output(self, ewf_prefix: str, raw_path: Path) -> None:
        _log.debug("cleaning previous output: %s.E?? and %s", ewf_prefix, raw_path)
        for old_segment in glob.glob(f"{ewf_prefix}.E??"):
            os.remove(old_segment)
        if raw_path.exists():
            raw_path.unlink()

    def _convert_to_raw(
        self,
        disk_source: Path,
        raw_path: Path,
        *,
        status_path: Path,
    ) -> dict[str, Any]:
        # raw_path lives on tmpfs (see _RAW_STAGING_DIR) so this conversion
        # doesn't burn a second pass of physical disk I/O. For sparse qcow2
        # the actual bytes written are much smaller than the virtual size.
        # status_path is a failure sidecar only -- on success this
        # intermediate step leaves no artifact of its own; the disk hash
        # that matters is the one ewfverify recomputes downstream.
        _log.debug("converting to raw: %s -> %s", disk_source, raw_path)
        command = [
            "qemu-img", "convert", "-O", "raw", str(disk_source), str(raw_path)
        ]
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        tool_version = self._tool_version(["qemu-img", "--version"])
        record = command_result(command, result, tool_version=tool_version)
        if result.returncode != 0:
            self._write_status(status_path, record)
            raise RuntimeError(
                f"qemu-img convert failed for '{disk_source}'.\n"
                f"{(result.stderr or '').strip()}"
            )
        return record

    def _run_ewfacquire(self, raw_path: Path, ewf_prefix: str) -> dict[str, Any]:
        """
        Wrap raw image into EWF format. Deletes raw_path when done (or on failure).
        ewf_prefix is the output path without extension; ewfacquire appends .E01, .E02, ...
        Returns the ewfacquire command record.
        """
        threads = max(1, (os.cpu_count() or 4) // 2)
        tool_version = self._tool_version(["ewfacquire", "-V"])
        _log.debug("running ewfacquire: %s -> %s.E??", raw_path, ewf_prefix)
        try:
            command = [
                "ewfacquire",
                "-u",
                "-c", "empty-block",
                "-d", "sha256",
                "-j", str(threads),
                "-t", ewf_prefix,
                str(raw_path),
            ]
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
            record = command_result(command, result, tool_version=tool_version)
            if result.returncode != 0:
                status_path = Path(ewf_prefix).parent / "ewfacquire_status.json"
                self._write_status(status_path, record)
                raise RuntimeError(
                    f"ewfacquire failed (rc={result.returncode})\n"
                    f"stdout:\n{result.stdout or ''}\n"
                    f"stderr:\n{result.stderr or ''}"
                )
            if _log.isEnabledFor(logging.DEBUG):
                _log.debug("%s", result.stdout or "")
            return record
        finally:
            # always remove the intermediate raw file regardless of success/failure
            if raw_path.exists():
                raw_path.unlink()

    def _run_ewfverify(
        self,
        first_segment: Path,
        ewf_prefix: str,
        segment_metadata: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Independently re-read and hash the written EWF. Returns the record."""
        command = ["ewfverify", "-d", "sha256", str(first_segment)]
        status_path = Path(ewf_prefix).parent / "ewfverify_status.json"
        tool_version = self._tool_version(["ewfverify", "-V"])
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
            record = command_result(command, result, tool_version=tool_version)
        except OSError as exc:
            record = {
                "command": command,
                "status": "failed",
                "exit_status": None,
                "stdout": "",
                "stderr": str(exc),
                "tool_version": tool_version,
            }
        
        if record["status"] == "completed":
            calculated_sha256 = _parse_ewfverify_sha256(
                f"{record.get('stdout', '')}\n{record.get('stderr', '')}"
            )
            if calculated_sha256:
                record["calculated_sha256"] = calculated_sha256
                # Cross-check against acquisition if possible? 
                # ewfacquire's digest isn't easily parsed from stdout without more work
                return record
            else:
                record["status"] = "failed"
                record["error"] = "ewfverify did not report a calculated SHA-256"

        self._write_status(status_path, record)
        raise RuntimeError(
            f"ewfverify failed (rc={record.get('exit_status')}); "
            f"details preserved in {status_path}"
        )

    def _validate_ewf_segments(self, segments: list[str], ewf_prefix: str) -> None:
        if not segments:
            raise RuntimeError(f"EWF output not found for prefix {ewf_prefix}.E??")
        for seg in segments:
            if Path(seg).stat().st_size == 0:
                raise RuntimeError(f"EWF segment is zero bytes: {seg}")

    def _log_disk_result(
        self,
        elapsed: float,
        segments: list[str],
        virtual_size: int | None,
        ewf_total_size: int,
    ) -> None:
        segment_count = len(segments)
        if segment_count == 1:
            size_info = f"ewf {_format_bytes(ewf_total_size)}"
        else:
            size_info = (
                f"{segment_count} segments, ewf {_format_bytes(ewf_total_size)} total"
            )
        console.ok(
            f"disk acquisition done ({elapsed:.1f}s): "
            f"{self._display(segments[0])} "
            f"(virtual {_format_bytes(virtual_size)}, {size_info})"
        )

    # --- private: generic helpers ----------------------------------------

    @staticmethod
    def _tool_version(command: list[str]) -> str | None:
        output = command_output(command, allow_nonzero=True)
        return output.splitlines()[0] if output else None

    @staticmethod
    def _write_status(path: Path, record: dict[str, object]) -> None:
        path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def _qemu_virtual_size(disk_source: Path) -> int:
        command = [
            "qemu-img",
            "info",
            "--output",
            "json",
            disk_source.absolute(),
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(
                f"qemu-img info failed for '{disk_source}': {exc}"
            ) from exc
        if result.returncode != 0:
            diagnostic = (result.stderr or result.stdout or "(no output)").strip()
            raise RuntimeError(
                f"qemu-img info failed for '{disk_source}' "
                f"(rc={result.returncode}):\n{diagnostic}"
            )
        try:
            info = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"qemu-img info returned invalid JSON for '{disk_source}':\n"
                f"stdout:\n{result.stdout or ''}\n"
                f"stderr:\n{result.stderr or ''}"
            ) from exc
        virtual_size = info.get("virtual-size")
        if (
            isinstance(virtual_size, bool)
            or not isinstance(virtual_size, int)
            or virtual_size <= 0
        ):
            raise RuntimeError(
                f"qemu-img info did not report a positive integer virtual-size "
                f"for '{disk_source}':\n"
                f"stdout:\n{result.stdout or ''}\n"
                f"stderr:\n{result.stderr or ''}"
            )
        return virtual_size


def _parse_ewfverify_sha256(output: str) -> str | None:
    match = re.search(
        r"^SHA256 hash calculated over data:\s*([0-9a-fA-F]{64})\s*$",
        output,
        flags=re.MULTILINE,
    )
    return match.group(1).lower() if match else None
