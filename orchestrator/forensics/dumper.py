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

from orchestrator.core import console
from orchestrator.core.paths import ProjectPaths
from orchestrator.core.provenance import command_output, command_result, file_sha256

# tmpfs staging area for the intermediate raw image produced by
# qemu-img convert. RAM-backed on every distro the project targets.
_RAW_STAGING_DIR = Path("/dev/shm")

_log = logging.getLogger(__name__)


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


@dataclass
class ImageMetadata:
    # Absolute path. The manifest is a per-machine artifact -- no point in
    # carrying a relative form that would just need re-anchoring on every read.
    path: str
    tool: str
    sha256: str | None
    size_bytes: int | None
    timestamp: float
    segments: list[str] | None = None
    segment_metadata: list[dict[str, object]] | None = None
    acquisition_seconds: float | None = None
    tool_version: str | None = None
    command: list[str] | None = None
    stdout: str | None = None
    stderr: str | None = None
    commands: list[dict[str, object]] | None = None
    verification: dict[str, object] | None = None


@dataclass
class AcquisitionManifest:
    # run_id is the unique per-run label "{distro}_{scenario}_{ts}" used as
    # the experiment directory name under experiments_dir (which holds the
    # dumps/ and analysis/ subtrees).
    run_id: str
    # scenario_id is the bare scenarios.yaml key (or "verify"); never has a
    # timestamp baked in. Use this for semantic queries / grouping.
    scenario_id: str
    created_at: float
    memory_image: ImageMetadata
    disk_image: ImageMetadata
    # Acquisition provenance: the disk image is taken host-side from the
    # powered-off guest's qcow2 (clean, no QEMU lock held).
    disk_acquisition_mode: str = "offline"
    disk_preparation: str = "powered_off"


class Dumper:
    def __init__(self, paths: ProjectPaths) -> None:
        self._paths = paths
        self.experiments_root = paths.experiments_dir
        self.experiments_root.mkdir(parents=True, exist_ok=True)

    # --- directory layout ------------------------------------------------

    def run_dir(self, run_id: str) -> Path:
        d = self._paths.run_dumps_dir(run_id)
        (d / "memory").mkdir(parents=True, exist_ok=True)
        (d / "disk").mkdir(parents=True, exist_ok=True)
        return d

    # --- memory (VM must be ON) ------------------------------------------

    def acquire_memory(self, domain: str, dest: Path) -> ImageMetadata:
        """
        Dump live RAM via virsh. Domain must be ON.
        dest is owned by the calling user -- experiments dir is pre-chowned at init.
        """
        if dest.exists():
            dest.unlink()

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
        record.update(
            {
                "status_path": str(status_path),
                "output_path": str(dest),
                "acquisition_status": record["status"],
            }
        )
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
                {
                    "status": "failed",
                    "acquisition_status": "failed",
                    "error": "output file not created or empty",
                }
            )
            self._write_status(status_path, record)
            raise RuntimeError("Memory dump failed: output file not created or empty")

        # libvirt may create the dump as root even when virsh was invoked by
        # the unprivileged lab user. Transfer it before hashing the evidence.
        subprocess.run(
            ["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(dest)],
            check=True,
        )
        elapsed = time.time() - started
        size_bytes = dest.stat().st_size
        sha256 = file_sha256(dest)
        completed_at = time.time()
        record.update(
            {
                "sha256": sha256,
                "size_bytes": size_bytes,
                "timestamp": completed_at,
                "acquisition_seconds": elapsed,
            }
        )
        self._write_status(status_path, record)
        console.ok(
            f"memory dump done ({elapsed:.1f}s): {dest}, {_format_bytes(size_bytes)}"
        )
        return ImageMetadata(
            path=str(dest),
            tool="virsh dump --memory-only",
            sha256=sha256,
            size_bytes=size_bytes,
            timestamp=completed_at,
            acquisition_seconds=elapsed,
            tool_version=tool_version,
            command=command,
            stdout=result.stdout,
            stderr=result.stderr,
            commands=[record],
        )

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
                    "qemu-img convert -O raw; ewfacquire -u -c empty-block; "
                    "ewfverify"
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
        prior_commands: list[dict[str, object]] | None = None,
    ) -> ImageMetadata:
        # Wrap the staged raw image to EWF, validate + chown the segments, and
        # build the manifest metadata.
        ewfacquire_result = self._run_ewfacquire(raw_path, ewf_prefix)
        ewf_segments = sorted(glob.glob(f"{ewf_prefix}.E??"))
        self._validate_ewf_segments(ewf_segments, ewf_prefix)
        self._chown_segments(ewf_segments)
        segment_metadata = [
            {
                "path": str(Path(segment)),
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

        return ImageMetadata(
            path=str(Path(ewf_segments[0])),
            segments=[str(Path(segment)) for segment in ewf_segments],
            segment_metadata=segment_metadata,
            tool=tool,
            sha256=str(verification["calculated_sha256"]),
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
        scenario_id: str,
        memory_meta: ImageMetadata,
        disk_meta: ImageMetadata,
    ) -> str:
        """Write AcquisitionManifest to disk. Returns the manifest path as str."""
        manifest = AcquisitionManifest(
            run_id=run_id,
            scenario_id=scenario_id,
            created_at=time.time(),
            memory_image=memory_meta,
            disk_image=disk_meta,
        )
        manifest_path = self.run_dir(run_id) / "acquisition.json"
        with open(manifest_path, "w") as f:
            json.dump(asdict(manifest), f, indent=2)
        console.ok(f"acquisition manifest written: {manifest_path}")
        return str(manifest_path)

    # --- private: disk acquisition steps ---------------------------------

    def _clean_previous_output(self, ewf_prefix: str, raw_path: Path) -> None:
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
    ) -> dict[str, object]:
        # raw_path lives on tmpfs (see _RAW_STAGING_DIR) so this conversion
        # doesn't burn a second pass of physical disk I/O. For sparse qcow2
        # the actual bytes written are much smaller than the virtual size.
        _log.debug("converting to raw: %s -> %s", disk_source, raw_path)
        command = [
            "qemu-img", "convert", "-O", "raw", str(disk_source), str(raw_path)
        ]
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        record = command_result(
            command,
            result,
            tool_version=self._tool_version(["qemu-img", "--version"]),
        )
        record["status_path"] = str(status_path)
        self._write_status(status_path, record)
        if result.returncode != 0:
            raise RuntimeError(
                f"qemu-img convert failed for '{disk_source}'.\n"
                f"{(result.stderr or '').strip()}"
            )
        return record

    def _run_ewfacquire(
        self, raw_path: Path, ewf_prefix: str
    ) -> dict[str, object]:
        """
        Wrap raw image into EWF format. Deletes raw_path when done (or on failure).
        ewf_prefix is the output path without extension; ewfacquire appends .E01, .E02, ...
        """
        threads = str(os.cpu_count() or 4)
        _log.debug("running ewfacquire: %s -> %s.E??", raw_path, ewf_prefix)
        try:
            command = [
                "ewfacquire",
                "-u",
                "-c",
                "empty-block",
                "-j",
                threads,
                "-t",
                ewf_prefix,
                str(raw_path),
            ]
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
            record = command_result(
                command,
                result,
                tool_version=self._tool_version(["ewfacquire", "-V"]),
            )
            status_path = Path(ewf_prefix).parent / "ewfacquire_status.json"
            record["status_path"] = str(status_path)
            self._write_status(status_path, record)
            if result.returncode != 0:
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
        *,
        segment_metadata: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        command = ["ewfverify", "-d", "sha256", str(first_segment)]
        status_path = Path(ewf_prefix).parent / "ewfverify_status.json"
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
            record = command_result(
                command,
                result,
                tool_version=self._tool_version(["ewfverify", "-V"]),
            )
        except OSError as exc:
            record = {
                "command": command,
                "status": "failed",
                "exit_status": None,
                "stdout": "",
                "stderr": str(exc),
                "tool_version": None,
            }
        record["status_path"] = str(status_path)
        record["acquisition_status"] = record["status"]
        if segment_metadata is not None:
            record["segments"] = segment_metadata
        if record["status"] != "completed":
            self._write_status(status_path, record)
            raise RuntimeError(
                f"ewfverify failed (rc={record['exit_status']}); "
                f"details preserved in {status_path}"
            )
        calculated_sha256 = _parse_ewfverify_sha256(
            f"{record.get('stdout', '')}\n{record.get('stderr', '')}"
        )
        if calculated_sha256 is None:
            record.update(
                {
                    "status": "failed",
                    "acquisition_status": "failed",
                    "error": "ewfverify did not report a calculated SHA-256",
                }
            )
            self._write_status(status_path, record)
            raise RuntimeError(
                f"ewfverify did not report a calculated SHA-256; "
                f"details preserved in {status_path}"
            )
        record["calculated_sha256"] = calculated_sha256
        self._write_status(status_path, record)
        return record

    def _validate_ewf_segments(self, segments: list[str], ewf_prefix: str) -> None:
        if not segments:
            raise RuntimeError(f"EWF output not found for prefix {ewf_prefix}.E??")
        for seg in segments:
            if Path(seg).stat().st_size == 0:
                raise RuntimeError(f"EWF segment is zero bytes: {seg}")

    def _chown_segments(self, segments: list[str]) -> None:
        owner = f"{os.getuid()}:{os.getgid()}"
        for seg in segments:
            subprocess.run(["sudo", "chown", owner, seg], check=True)

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
            f"{segments[0]} "
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
