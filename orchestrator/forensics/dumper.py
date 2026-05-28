"""
orchestrator/forensics/dumper.py

RAM and disk acquisition pipeline. Pure I/O -- no VM lifecycle management.

Caller contract (enforced by orchestrator._run_acquisition):
  - acquire_memory: domain must be ON (virsh dump --live)
  - acquire_disk:   disk_source must be safe to read at the host level. The
                    orchestrator arranges this either by shutting the VM
                    down ("offline" workflow) or by taking a live external
                    disk snapshot so writes divert to an overlay
                    ("external_snapshot" workflow). The dumper itself does
                    no VM state transitions.
"""

import glob
import hashlib
import json
import logging
import os
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from orchestrator.core import console


# Canonical labels used in manifests and across orchestration boundaries.
# Legacy aliases ("shutdown", "suspend") are accepted for normalization
# only -- they must never leak past normalize_disk_acquisition_mode().
_CANONICAL_MODES = ("offline", "external_snapshot")
_MODE_ALIASES = {
    "shutdown": "offline",
    "suspend": "external_snapshot",
}


def normalize_disk_acquisition_mode(mode: str) -> str:
    if mode in _CANONICAL_MODES:
        return mode
    canonical = _MODE_ALIASES.get(mode)
    if canonical is not None:
        return canonical
    raise ValueError(
        f"unknown disk acquisition mode: {mode!r}. "
        f"expected one of {_CANONICAL_MODES} "
        f"(legacy aliases: {sorted(_MODE_ALIASES)})"
    )

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
    # path is relative to repo_root when possible, else absolute
    # (re-anchored by orchestrator when reading manifest)
    path: str
    tool: str
    sha256: str | None
    size_bytes: int | None
    timestamp: float
    segments: list[str] | None = None
    acquisition_seconds: float | None = None
    virtual_size_bytes: int | None = None
    ewf_size_bytes: int | None = None


@dataclass
class AcquisitionManifest:
    scenario_id: str
    created_at: float
    memory_image: ImageMetadata
    disk_image: ImageMetadata
    # Canonical mode label: "offline" or "external_snapshot".
    # "offline"           = VM not actively using the disk during host-side
    #                       acquisition (guest powered off first).
    # "external_snapshot" = live external disk snapshot, used to avoid the
    #                       active qcow2 lock and the filesystem noise that
    #                       a guest shutdown would create.
    disk_acquisition_mode: str = "offline"
    # Derived from disk_acquisition_mode; carried explicitly so downstream
    # tools don't have to know the mapping.
    disk_preparation: str = "powered_off"


class Dumper:
    def __init__(self, repo_root: Path, dumps_dir: Path) -> None:
        # repo_root anchors manifest paths so they stay portable within the project
        # (fallback to absolute when dumps_dir lives outside repo_root).
        self.repo_root = repo_root
        self.dumps_root = dumps_dir
        self.dumps_root.mkdir(parents=True, exist_ok=True)

    def _rel_or_abs(self, p: Path) -> str:
        """Render p relative to repo_root if possible, else absolute."""
        try:
            return str(p.relative_to(self.repo_root))
        except ValueError:
            return str(p)

    # --- directory layout ------------------------------------------------

    def scenario_dir(self, scenario_id: str) -> Path:
        d = self.dumps_root / scenario_id
        (d / "memory").mkdir(parents=True, exist_ok=True)
        (d / "disk").mkdir(parents=True, exist_ok=True)
        return d

    # --- memory (VM must be ON) ------------------------------------------

    def acquire_memory(self, domain: str, dest: Path) -> ImageMetadata:
        """
        Dump live RAM via virsh. Domain must be ON.
        dest is owned by the calling user -- dumps dir is pre-chowned at init.
        """
        if dest.exists():
            dest.unlink()

        started = time.time()
        console.step(f"acquiring memory from '{domain}'...", indent=True)
        result = subprocess.run(
            ["virsh", "dump", domain, str(dest), "--memory-only"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"virsh dump failed (rc={result.returncode})\n"
                f"{result.stdout or ''}\n{result.stderr or ''}"
            )
        if _log.isEnabledFor(logging.DEBUG):
            _log.debug("%s", result.stdout or "")

        if not dest.exists() or dest.stat().st_size == 0:
            raise RuntimeError("Memory dump failed: output file not created or empty")

        elapsed = time.time() - started
        size_bytes = dest.stat().st_size
        subprocess.run(
            ["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(dest)],
            check=True,
        )
        console.ok(
            f"memory dump done ({elapsed:.1f}s): "
            f"{self._rel_or_abs(dest)}, {_format_bytes(size_bytes)}",
            indent=True,
        )
        return ImageMetadata(
            path=self._rel_or_abs(dest),
            tool="virsh dump --memory-only --live",
            sha256=self._sha256(dest),
            size_bytes=size_bytes,
            timestamp=time.time(),
            acquisition_seconds=elapsed,
        )

    # --- disk (VM must be OFF) -------------------------------------------

    def acquire_disk(self, disk_source: str, dest: Path) -> ImageMetadata:
        """
        Pure host-side disk acquisition: qemu-img convert -> raw, then
        ewfacquire -> EWF. Assumes disk_source is safe to read (VM off, or
        behind an external snapshot overlay so writes don't touch it).
        VM lifecycle preparation is the caller's responsibility.
        """
        ewf_prefix = str(dest.with_suffix(""))
        raw_path = dest.with_suffix(".raw")

        self._clean_previous_output(ewf_prefix, raw_path)

        started = time.time()
        virtual_size = self._qemu_virtual_size(disk_source)
        console.step(f"acquiring disk from '{Path(disk_source).stem}'...", indent=True)

        self._convert_to_raw(disk_source, raw_path)
        self._run_ewfacquire(raw_path, ewf_prefix)
        # self._run_ewfacquire_from_qcow2(disk_source, ewf_prefix)

        ewf_segments = sorted(glob.glob(f"{ewf_prefix}.E??"))
        self._validate_ewf_segments(ewf_segments, ewf_prefix)
        self._chown_segments(ewf_segments)

        elapsed = time.time() - started
        ewf_total_size = sum(Path(s).stat().st_size for s in ewf_segments)
        self._log_disk_result(elapsed, ewf_segments, virtual_size, ewf_total_size)

        return ImageMetadata(
            # paths relative to repo_root when possible -- re-anchored by orchestrator
            # when reading manifest; absolute fallback when dumps_dir is outside repo_root
            path=self._rel_or_abs(Path(ewf_segments[0])),
            segments=[self._rel_or_abs(Path(s)) for s in ewf_segments],
            tool="qemu-img convert -O raw && ewfacquire -u -c fast",
            sha256=self._sha256(Path(ewf_segments[0])),
            size_bytes=Path(ewf_segments[0]).stat().st_size,
            timestamp=time.time(),
            acquisition_seconds=elapsed,
            virtual_size_bytes=virtual_size,
            ewf_size_bytes=ewf_total_size,
        )

    # --- manifest --------------------------------------------------------

    def write_manifest(
        self,
        scenario_id: str,
        memory_meta: ImageMetadata,
        disk_meta: ImageMetadata,
        disk_acquisition_mode: str = "offline",
    ) -> str:
        """Write AcquisitionManifest to disk. Returns the manifest path as str."""
        # Defensive normalization: callers should already pass canonical
        # labels, but accepting legacy aliases here means no manifest can
        # accidentally record "shutdown" or "suspend".
        canonical_mode = normalize_disk_acquisition_mode(disk_acquisition_mode)
        preparation = (
            "external_snapshot"
            if canonical_mode == "external_snapshot"
            else "powered_off"
        )
        manifest = AcquisitionManifest(
            scenario_id=scenario_id,
            created_at=time.time(),
            memory_image=memory_meta,
            disk_image=disk_meta,
            disk_acquisition_mode=canonical_mode,
            disk_preparation=preparation,
        )
        manifest_path = self.scenario_dir(scenario_id) / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(asdict(manifest), f, indent=2)
        console.ok(f"manifest written: {self._rel_or_abs(manifest_path)}")
        return str(manifest_path)

    # --- private: disk acquisition steps ---------------------------------

    def _clean_previous_output(self, ewf_prefix: str, raw_path: Path) -> None:
        for old_segment in glob.glob(f"{ewf_prefix}.E??"):
            os.remove(old_segment)
        if raw_path.exists():
            raw_path.unlink()

    def _convert_to_raw(self, disk_source: str, raw_path: Path) -> None:
        # Write to /dev/shm (tmpfs) to avoid a second disk write.
        # For a sparse qcow2 the written size is much smaller than virtual size.
        _log.debug("converting to raw: %s -> %s", disk_source, raw_path)
        try:
            subprocess.run(
                ["qemu-img", "convert", "-O", "raw", disk_source, str(raw_path)],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"qemu-img convert failed for '{disk_source}'.\n"
                f"{(exc.stderr or '').strip()}"
            ) from exc

    def _run_ewfacquire(self, raw_path: Path, ewf_prefix: str) -> None:
        """
        Wrap raw image into EWF format. Deletes raw_path when done (or on failure).
        ewf_prefix is the output path without extension; ewfacquire appends .E01, .E02, ...
        """
        threads = str(os.cpu_count() or 4)
        _log.debug("running ewfacquire: %s -> %s.E??", raw_path, ewf_prefix)
        try:
            result = subprocess.run(
                [
                    "ewfacquire",
                    "-u",
                    "-c",
                    "empty-block",
                    "-j",
                    threads,
                    "-t",
                    ewf_prefix,
                    str(raw_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"ewfacquire failed (rc={result.returncode})\n"
                    f"stdout:\n{result.stdout or ''}\n"
                    f"stderr:\n{result.stderr or ''}"
                )
            if _log.isEnabledFor(logging.DEBUG):
                _log.debug("%s", result.stdout or "")
        finally:
            # always remove the intermediate raw file regardless of success/failure
            if raw_path.exists():
                raw_path.unlink()

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
            f"{self._rel_or_abs(Path(segments[0]))} "
            f"(virtual {_format_bytes(virtual_size)}, {size_info})",
            indent=True,
        )

    # --- private: generic helpers ----------------------------------------

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _qemu_virtual_size(disk_source: str) -> int | None:
        try:
            result = subprocess.run(
                ["qemu-img", "info", "--output", "json", disk_source],
                capture_output=True,
                text=True,
                check=True,
            )
            return json.loads(result.stdout).get("virtual-size")
        except Exception:
            console.warn(f"could not determine virtual disk size for {disk_source}")
            return None
