"""
orchestrator/forensics/dumper.py

RAM and disk acquisition pipeline. Pure I/O -- no VM lifecycle management.

Caller contract (enforced by orchestrator._run_acquisition):
  - domain must be ON  when acquire_memory is called  (virsh dump --live)
  - domain must be OFF when acquire_disk is called     (ewfacquire safety)
  - The orchestrator owns all shutdown/start transitions between the two steps.
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


class Dumper:
    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root
        self.dumps_root = repo_root / "shared" / "dumps"
        self.dumps_root.mkdir(parents=True, exist_ok=True)

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
        _log.info("[*] Acquiring memory from '%s'...", domain)
        result = subprocess.run(
            ["virsh", "dump", domain, str(dest), "--memory-only"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            raise RuntimeError(
                f"virsh dump failed (rc={result.returncode})\n{stdout}\n{stderr}"
            )
        if _log.isEnabledFor(logging.DEBUG):
            _log.debug("%s", result.stdout or "")

        if not dest.exists() or dest.stat().st_size == 0:
            raise RuntimeError("Memory dump failed: output file not created or empty")

        elapsed = time.time() - started
        size_bytes = dest.stat().st_size if dest.exists() else None
        subprocess.run(
            ["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(dest)],
            check=True,
        )
        _log.info(
            "[+] Memory dump done (%.1fs): %s, %s",
            elapsed,
            str(dest.relative_to(self.repo_root)),
            _format_bytes(size_bytes),
        )

        return ImageMetadata(
            path=str(dest.relative_to(self.repo_root)),
            tool="virsh dump --memory-only --live",
            sha256=self._sha256(dest),
            size_bytes=dest.stat().st_size,
            timestamp=time.time(),
            acquisition_seconds=elapsed,
        )

    # --- disk (VM must be OFF) -------------------------------------------

    def acquire_disk(self, vm_name: str, disk_source: str, dest: Path) -> ImageMetadata:
        """
        Acquire disk via ewfacquire. Domain must be OFF.
        dest segments are owned by the calling user -- dumps dir is pre-chowned at init.
        """
        prefix = str(dest.with_suffix(""))
        raw_path = dest.with_suffix(".raw")

        for seg in glob.glob(f"{prefix}.E??"):
            os.remove(seg)
        if raw_path.exists():
            raw_path.unlink()

        started = time.time()
        virtual_size = self._qemu_virtual_size(disk_source)
        domain_hint = Path(disk_source).stem
        _log.info("[*] Acquiring disk from '%s'...", domain_hint)

        _log.debug(
            "[*] Converting disk source to raw: %s -> %s...",
            disk_source,
            raw_path,
        )
        try:
            subprocess.run(
                ["qemu-img", "convert", "-O", "raw", disk_source, str(raw_path)],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"disk: qemu-img convert failed for '{disk_source}'.\n"
                f"{(exc.stderr or '').strip()}"
            ) from exc

        _log.debug("[*] Acquiring disk from '%s' -> %s...", raw_path, dest)
        try:
            threads = str(os.cpu_count() or 4)
            result = subprocess.run(
                [
                    "ewfacquire",
                    "-u",
                    "-c",
                    "fast",
                    "-j",
                    threads,
                    "-t",
                    prefix,
                    str(raw_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                stdout = result.stdout or ""
                stderr = result.stderr or ""
                raise RuntimeError(
                    "ewfacquire failed "
                    f"(rc={result.returncode})\nstdout:\n{stdout}\nstderr:\n{stderr}"
                )
            if _log.isEnabledFor(logging.DEBUG):
                _log.debug("%s", result.stdout or "")
        finally:
            if raw_path.exists():
                raw_path.unlink()

        segments = sorted(glob.glob(f"{prefix}.E??"))
        if not segments:
            raise RuntimeError(f"EWF output not found for prefix {prefix}.E??")

        for seg in segments:
            if Path(seg).stat().st_size == 0:
                raise RuntimeError(f"EWF segment is zero bytes: {seg}")

        for seg in segments:
            subprocess.run(
                ["sudo", "chown", f"{os.getuid()}:{os.getgid()}", seg],
                check=True,
            )

        elapsed = time.time() - started
        segment_count = len(segments)
        ewf_size = sum(Path(p).stat().st_size for p in segments)
        ewf_gib = _format_bytes(ewf_size)
        virtual_gib = _format_bytes(virtual_size)

        if segment_count == 1:
            seg_info = f"ewf {ewf_gib}"
        else:
            seg_info = f"{segment_count} segments, ewf {ewf_gib} total"

        _log.info(
            "[+] Disk acquisition done (%.1fs): %s (virtual %s, %s)",
            elapsed,
            Path(segments[0]).relative_to(self.repo_root),
            f"{virtual_gib}" if virtual_gib else "?",
            seg_info,
        )
        return ImageMetadata(
            path=str(Path(segments[0]).relative_to(self.repo_root)),
            segments=[str(Path(p).relative_to(self.repo_root)) for p in segments],
            tool="qemu-img convert -O raw && ewfacquire -u -c fast -j 4",
            sha256=self._sha256(Path(segments[0])),
            size_bytes=Path(segments[0]).stat().st_size,
            timestamp=time.time(),
            acquisition_seconds=elapsed,
            virtual_size_bytes=virtual_size,
            ewf_size_bytes=ewf_size,
        )

    # --- manifest --------------------------------------------------------

    def write_manifest(
        self,
        scenario_id: str,
        memory_meta: ImageMetadata,
        disk_meta: ImageMetadata,
    ) -> str:
        """Write AcquisitionManifest to disk. Returns the manifest path."""
        manifest = AcquisitionManifest(
            scenario_id=scenario_id,
            created_at=time.time(),
            memory_image=memory_meta,
            disk_image=disk_meta,
        )
        path = self.scenario_dir(scenario_id) / "manifest.json"
        with open(path, "w") as f:
            json.dump(asdict(manifest), f, indent=2)
        _log.info("[+] Manifest written: %s", str(path.relative_to(self.repo_root)))
        return str(path)

    # --- helpers ---------------------------------------------------------

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
            r = subprocess.run(
                ["qemu-img", "info", "--output", "json", disk_source],
                capture_output=True,
                text=True,
                check=True,
            )
            return json.loads(r.stdout).get("virtual-size")
        except Exception:
            _log.warning(
                "[!] Could not determine virtual disk size for %s", disk_source
            )
            return None
