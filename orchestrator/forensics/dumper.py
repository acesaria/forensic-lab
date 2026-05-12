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
import os
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class ImageMetadata:
    path: str
    tool: str
    sha256: str | None
    size_bytes: int | None
    timestamp: float
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
        print(f"[*] Acquiring memory from '{domain}'...")
        subprocess.run(
            ["virsh", "dump", domain, str(dest), "--memory-only"],
            check=True,
        )
        elapsed = time.time() - started
        subprocess.run(
            ["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(dest)],
            check=True,
        )
        print(f"[+] Memory dump done ({elapsed:.1f}s): {dest}")

        return ImageMetadata(
            path=str(dest.relative_to(self.repo_root)),
            tool="virsh dump --memory-only --live",
            sha256=self._sha256(dest),
            size_bytes=dest.stat().st_size,
            timestamp=time.time(),
            acquisition_seconds=elapsed,
        )

    # --- disk (VM must be OFF) -------------------------------------------

    def acquire_disk(self, disk_source: str, dest: Path) -> ImageMetadata:
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

        print(f"[*] Converting disk source to raw: {disk_source} -> {raw_path}...")
        subprocess.run(
            ["qemu-img", "convert", "-O", "raw", disk_source, str(raw_path)],
            check=True,
        )

        print(f"[*] Acquiring disk from '{raw_path}' -> {dest}...")
        ewf_ok = False
        try:
            threads = str(os.cpu_count() or 4)
            subprocess.run(
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
                check=True,
            )
            ewf_ok = True
        finally:
            if ewf_ok and raw_path.exists():
                raw_path.unlink()

        segments = sorted(glob.glob(f"{prefix}.E??"))
        if not segments:
            raise RuntimeError(f"EWF output not found for prefix {prefix}.E??")

        for seg in segments:
            subprocess.run(
                ["sudo", "chown", f"{os.getuid()}:{os.getgid()}", seg],
                check=True,
            )

        elapsed = time.time() - started
        ewf_size = sum(Path(p).stat().st_size for p in segments)
        print(f"[+] Disk acquisition done ({elapsed:.1f}s): {segments[0]}")

        return ImageMetadata(
            path=str(Path(segments[0]).relative_to(self.repo_root)),
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
        print(f"[+] Manifest written: {path}")
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
            return None
