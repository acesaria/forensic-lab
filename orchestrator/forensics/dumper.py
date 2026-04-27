"""
orchestrator/forensics/dumper.py

RAM and disk acquisition pipeline. Decoupled from any VM management —
receives a domain name and a Provider instance, does the rest.
"""

from concurrent.futures import process
import glob
import hashlib
import json
import os
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from infra.provider import Provider


@dataclass
class ImageMetadata:
    path: str
    tool: str
    sha256: str | None
    size_bytes: int | None
    timestamp: float
    acquisition_seconds: float | None = None
    # TODO(milestone-2): expose virtual_size_bytes and ewf_size_bytes
    # in acquisition report / analysis pipeline
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

    # --- public entry point -----------------------------------------------

    def acquire(
        self,
        domain: str,
        scenario_id: str,
        provider: "Provider",
    ) -> str:
        """
        Acquire RAM and disk for *domain*, write manifest.
        Returns the manifest path.
        """
        scenario_dir = self._scenario_dir(scenario_id)
        memory_path = scenario_dir / "memory" / "baseline_memory.raw"
        disk_path = scenario_dir / "disk" / "baseline_disk.E01"

        memory_meta = self._acquire_memory(domain, memory_path)
        disk_meta = self._acquire_disk(domain, disk_path, provider)

        manifest = AcquisitionManifest(
            scenario_id=scenario_id,
            created_at=time.time(),
            memory_image=memory_meta,
            disk_image=disk_meta,
        )
        return self._write_manifest(scenario_id, manifest)

    # --- directory layout -------------------------------------------------

    def _scenario_dir(self, scenario_id: str) -> Path:
        d = self.dumps_root / scenario_id
        (d / "memory").mkdir(parents=True, exist_ok=True)
        (d / "disk").mkdir(parents=True, exist_ok=True)
        return d

    def _write_manifest(self, scenario_id: str, manifest: AcquisitionManifest) -> str:
        path = self._scenario_dir(scenario_id) / "manifest.json"
        with open(path, "w") as f:
            json.dump(asdict(manifest), f, indent=2)
        print(f"[+] Manifest written: {path}")
        return str(path)

    # --- memory -----------------------------------------------------------

    def _acquire_memory(self, domain: str, dest: Path) -> ImageMetadata:
        if dest.exists():
            dest.unlink()

        started = time.time()
        print(f"[*] Acquiring memory from '{domain}'...")
        subprocess.run(
            ["virsh", "dump", domain, str(dest), "--memory-only", "--live"],
            check=True,
        )
        elapsed = time.time() - started
        print(f"[+] Memory dump done ({elapsed:.1f}s): {dest}")

        
        subprocess.run(
        ["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(dest)],
        check=True,
        )


        return ImageMetadata(
            path=str(dest.relative_to(self.repo_root)),
            tool="virsh dump --memory-only --live",
            sha256=self._sha256(dest),
            size_bytes=dest.stat().st_size,
            timestamp=time.time(),
            acquisition_seconds=elapsed,
        )

    # --- disk -------------------------------------------------------------

    def _acquire_disk(
        self,
        domain: str,
        dest: Path,
        provider: "Provider",
    ) -> ImageMetadata:
        prefix = str(dest.with_suffix(""))

        # clean up any previous EWF segments
        for seg in glob.glob(f"{prefix}.E??"):
            os.remove(seg)

        started = time.time()
        disk_source = provider.get_disk_path(domain)
        virtual_size = self._qemu_virtual_size(disk_source)

        try:
            provider.shutdown_vm(domain)
            print(f"[*] Acquiring disk from '{disk_source}' -> {dest}...")
            subprocess.run(
                [
                    "ewfacquire",
                    "-u",
                    "-c",
                    "fast",
                    "-j",
                    "4",
                    "-t",
                    prefix,
                    disk_source,
                ],
                check=True,
            )
        finally:
            print(f"[*] Restarting '{domain}'...")
            provider.start_vm(domain)

        segments = sorted(glob.glob(f"{prefix}.E??"))
        if not segments:
            raise RuntimeError(f"EWF output not found for prefix {prefix}.E??")
        
        for seg in segments:
            subprocess.run(
            ["sudo", "chown", f"{os.getuid()}:{os.getuid()}", seg],
            check=True,)

        elapsed = time.time() - started
        ewf_size = sum(Path(p).stat().st_size for p in segments)
        print(f"[+] Disk acquisition done ({elapsed:.1f}s): {segments[0]}")

        return ImageMetadata(
            path=str(Path(segments[0]).relative_to(self.repo_root)),
            tool="ewfacquire -u -c fast -j 4",
            sha256=self._sha256(Path(segments[0])),
            size_bytes=Path(segments[0]).stat().st_size,
            timestamp=time.time(),
            acquisition_seconds=elapsed,
            virtual_size_bytes=virtual_size,
            ewf_size_bytes=ewf_size,
        )

    # --- helpers ----------------------------------------------------------

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
