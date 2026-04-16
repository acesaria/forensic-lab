import hashlib
import json
import os
import subprocess
import time
import glob
from dataclasses import dataclass, asdict
from typing import Optional

from orchestrator.core.orchestrator import ForensicOrchestrator


@dataclass
class ImageMetadata:
    path: str
    tool: str
    sha256: Optional[str]
    size_bytes: Optional[int]
    timestamp: float
    acquisition_seconds: Optional[float] = None
    virtual_size_bytes: Optional[int] = None
    ewf_size_bytes: Optional[int] = None


@dataclass
class AcquisitionManifest:
    scenario_id: str          # es.: "baseline_pristine" o "ptrace_injection_01"
    created_at: float
    memory_image: ImageMetadata
    disk_image: ImageMetadata


class Dumper:
    """
    Handles directory layout and manifest generation
    for memory+disk acquisition per scenario.
    """

    def __init__(self, project_root: Optional[str] = None) -> None:
        if project_root is None:
            project_root = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..")
            )
        self.project_root = project_root
        self.dumps_root = os.path.join(self.project_root, "shared", "dumps")
        os.makedirs(self.dumps_root, exist_ok=True)

    def _scenario_dir(self, scenario_id: str) -> str:
        path = os.path.join(self.dumps_root, scenario_id)
        os.makedirs(path, exist_ok=True)
        os.makedirs(os.path.join(path, "memory"), exist_ok=True)
        os.makedirs(os.path.join(path, "disk"), exist_ok=True)
        return path

    def _write_manifest(self, scenario_id: str, manifest: AcquisitionManifest) -> str:
        scenario_dir = self._scenario_dir(scenario_id)
        manifest_path = os.path.join(scenario_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(asdict(manifest), f, indent=4)
        return manifest_path

    def _sha256_file(self, file_path: str) -> str:
        digest = hashlib.sha256()
        with open(file_path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _file_size(self, file_path: str) -> int:
        return os.path.getsize(file_path)

    def _safe_remove(self, orchestrator: ForensicOrchestrator, file_path: str) -> None:
        if not os.path.exists(file_path):
            return
        try:
            os.remove(file_path)
        except PermissionError:
            orchestrator.run_host_command(
                ["rm", "-f", file_path],
                require_command="rm",
                sudo=True,
            )

    def _get_qemu_virtual_size(
        self,
        orchestrator: ForensicOrchestrator,
        disk_source: str,
    ) -> Optional[int]:
        try:
            result = orchestrator.run_host_command(
                ["qemu-img", "info", "--output", "json", disk_source],
                require_command="qemu-img",
                sudo=True,
            )
            info = json.loads(result.stdout)
            virtual_size = info.get("virtual-size")
            if isinstance(virtual_size, int):
                return virtual_size
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return None
        return None

    def _find_free_nbd_device(self) -> str:
        for index in range(0, 32):
            device = f"/dev/nbd{index}"
            if not os.path.exists(device):
                continue
            pid_path = f"/sys/class/block/nbd{index}/pid"
            if not os.path.exists(pid_path):
                return device
        raise RuntimeError("No free NBD device available (expected /dev/nbd0..nbd31)")

    def _acquire_memory_image(
        self,
        orchestrator: ForensicOrchestrator,
        domain: str,
        memory_path: str,
    ) -> ImageMetadata:
        self._safe_remove(orchestrator, memory_path)

        started_at = time.time()
        print(f"[*] Acquiring memory dump from domain '{domain}'...")
        orchestrator.run_host_command(
            [
                "virsh",
                "dump",
                domain,
                memory_path,
                "--memory-only",
                "--live",
            ],
            require_command="virsh",
            sudo=True,
        )

        orchestrator.run_host_command(["chown", f"{os.getuid()}:{os.getgid()}", memory_path],sudo=True)
        completed_at = time.time()

        print(f"[+] Memory dump acquired: {memory_path}")

        return ImageMetadata(
            path=os.path.relpath(memory_path, self.project_root),
            tool="virsh dump --memory-only --live",
            sha256=self._sha256_file(memory_path),
            size_bytes=self._file_size(memory_path),
            timestamp=completed_at,
            acquisition_seconds=completed_at - started_at,
        )

    def _get_domain_state(
        self,
        orchestrator: ForensicOrchestrator,
        domain: str,
    ) -> str:
        result = orchestrator.run_host_command(
            ["virsh", "domstate", domain],
            require_command="virsh",
            sudo=True,
        )
        return (result.stdout or "").strip().lower()

    def _wait_domain_state(
        self,
        orchestrator: ForensicOrchestrator,
        domain: str,
        expected_substring: str,
        timeout_seconds: int = 60,
    ) -> bool:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            if expected_substring in self._get_domain_state(orchestrator, domain):
                return True
            time.sleep(1)
        return False

    def _acquire_disk_image(
        self,
        orchestrator: ForensicOrchestrator,
        domain: str,
        disk_path: str,
    ) -> ImageMetadata:
        disk_source = orchestrator.get_domain_disk_source(domain)
        virtual_size = self._get_qemu_virtual_size(orchestrator, disk_source)
        disk_prefix, _ = os.path.splitext(disk_path)

        for existing_segment in glob.glob(f"{disk_prefix}.E??"):
            self._safe_remove(orchestrator, existing_segment)

        print(f"[*] Acquiring disk image from source: {disk_source}")
        started_at = time.time()
        nbd_device: Optional[str] = None
        was_running = False

        try:
            state = self._get_domain_state(orchestrator, domain)
            was_running = ("running" in state) or ("paused" in state)

            if was_running:
                orchestrator.run_host_command(
                    ["virsh", "shutdown", domain],
                    require_command="virsh",
                    sudo=True,
                )
                if not self._wait_domain_state(orchestrator, domain, "shut off", timeout_seconds=90):
                    orchestrator.run_host_command(
                        ["virsh", "destroy", domain],
                        require_command="virsh",
                        sudo=True,
                    )
                    if not self._wait_domain_state(orchestrator, domain, "shut off", timeout_seconds=20):
                        raise RuntimeError(f"Domain '{domain}' did not reach 'shut off' state")

            try:
                orchestrator.run_host_command(
                    ["modprobe", "nbd", "max_part=16"],
                    require_command="modprobe",
                    sudo=True,
                )
            except subprocess.CalledProcessError as exc:
                error_text = exc.stderr.strip() if exc.stderr else str(exc)
                raise RuntimeError(f"Failed to load nbd kernel module: {error_text}") from exc

            nbd_device = self._find_free_nbd_device()

            try:
                orchestrator.run_host_command(
                    ["qemu-nbd", "--read-only", "--connect", nbd_device, disk_source],
                    require_command="qemu-nbd",
                    sudo=True,
                )
            except subprocess.CalledProcessError as exc:
                error_text = exc.stderr.strip() if exc.stderr else str(exc)
                raise RuntimeError(f"qemu-nbd connect failed: {error_text}") from exc

            try:
                orchestrator.run_host_command(
                    ["ewfacquire", "-u", "-c", "fast", "-j", "4", "-t", disk_prefix, nbd_device],
                    require_command="ewfacquire",
                    sudo=True,
                )
            except subprocess.CalledProcessError as exc:
                error_text = exc.stderr.strip() if exc.stderr else str(exc)
                raise RuntimeError(f"ewfacquire failed: {error_text}") from exc

        finally:
            if nbd_device:
                try:
                    orchestrator.run_host_command(
                        ["qemu-nbd", "--disconnect", nbd_device],
                        require_command="qemu-nbd",
                        sudo=True,
                    )
                except subprocess.CalledProcessError:
                    print(f"[!] Failed to disconnect NBD device '{nbd_device}'. Disconnect it manually.")

            if was_running:
                try:
                    orchestrator.run_host_command(
                        ["virsh", "start", domain],
                        require_command="virsh",
                        sudo=True,
                    )
                except subprocess.CalledProcessError:
                    print(f"[!] Failed to start domain '{domain}'. Start it manually.")

        if not os.path.exists(disk_path):
            raise RuntimeError(f"EWF output not found at expected path: {disk_path}")

        completed_at = time.time()
        print(f"[+] Disk EWF acquired: {disk_path}")

        ewf_size = self._file_size(disk_path)
        return ImageMetadata(
            path=os.path.relpath(disk_path, self.project_root),
            tool="qemu-nbd --read-only + ewfacquire -c fast -j 4",
            sha256=self._sha256_file(disk_path),
            size_bytes=ewf_size,
            timestamp=completed_at,
            acquisition_seconds=completed_at - started_at,
            virtual_size_bytes=virtual_size,
            ewf_size_bytes=ewf_size,
        )


    # ---------- Baseline pristine acquisition ----------

    def acquire_pristine_baseline(
        self,
        orchestrator: ForensicOrchestrator,
        snapshot_name: str = "baseline",
        scenario_id: str = "baseline_pristine",
    ) -> str:
        """
        Restore victim to baseline snapshot, acquire RAM+disk images,
        and write a manifest describing the acquisition.
        Returns manifest path.
        """
        # 1) Assicuriamo stato baseline della vittima
        orchestrator.restore_victim_snapshot(snapshot_name)

        scenario_dir = self._scenario_dir(scenario_id)
        memory_path = os.path.join(scenario_dir, "memory", "baseline_memory.raw")
        disk_path = os.path.join(scenario_dir, "disk", "baseline_disk.E01")

        # 2) Host-side acquisition through libvirt + EWF tools.
        domain = orchestrator.resolve_victim_domain()

        memory_meta = self._acquire_memory_image(
            orchestrator=orchestrator,
            domain=domain,
            memory_path=memory_path,
        )

        disk_meta = self._acquire_disk_image(
            orchestrator=orchestrator,
            domain=domain,
            disk_path=disk_path,
        )

        # Ensure acquisition artifacts are readable for hashing when created as root.
        orchestrator.run_host_command(
            ["chown", "-R", f"{os.getuid()}:{os.getgid()}", scenario_dir],
            require_command="chown",
            sudo=True,
        )

        manifest_created_at = time.time()

        manifest = AcquisitionManifest(
            scenario_id=scenario_id,
            created_at=manifest_created_at,
            memory_image=memory_meta,
            disk_image=disk_meta,
        )

        manifest_path = self._write_manifest(scenario_id, manifest)
        print(f"[+] Baseline manifest written to {manifest_path}")
        return manifest_path
