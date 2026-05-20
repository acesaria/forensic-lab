"""
orchestrator/core/orchestrator.py

Coordinates the full experiment lifecycle. Sits above vm_manager and
below attack modules -- it knows the sequence, not the details.

Public API
----------
setup_infra()              one-time: libvirt network + pool
prepare_lab(distro_id)     one-time: image + VM + baseline snapshot + pipeline verify
build_isf(distro_id)       one-time: Volatility symbol file
run_experiment(...)        experiment loop
destroy_lab(distro_id)     teardown
lab_exists(distro_id)      predicate
def verify_pipeline(distro_id: str): Acquire a baseline image and probe with Volatility + SleuthKit.

Naming contract
---------------
distro_id    short config key  e.g. "ubuntu-22.04"
vm_name      libvirt domain    e.g. "lab-ubuntu-22.04"
Public methods accept distro_id. Private helpers use vm_name after resolution.

VM power-state contract
-----------------------
prepare_lab        ends OFF (snapshot taken, pipeline probe done)
build_isf          ends OFF (lab parked, build VM destroyed)
_reset_lab         ends ON + SSH ready
_run_acquisition   ends ON (VM restarted after disk dump)
run_experiment     ends ON (caller decides when to shut down)
"""

from datetime import datetime
import json
import logging
from pathlib import Path
from typing import Any, Callable

from orchestrator.core.config import (
    BASELINE_DISK_FILENAME,
    BASELINE_MEMORY_FILENAME,
    BUILD_VM_PREFIX,
    ISF_BUILD_PLAYBOOK,
    ISF_SHARED_DIR,
    LAB_VM_PREFIX,
    VERIFY_SCENARIO,
    load_profile,
)
from orchestrator.core.vm_manager import VMManager
from orchestrator.attacks import ArtRunner
from orchestrator.forensics import Dumper
from orchestrator.forensics import SleuthKitRunner, VolatilityRunner

_log = logging.getLogger(__name__)


class ForensicOrchestrator:
    def __init__(
        self,
        vm_manager: VMManager,
        art_runner: ArtRunner,
        dumper: Dumper,
        vol_runner: VolatilityRunner,
        sleuth_runner: SleuthKitRunner,
        repo_root: Path,
        results_path: Path,
        role_defaults: dict[str, Any],
    ) -> None:
        self.vm_manager = vm_manager
        self._art_runner = art_runner
        self.dumper = dumper
        self._vol_runner = vol_runner
        self._sleuth_runner = sleuth_runner
        self.repo_root = repo_root
        self.results_path = results_path
        self.results_path.mkdir(parents=True, exist_ok=True)
        self._role_defaults = role_defaults

    # --- one-time setup --------------------------------------------------

    def setup_infra(self) -> None:
        """Create libvirt network and storage pool. Run once on a new machine."""
        self.vm_manager.ensure_isolated_network()
        self.vm_manager.ensure_storage_pool()

    def prepare_lab(self, distro_id: str) -> None:
        """
        Download image, create lab VM, provision, take baseline snapshot.
        Safe to run multiple times -- skips steps already done.
        VM ends OFF.
        """
        profile = load_profile(self.repo_root, distro_id)
        role_cfg = self._role_defaults.get("lab")
        if not isinstance(role_cfg, dict):
            raise RuntimeError("Missing 'role_defaults.lab' in config")
        self.vm_manager.prepare_lab(distro_id, profile, role_cfg)
        _log.info("[+] '%s' ready for experiments", distro_id)

    def build_isf(self, distro_id: str) -> Path:
        """
        Ensure a Volatility ISF symbol file exists for the lab VM's kernel.
        Starts the lab VM briefly to detect the kernel, then shuts it down.
        Creates an ephemeral build VM if the ISF is not cached.
        VM ends OFF. Returns the ISF path.
        """
        profile = load_profile(self.repo_root, distro_id)
        lab_vm_name = f"{LAB_VM_PREFIX}-{distro_id}"

        kernel_release = self._detect_kernel_release(lab_vm_name)

        isf_name = _isf_filename(distro_id, kernel_release)
        isf_dir = self.repo_root / ISF_SHARED_DIR
        isf_dir.mkdir(parents=True, exist_ok=True)
        isf_path = isf_dir / isf_name

        if isf_path.exists():
            _log.info("[i] Symbol file already present: %s", isf_path.absolute())
            return isf_path

        role_cfg = self._role_defaults.get("build-isf")
        if not isinstance(role_cfg, dict):
            raise RuntimeError("Missing 'role_defaults.build-isf' in config")

        self._build_isf_with_ephemeral_vm(
            distro_id=distro_id,
            profile=profile,
            role_cfg=role_cfg,
            kernel_release=kernel_release,
            isf_name=isf_name,
        )

        if not isf_path.exists():
            raise RuntimeError(f"ISF build completed but output not found: {isf_path}")

        _log.info("[+] ISF exported: %s", isf_path)
        return isf_path

    def lab_exists(self, distro_id: str) -> bool:
        return self.vm_manager.vm_exists(f"{LAB_VM_PREFIX}-{distro_id}")

    # --- experiment loop -------------------------------------------------

    def run_experiment(
        self,
        distro_id: str,
        scenario_cfg: dict[str, Any],
        acquire: bool = True,
    ) -> str | None:
        """
        Full experiment cycle:
        1. Revert VM to baseline and start it
        2. Run attack scenario, save ground truth
        3. Acquire RAM + disk (unless acquire=False)

        VM ends OFF after acquisition.
        Returns manifest path if acquired, else None.
        """
        scenario_id = scenario_cfg["technique_id"]
        _log.info("\n[*] Starting experiment: %s on %s", scenario_id, distro_id)
        vm_name = self._reset_lab(distro_id)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        scenario_ts = f"{distro_id}_{scenario_id}_{ts}"

        with self.vm_manager.open_ssh(vm_name) as ssh:
            ground_truth = self._art_runner.run_test(
                ssh._ip,
                scenario_id,
                scenario_cfg["test_guid"],
                cleanup=scenario_cfg["cleanup"],
            )
        if ground_truth:
            gt_path = self.results_path / f"gt_{scenario_id}.json"
            gt_path.write_text(json.dumps(ground_truth, indent=2))
            _log.info("[+] Ground truth saved: %s", gt_path)

        if acquire:
            return self._run_acquisition(vm_name, scenario_id)
        return None

    # --- teardown --------------------------------------------------------

    def destroy_lab(self, distro_id: str) -> None:
        """Remove the lab VM and all its associated storage."""
        self.vm_manager.destroy_lab(distro_id)

    def close(self) -> None:
        self.vm_manager.close()

    def __enter__(self) -> "ForensicOrchestrator":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # --- private: setup helpers ------------------------------------------

    def _detect_kernel_release(self, lab_vm_name: str) -> str:
        _log.info("[*] Detecting kernel on %s...", lab_vm_name)
        self.vm_manager.start_vm(lab_vm_name)
        self.vm_manager.wait_ssh_ready(lab_vm_name, reason="kernel detection")
        with self.vm_manager.open_ssh(lab_vm_name) as ssh:
            kernel_release = ssh.run_checked("uname -r")
        _log.info("[+] Kernel: %s", kernel_release)
        self.vm_manager.shutdown_vm(lab_vm_name)
        return kernel_release

    def _build_isf_with_ephemeral_vm(
        self,
        distro_id: str,
        profile: dict[str, Any],
        role_cfg: dict[str, Any],
        kernel_release: str,
        isf_name: str,
    ) -> None:
        """
        Create a temporary build VM, run the ISF build playbook, destroy it.
        Lab VM is not touched here.
        """
        build_vm_name = f"{BUILD_VM_PREFIX}-{distro_id}"
        base_image = self.vm_manager.ensure_base_image(profile)
        self.vm_manager.create_vm(
            role="build-isf",
            distro_id=distro_id,
            profile=profile,
            role_cfg=role_cfg,
            base_image=base_image,
        )
        try:
            self.vm_manager.start_vm(build_vm_name)
            try:
                self.vm_manager.run_playbook_on_vm(
                    build_vm_name,
                    self.repo_root / ISF_BUILD_PLAYBOOK,
                    extra_vars={
                        "kernel_version": kernel_release,
                        "isf_filename": isf_name,
                        "shared_isf_dir": str(self.repo_root / ISF_SHARED_DIR),
                    },
                    reason="isf build",
                )
            except RuntimeError as exc:
                raise RuntimeError(
                    f"ISF build: Ansible playbook failed for '{distro_id}'.\n"
                    "Common causes: no internet on build VM, kernel debuginfo "
                    f"package not available for kernel '{kernel_release}'.\n"
                    "Run with --debug to see full Ansible output.\n"
                    f"Original error: {exc}"
                ) from exc
        finally:
            self.vm_manager.destroy_vm(build_vm_name)

    def verify_pipeline(self, distro_id: str) -> None:
        """
        Acquire a baseline image and probe with Volatility + SleuthKit.
        Called automatically at the end of the CLI 'setup' sequence.
        Requires the ISF to already exist (call after build_isf).
        VM ends OFF.
        """
        vm_name = self._reset_lab(distro_id)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        scenario_id = f"{distro_id}_{VERIFY_SCENARIO}_{ts}"

        manifest_path = self._run_acquisition(vm_name, scenario_id)

        manifest = json.loads(Path(manifest_path).read_text())
        memory_path = self.repo_root / manifest["memory_image"]["path"]
        disk_path = self.repo_root / manifest["disk_image"]["path"]

        _log.info("\n[*] Probing acquired images for %s...", distro_id)
        self._vol_runner.probe(memory_path, distro_id)
        self._sleuth_runner.probe(disk_path)
        _log.info("[+] Pipeline verified for '%s'", distro_id)

    # --- private: experiment helpers -------------------------------------

    def _reset_lab(self, distro_id: str) -> str:
        """
        Revert to baseline snapshot, start VM, wait for SSH.
        VM ends ON + SSH ready. Returns vm_name.
        """
        vm_name = f"{LAB_VM_PREFIX}-{distro_id}"
        _log.info("[*] Reverting '%s' to baseline snapshot...", vm_name)
        self.vm_manager.revert_to_baseline(distro_id)
        self.vm_manager.start_vm(vm_name)
        self.vm_manager.wait_ssh_ready(vm_name, reason="after snapshot revert")
        return vm_name

    def _run_acquisition(self, vm_name: str, scenario_id: str) -> str:
        """
        Acquire memory (VM ON) then disk (VM OFF).
        VM ends OFF. Returns manifest path.
        """
        disk_source = self.vm_manager.get_disk_path(vm_name)
        scenario_dir = self.dumper.scenario_dir(scenario_id)
        memory_path = scenario_dir / "memory" / BASELINE_MEMORY_FILENAME
        disk_path = scenario_dir / "disk" / BASELINE_DISK_FILENAME

        memory_meta = self.dumper.acquire_memory(vm_name, memory_path)
        self.vm_manager.shutdown_vm(vm_name)
        disk_meta = self.dumper.acquire_disk(vm_name, disk_source, disk_path)

        return self.dumper.write_manifest(scenario_id, memory_meta, disk_meta)


# --- module helpers ------------------------------------------------------


def _isf_filename(distro_id: str, kernel_release: str) -> str:
    family = distro_id.split("-", 1)[0]
    safe_kernel = kernel_release.replace("/", "_")
    return f"{family}_{safe_kernel}.json"
