"""
orchestrator/core/orchestrator.py

Coordinates the full experiment lifecycle. Sits above vm_manager and
below attack modules — it knows the sequence, not the details.
"""

import json
import time
from pathlib import Path
from typing import Any

from orchestrator.core.config import ISF_BUILD_PLAYBOOK, ISF_SHARED_DIR, load_profile
from orchestrator.core.ssh_client import SSHClient
from orchestrator.core.vm_manager import VMManager
from orchestrator.forensics.dumper import Dumper


class ForensicOrchestrator:
    def __init__(
        self,
        vm_manager: VMManager,
        dumper: Dumper,
        repo_root: Path,
        results_path: Path,
        role_defaults: dict[str, Any],
        ssh_user: str,
        ssh_key: str,
    ) -> None:
        self.vm_manager = vm_manager
        self.dumper = dumper
        self.repo_root = repo_root
        self.results_path = results_path
        self.results_path.mkdir(parents=True, exist_ok=True)
        self._role_defaults = role_defaults
        self._ssh_user = ssh_user
        self._ssh_key = ssh_key

    # --- one-time infra setup ---------------------------------------------

    def setup_infra(self) -> None:
        """Create libvirt network and storage pool. Run once on a new machine."""
        self.vm_manager.ensure_network()
        self.vm_manager.ensure_pool()

    # --- per-distro lifecycle ---------------------------------------------

    def prepare_lab(self, distro_id: str) -> None:
        """
        Download image, create lab VM, take baseline snapshot.
        Safe to run multiple times — skips steps already done.
        """
        profile = load_profile(self.repo_root, distro_id)
        role_cfg = self._role_defaults.get("lab")
        if not isinstance(role_cfg, dict):
            raise RuntimeError("Missing 'role_defaults.lab' config for lab VM")
        self.vm_manager.prepare_lab(distro_id, profile, role_cfg)
        print(f"[+] '{distro_id}' ready for experiments")

    def lab_exists(self, distro_id: str) -> bool:
        return self.vm_manager.vm_exists(f"lab-{distro_id}")

    def build_isf(self, distro_id: str, profile: dict[str, Any] | None = None) -> Path:
        """Ensure ISF exists for the running lab kernel and return its path."""
        if profile is None:
            profile = load_profile(self.repo_root, distro_id)

        lab_vm_name = f"lab-{distro_id}"
        print(f"[*] Starting {lab_vm_name} to detect kernel version for ISF build...")
        self.vm_manager.start_vm(lab_vm_name)

        lab_ip = self.vm_manager.wait_ssh_ready(lab_vm_name, reason="kernel detection")
        kernel_release = self._kernel_release(lab_ip)

        print(f"[*] Detected kernel version: {kernel_release}. Shutting down lab VM {lab_vm_name}...")
        self.vm_manager.shutdown_vm(lab_vm_name)

        isf_name = self._isf_filename(distro_id, kernel_release)
        isf_dir = self.repo_root / ISF_SHARED_DIR
        isf_dir.mkdir(parents=True, exist_ok=True)
        isf_path = isf_dir / isf_name
        if isf_path.exists():
            print(f"[i] ISF already present: {isf_path}")
            return isf_path

        role_cfg = self._role_defaults.get("build-isf")
        if not isinstance(role_cfg, dict):
            raise RuntimeError("Missing 'role_defaults.build-isf' config for ISF build VM")

        build_vm_name = f"build-isf-{distro_id}"
        base_image = self.vm_manager.ensure_base_image(profile)
        self.vm_manager.create_vm(
            role="build-isf",
            distro_id=distro_id,
            profile=profile,
            role_cfg=role_cfg,
            base_image=base_image,
        )

        try:
            playbook = self.repo_root / ISF_BUILD_PLAYBOOK
            print(f"[*] Building ISF via ephemeral build VM (kernel: {kernel_release})...")
            self.vm_manager.run_playbook_on_vm(
                build_vm_name,
                playbook,
                extra_vars={
                    "kernel_version": kernel_release,
                    "isf_filename": isf_name,
                    "shared_isf_dir": str(self.repo_root / ISF_SHARED_DIR),
                },
                reason="isf build provisioning",
            )
        finally:
            self.vm_manager.destroy_vm(build_vm_name)
            self.vm_manager.start_vm(lab_vm_name)

        if not isf_path.exists():
            raise RuntimeError(f"ISF build completed but output not found: {isf_path}")

        print(f"[+] ISF exported: {isf_path}")
        return isf_path

    # --- experiment execution ---------------------------------------------

    def run(
        self,
        distro_id: str,
        scenario: str,
        acquire: bool = True,
    ) -> str | None:
        """
        Full experiment cycle:
          1. Revert VM to baseline snapshot
          2. Wait for SSH
          3. Run attack scenario
          4. Acquire RAM + disk (unless acquire=False)

        Returns manifest path if acquired, else None.
        """
        print(f"\n[*] Setting up experiment: {scenario} on {distro_id}")
        vm_name, ip = self._revert_lab_and_wait(distro_id)
        scenario_id = f"{distro_id}__{scenario}__{int(time.time())}"

        ground_truth = self._run_attack(scenario, ip, scenario_id)
        if ground_truth:
            gt_path = self.results_path / f"gt_{scenario_id}.json"
            gt_path.write_text(json.dumps(ground_truth, indent=2))
            print(f"[+] Ground truth saved: {gt_path}")

        if acquire:
            return self.dumper.acquire(
                domain=vm_name,
                scenario_id=scenario_id,
                vm_manager=self.vm_manager,
            )
        return None

    def acquire_baseline(self, distro_id: str) -> str:
        """
        Revert to baseline and acquire RAM + disk without running any attack.
        Useful for building a pristine reference image.
        """
        vm_name, _ = self._revert_lab_and_wait(distro_id)
        scenario_id = f"{distro_id}__baseline__{int(time.time())}"
        return self.dumper.acquire(
            domain=vm_name,
            scenario_id=scenario_id,
            vm_manager=self.vm_manager,
        )

    def run_pipeline(self, distro_id: str) -> str:
        """
        Full pipeline for a distro: build ISF, acquire baseline, shut down.
        Entry point for the 'run' CLI command.
        """
        self.build_isf(distro_id)
        manifest_path = self.acquire_baseline(distro_id)
        print(f"[+] Baseline acquisition manifest: {manifest_path}")
        self.vm_manager.shutdown_vm(f"lab-{distro_id}")
        return manifest_path

    # --- teardown ---------------------------------------------------------

    def destroy_lab(self, distro_id: str) -> None:
        """Remove the lab VM and all its associated storage."""
        self.vm_manager.destroy_lab(distro_id)

    def close(self) -> None:
        self.vm_manager.close()

    def __enter__(self) -> "ForensicOrchestrator":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # --- private helpers --------------------------------------------------

    def _revert_lab_and_wait(self, distro_id: str) -> tuple[str, str]:
        vm_name = f"lab-{distro_id}"
        self.vm_manager.revert_to_baseline(distro_id)

        print(f"[*] Start VM {vm_name} after snapshot revert...")
        self.vm_manager.start_vm(vm_name)
        ip = self.vm_manager.wait_ssh_ready(vm_name, reason="after snapshot revert")
        return vm_name, ip

    def _run_attack(self, scenario: str, ip: str, scenario_id: str) -> dict | None:
        """
        Dynamically load and run the attack module for the given scenario.
        Each attack module must expose: run(ssh, scenario_id) -> dict | None
        """
        import importlib
        module_map = {
            "ptrace":     "orchestrator.attacks.attack_01_ptrace",
            "metasploit": "orchestrator.attacks.attack_05_metasploit",
            "kernel":     "orchestrator.attacks.attack_06_kernel",
        }

        if scenario not in module_map:
            print(f"[!] Unknown scenario '{scenario}', skipping attack step")
            return None

        with SSHClient(ip, self._ssh_user, self._ssh_key) as ssh:
            mod = importlib.import_module(module_map[scenario])
            return mod.run(ssh, scenario_id)

    def _kernel_release(self, ip: str) -> str:
        with SSHClient(ip, self._ssh_user, self._ssh_key) as ssh:
            return ssh.run_checked("uname -r")

    @staticmethod
    def _isf_filename(distro_id: str, kernel_release: str) -> str:
        distro_family = distro_id.split("-", 1)[0]
        return f"{distro_family}_{kernel_release}.json"