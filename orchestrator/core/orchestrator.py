"""
orchestrator/core/orchestrator.py

Coordinates the full experiment lifecycle. Sits above vm_manager and
below attack modules — it knows the sequence, not the details.
"""

import json
import subprocess
import time
from pathlib import Path
from typing import Any

from infra.image_store import ensure_image
from infra.provider import Provider
from orchestrator.core.config import load_config, load_profile
from orchestrator.core.ssh_client import SSHClient
from orchestrator.core.vm_manager import VMManager
from orchestrator.forensics.dumper import Dumper


class ForensicOrchestrator:
    """
    Main entry point for experiment automation.

    Typical usage:
        orch = ForensicOrchestrator()
        orch.prepare("ubuntu-22.04")           # once per distro
        orch.run("ubuntu-22.04", "ptrace")     # repeatable
    """

    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = repo_root or Path(__file__).resolve().parents[2]
        self.cfg = load_config(self.repo_root)
        self.provider = Provider(self.cfg, self.repo_root)
        self.vm_manager = VMManager(self.cfg, self.provider, self.repo_root)
        self.dumper = Dumper(self.repo_root)
        self.results_path = Path(self.cfg["lab"]["shared_dir"]).expanduser() / "results"
        self.results_path.mkdir(parents=True, exist_ok=True)

    # --- one-time setup ---------------------------------------------------

    def setup(self) -> None:
        """Create libvirt network and storage pool. Run once on a new machine."""
        self.provider.ensure_network()
        self.provider.ensure_pool()

    # --- per-distro prepare -----------------------------------------------

    def prepare(self, distro_id: str) -> None:
        """
        Download image, create lab VM, take baseline snapshot.
        Safe to run multiple times — skips steps already done.
        """
        self._prepare_lab(distro_id)
        print(f"[+] '{distro_id}' ready for experiments")

    def build_isf(self, distro_id: str, profile: dict[str, Any] | None = None) -> Path:
        """Ensure ISF exists for the running lab kernel and return its path."""
        if profile is None:
            profile = self._prepare_lab(distro_id)
        lab_vm_name = f"lab-{distro_id}"
        lab_ip = self.vm_manager.wait_ssh_ready(lab_vm_name, reason="kernel detection")
        kernel_release = self._kernel_release(lab_ip)

        isf_name = self._isf_filename(distro_id, kernel_release)
        isf_path = self.repo_root / "shared" / "isf" / isf_name
        if isf_path.exists():
            print(f"[i] ISF already present: {isf_path}")
            return isf_path

        role_cfg = self.cfg["role_defaults"].get("build-isf")
        if not isinstance(role_cfg, dict):
            raise RuntimeError("Missing 'role_defaults.build-isf' config for ISF build VM")

        build_vm_name = f"build-isf-{distro_id}"
        base_image = self.vm_manager.ensure_base_image(profile)

        self.provider.shutdown_vm(lab_vm_name)
        self.provider.create_vm(
            role="build-isf",
            distro_id=distro_id,
            profile=profile,
            role_cfg=role_cfg,
            base_image=base_image,
        )
        self.provider.start_vm(build_vm_name)

        try:
            playbook = self.repo_root / ISF_BUILD_PLAYBOOK
            print("[*] Building ISF via ephemeral build VM...")
            print(f"[*] Kernel version: {kernel_release}")
            print(f"[*] ISF filename: {isf_name}")

            self.vm_manager.run_playbook_on_vm(
                build_vm_name,
                playbook,
                extra_vars={
                    "kernel_version": kernel_release,
                    "isf_filename": isf_name,
                    "shared_isf_dir": str(self.repo_root / "shared" / "isf"),
                },
                reason="isf build provisioning",
            )
        finally:
            self.provider.destroy_vm(build_vm_name)
            self.provider.start_vm(lab_vm_name)

        if not isf_path.exists():
            raise RuntimeError(f"ISF build completed but output not found: {isf_path}")

        print(f"[+] ISF exported: {isf_path}")
        return isf_path

    # --- experiment run ---------------------------------------------------

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
            with open(gt_path, "w") as f:
                json.dump(ground_truth, f, indent=2)
            print(f"[+] Ground truth saved: {gt_path}")

        if acquire:
            domain = vm_name
            return self.dumper.acquire(
                domain=domain,
                scenario_id=scenario_id,
                provider=self.provider,
            )

        return None

    def _run_attack(
        self,
        scenario: str,
        ip: str,
        scenario_id: str,
    ) -> dict | None:
        """
        Dynamically load and run the attack module for the given scenario.
        Each attack module must expose: run(ssh, scenario_id) -> dict
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

        user = self.cfg["lab"]["ssh_user"]
        key  = self.cfg["lab"]["ssh_key"]

        with SSHClient(ip, user, key) as ssh:
            mod = importlib.import_module(module_map[scenario])
            return mod.run(ssh, scenario_id)

    # --- acquire baseline only (no attack) --------------------------------

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
            provider=self.provider,
        )

    def _run_pipeline(self, distro_id: str) -> str:
        profile = self._prepare_lab(distro_id)
        self.build_isf(distro_id, profile=profile)
        manifest_path = self.acquire_baseline(distro_id)
        print(f"[+] Baseline acquisition manifest: {manifest_path}")
        return manifest_path

    def _kernel_release(self, ip: str) -> str:
        user = self.cfg["lab"]["ssh_user"]
        key = self.cfg["lab"]["ssh_key"]
        with SSHClient(ip, user, key) as ssh:
            return ssh.run_checked("uname -r")

    def _prepare_lab(self, distro_id: str) -> dict[str, Any]:
        profile = load_profile(self.repo_root, distro_id)
        self.vm_manager.prepare_lab(distro_id, profile)
        return profile

    def _revert_lab_and_wait(self, distro_id: str) -> tuple[str, str]:
        vm_name = f"lab-{distro_id}"
        self.vm_manager.revert_to_baseline(distro_id)
        ip = self.vm_manager.wait_ssh_ready(vm_name, reason="after snapshot revert")
        return vm_name, ip

    
    @staticmethod
    def _isf_filename(distro_id: str, kernel_release: str) -> str:
        distro_family = distro_id.split("-", 1)[0]
        return f"{distro_family}_{kernel_release}.json"

    # --- teardown ---------------------------------------------------------

    def destroy(self, distro_id: str) -> None:
        """Remove the lab VM and all its associated storage."""
        self.vm_manager.destroy_lab(distro_id)

    def close(self) -> None:
        self.provider.close()

    def __enter__(self) -> "ForensicOrchestrator":
        return self

    def __exit__(self, *_) -> None:
        self.close()