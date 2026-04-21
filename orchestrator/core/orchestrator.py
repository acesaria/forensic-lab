"""
orchestrator/core/orchestrator.py

Coordinates the full experiment lifecycle. Sits above vm_manager and
below attack modules — it knows the sequence, not the details.
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Optional

import yaml

from infra.provider import Provider
from orchestrator.core.vm_manager import VMManager
from orchestrator.forensics.dumper import Dumper


def _load_config(repo_root: Path) -> dict[str, Any]:
    path = repo_root / "config.yaml"
    with open(path) as f:
        return yaml.safe_load(f)


def _load_profile(repo_root: Path, distro_id: str) -> dict[str, Any]:
    path = repo_root / "infra" / "profiles" / f"{distro_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(
            f"No profile found for '{distro_id}' at {path}\n"
            "Add a YAML file in infra/profiles/ to support this distro."
        )
    with open(path) as f:
        return yaml.safe_load(f)


class ForensicOrchestrator:
    """
    Main entry point for experiment automation.

    Typical usage:
        orch = ForensicOrchestrator()
        orch.prepare("ubuntu-22.04")           # once per distro
        orch.run("ubuntu-22.04", "ptrace")     # repeatable
    """

    def __init__(self, repo_root: Optional[Path] = None) -> None:
        self.repo_root = repo_root or Path(__file__).resolve().parents[2]
        self.cfg = _load_config(self.repo_root)
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
        profile = _load_profile(self.repo_root, distro_id)
        self.vm_manager.prepare_lab(distro_id, profile)
        print(f"[+] '{distro_id}' ready for experiments")

    # --- experiment run ---------------------------------------------------

    def run(
        self,
        distro_id: str,
        scenario: str,
        acquire: bool = True,
    ) -> Optional[str]:
        """
        Full experiment cycle:
          1. Revert VM to baseline snapshot
          2. Wait for SSH
          3. Run attack scenario
          4. Acquire RAM + disk (unless acquire=False)

        Returns manifest path if acquired, else None.
        """
        profile = _load_profile(self.repo_root, distro_id)
        vm_name = f"lab-{distro_id}"

        print(f"\n[*] Setting up experiment: {scenario} on {distro_id}")
        self.vm_manager.revert_to_baseline(distro_id)
        ip = self.vm_manager.wait_ssh_ready(vm_name)

        scenario_id = f"{distro_id}__{scenario}__{int(time.time())}"

        ground_truth = self._run_attack(scenario, vm_name, ip, scenario_id)
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
        vm_name: str,
        ip: str,
        scenario_id: str,
    ) -> Optional[dict]:
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

        from orchestrator.core.ssh_client import SSHClient
        with SSHClient(ip, user, key) as ssh:
            mod = importlib.import_module(module_map[scenario])
            return mod.run(ssh, scenario_id)

    # --- acquire baseline only (no attack) --------------------------------

    def acquire_baseline(self, distro_id: str) -> str:
        """
        Revert to baseline and acquire RAM + disk without running any attack.
        Useful for building a pristine reference image.
        """
        vm_name = f"lab-{distro_id}"
        self.vm_manager.revert_to_baseline(distro_id)
        self.vm_manager.wait_ssh_ready(vm_name)

        scenario_id = f"{distro_id}__baseline__{int(time.time())}"
        return self.dumper.acquire(
            domain=vm_name,
            scenario_id=scenario_id,
            provider=self.provider,
        )

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