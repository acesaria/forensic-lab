"""
orchestrator/core/vm_manager.py

High-level VM operations oriented around experiments.
This layer sits between the orchestrator and provider:
- provider knows how to create/destroy/snapshot VMs
- vm_manager knows when and why to do those things
"""

import time
from pathlib import Path
from typing import Any

from infra.image_store import ensure_image
from infra.provider import Provider
from orchestrator.core.ssh_client import SSHClient

BASELINE_SNAPSHOT = "baseline"


class VMManager:
    def __init__(
        self,
        cfg: dict[str, Any],
        provider: Provider,
        repo_root: Path,
    ) -> None:
        self._cfg = cfg
        self._provider = provider
        self._images_dir = (
            Path(cfg["lab"]["pool_path"]).expanduser().resolve().parent / "images"
        )
        self._repo_root = repo_root

    def _role_cfg(self, role: str) -> dict[str, Any]:
        return self._cfg["role_defaults"][role]

    def _ssh_cfg(self) -> tuple[str, str]:
        return (
            self._cfg["lab"]["ssh_user"],
            self._cfg["lab"]["ssh_key"],
        )

    # --- prepare (one-time per distro) ------------------------------------

    def prepare_lab(
        self,
        distro_id: str,
        profile: dict[str, Any],
    ) -> str:
        """
        Full setup for a lab VM:
          1. Download and verify base image
          2. Create VM (skips if already exists)
          3. Wait for SSH to be ready
          4. Create baseline snapshot (skips if already exists)

        Returns the VM name.
        """
        vm_name = f"lab-{distro_id}"

        base_image = ensure_image(profile, self._images_dir)

        self._provider.create_vm(
            role="lab",
            distro_id=distro_id,
            profile=profile,
            role_cfg=self._role_cfg("lab"),
            base_image=base_image,
        )

        self._provider.start_vm(vm_name)

        self.wait_ssh_ready(vm_name)

        if not self._provider.snapshot_exists(vm_name, BASELINE_SNAPSHOT):
            self._provider.create_snapshot(vm_name, BASELINE_SNAPSHOT)
        else:
            print(f"[i] Snapshot '{BASELINE_SNAPSHOT}' already exists on '{vm_name}'")

        return vm_name

    # --- experiment setup (before every run) ------------------------------

    def revert_to_baseline(self, distro_id: str) -> str:
        """
        Revert the lab VM to its baseline snapshot.
        Called before every experiment to guarantee a clean state.

        Returns the VM name.
        """
        vm_name = f"lab-{distro_id}"

        if not self._provider.snapshot_exists(vm_name, BASELINE_SNAPSHOT):
            raise RuntimeError(
                f"No baseline snapshot on '{vm_name}'. "
                "Run 'prepare' first."
            )

        self._provider.revert_snapshot(vm_name, BASELINE_SNAPSHOT)
        return vm_name

    # --- SSH readiness polling --------------------------------------------

    def wait_ssh_ready(
        self,
        vm_name: str,
        timeout: int = 180,
    ) -> str:
        """
        Wait until SSH is accepting connections on the VM.
        Returns the IP once ready.
        """
        ip = self._provider.get_vm_ip(vm_name)
        user, key = self._ssh_cfg()

        print(f"[*] Waiting for SSH on {ip}...")
        deadline = time.time() + timeout
        last_error = ""

        while time.time() < deadline:
            try:
                with SSHClient(ip, user, key) as ssh:
                    ssh.run_checked("true")
                print(f"[+] SSH ready on {vm_name} ({ip})")
                return ip
            except Exception as e:
                last_error = str(e)
                time.sleep(5)

        raise RuntimeError(
            f"SSH not ready on '{vm_name}' after {timeout}s: {last_error}"
        )

    # --- open SSH session (used by orchestrator and attack modules) -------

    def open_ssh(self, vm_name: str) -> SSHClient:
        """
        Resolve the VM's current IP and return a connected SSHClient.
        Caller is responsible for closing it (or using it as context manager).
        """
        ip = self._provider.get_vm_ip(vm_name)
        user, key = self._ssh_cfg()
        client = SSHClient(ip, user, key)
        client.connect()
        return client

    # --- teardown ---------------------------------------------------------

    def destroy_lab(self, distro_id: str) -> None:
        """Remove the lab VM and all its storage."""
        self._provider.destroy_vm(f"lab-{distro_id}")
