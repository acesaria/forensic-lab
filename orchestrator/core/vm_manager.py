"""
orchestrator/core/vm_manager.py

High-level VM operations oriented around experiments.
This layer sits between the orchestrator and provider:
- provider knows how to create/destroy/snapshot VMs
- vm_manager knows when and why to do those things
"""

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from infra.image_store import ensure_image
from infra.provider import Provider
from orchestrator.core.config import (
    BASELINE_SNAPSHOT,
    CLOUD_INIT_META_DATA,
    CLOUD_INIT_USER_DATA,
    LAB_BASELINE_PLAYBOOK,
)
from orchestrator.core.ssh_client import SSHClient


class VMManager:
    def __init__(
        self,
        provider: Provider,
        images_path: Path,
        ssh_user: str,
        ssh_key: str,
        repo_root: Path,
    ) -> None:
        self._provider = provider
        self._images_dir = images_path.expanduser().resolve()
        self._ssh_user = ssh_user
        self._ssh_key = Path(ssh_key).expanduser()
        self._repo_root = repo_root

    def _ssh_cfg(self) -> tuple[str, str]:
        # Now uses stored instance variables
        return self._ssh_user, str(self._ssh_key)


    def ensure_base_image(self, profile: dict[str, Any]) -> Path:
        return ensure_image(profile, self._images_dir)

    # --- provider wrappers -----------------------------------------------

    def ensure_network(self) -> None:
        self._provider.ensure_network()

    def ensure_pool(self) -> None:
        self._provider.ensure_pool()

    def vm_exists(self, vm_name: str) -> bool:
        return self._provider.vm_exists(vm_name)

    def create_vm(
        self,
        role: str,
        distro_id: str,
        profile: dict[str, Any],
        role_cfg: dict[str, Any],
        base_image: Path,
        seed_path: Path | None = None,
    ) -> str:
        vm_name = f"{role}-{distro_id}"
        if seed_path is None and not self.vm_exists(vm_name):
            seed_path = self._create_cloud_init_seed(vm_name)
        return self._provider.create_vm(
            role=role,
            distro_id=distro_id,
            profile=profile,
            role_cfg=role_cfg,
            base_image=base_image,
            seed_path=seed_path,
        )

    def start_vm(self, vm_name: str) -> None:
        self._provider.start_vm(vm_name)

    def shutdown_vm(self, vm_name: str, timeout: int = 90) -> None:
        self._provider.shutdown_vm(vm_name, timeout=timeout)

    def destroy_vm(self, vm_name: str) -> None:
        self._provider.destroy_vm(vm_name)

    def snapshot_exists(self, vm_name: str, snapshot_name: str) -> bool:
        return self._provider.snapshot_exists(vm_name, snapshot_name)

    def create_snapshot(self, vm_name: str, snapshot_name: str) -> None:
        self._provider.create_snapshot(vm_name, snapshot_name)

    def revert_snapshot(self, vm_name: str, snapshot_name: str) -> None:
        self._provider.revert_snapshot(vm_name, snapshot_name)

    def get_disk_path(self, vm_name: str) -> str:
        return self._provider.get_disk_path(vm_name)

    def get_vm_ip(self, vm_name: str, timeout: int = 120) -> str:
        return self._provider.get_vm_ip(vm_name, timeout=timeout)
    # --- prepare (one-time per distro) ------------------------------------
        
    def _run_playbook(
        self,
        ip: str,
        playbook: Path,
        extra_vars: dict[str, str] | None = None,
    ) -> None:

        user, key = self._ssh_cfg()
        cmd = [
            "ansible-playbook",
            "-i", f"{ip},",
            "-u", user,
            "--private-key", str(Path(key).expanduser()),
            "--ssh-common-args", "-o StrictHostKeyChecking=no",
            str(playbook),
        ]

        if extra_vars:
            for k, v in extra_vars.items():
                cmd.extend(["-e", f"{k}={v}"])

        result = subprocess.run(cmd, check=False, capture_output=False)
        if result.returncode != 0:
            
            raise RuntimeError(
                f"Ansible playbook failed (rc={result.returncode}): {playbook}"
            )

    def run_playbook_on_vm(
        self,
        vm_name: str,
        playbook: Path,
        extra_vars: dict[str, str] | None = None,
        reason: str = "",
    ) -> str:
        """
        Wait for SSH on a VM, then run an Ansible playbook on it.
        Returns the VM IP used.
        """
        ip = self.wait_ssh_ready(vm_name, reason=reason)
        self._run_playbook(ip, playbook, extra_vars=extra_vars)
        return ip


    def prepare_lab(
        self,
        distro_id: str,
        profile: dict[str, Any],
        role_cfg: dict[str, Any],
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

        if not self.vm_exists(vm_name):
            self.create_vm(
                role="lab",
                distro_id=distro_id,
                profile=profile,
                role_cfg=role_cfg,
                base_image=base_image,
            )
        else:
            print(f"[i] VM '{vm_name}' already exists, skipping creation")

        self._provider.start_vm(vm_name)

        ip = self.wait_ssh_ready(vm_name, reason="initial boot")

        if not self._provider.snapshot_exists(vm_name, BASELINE_SNAPSHOT):
            playbook = self._repo_root / LAB_BASELINE_PLAYBOOK
            self.run_playbook_on_vm(
                vm_name,
                playbook,
                reason="baseline provisioning",
            )
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
        reason: str = "",
    ) -> str:
        """
        Wait until SSH is accepting connections on the VM.
        Returns the IP once ready.
        """
        self._provider.start_vm(vm_name)
        ip = self._provider.get_vm_ip(vm_name)
        label = f" [{reason}]" if reason else ""
        user, key = self._ssh_cfg()

        print(f"[*] Waiting for SSH on {vm_name} ({ip}){label}...")
        deadline = time.time() + timeout
        last_error = ""

        while time.time() < deadline:
            try:
                with SSHClient(ip, user, key) as ssh:
                    ssh.run_checked("true")
                print(f"[+] SSH ready on {vm_name} ({ip}){label}")
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
        self._provider.start_vm(vm_name)
        ip = self._provider.get_vm_ip(vm_name)
        user, key = self._ssh_cfg()
        client = SSHClient(ip, user, key)
        client.connect()
        return client

    # --- teardown ---------------------------------------------------------

    def destroy_lab(self, distro_id: str) -> None:
        """Remove the lab VM and all its storage."""
        self._provider.destroy_vm(f"lab-{distro_id}")

    def close(self) -> None:
        self._provider.close()

    # --- cloud-init rendering --------------------------------------------

    def _create_cloud_init_seed(self, vm_name: str) -> Path:
        pool_path = self._provider.pool_path()
        seed_path = pool_path / f"{vm_name}-seed.iso"
        if seed_path.exists():
            seed_path.unlink()

        with tempfile.TemporaryDirectory() as tmp:
            meta_path = Path(tmp) / "meta-data"
            user_path = Path(tmp) / "user-data"
            meta_path.write_text(self._render_meta_data(vm_name))
            user_path.write_text(self._render_user_data())

            result = subprocess.run(
                [
                    "cloud-localds",
                    str(seed_path),
                    str(user_path),
                    str(meta_path),
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"cloud-localds failed:\n{result.stderr.strip()}"
                )

        return seed_path

    def _render_user_data(self) -> str:
        public_key_path = self._public_key_path()
        pubkey = public_key_path.read_text().strip()
        template = (self._repo_root / CLOUD_INIT_USER_DATA).read_text()
        return template.replace("__SSH_PUBLIC_KEY__", pubkey)

    def _render_meta_data(self, vm_name: str) -> str:
        template = (self._repo_root / CLOUD_INIT_META_DATA).read_text()
        return (
            template.replace("__INSTANCE_ID__", vm_name)
            .replace("__LOCAL_HOSTNAME__", vm_name)
        )

    def _public_key_path(self) -> Path:
        if self._ssh_key.suffix == ".pub":
            pub_path = self._ssh_key
        elif self._ssh_key.suffix:
            pub_path = self._ssh_key.with_suffix(f"{self._ssh_key.suffix}.pub")
        else:
            pub_path = self._ssh_key.with_name(f"{self._ssh_key.name}.pub")

        if not pub_path.exists():
            raise FileNotFoundError(f"SSH public key not found: {pub_path}")

        return pub_path
