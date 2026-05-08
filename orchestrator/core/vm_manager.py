"""
orchestrator/core/vm_manager.py

Lab-level VM operations. Knows when and why to start/stop/snapshot VMs.
Delegates all libvirt mechanics to Provider. Never calls libvirt directly.

Lifecycle contract:
  - Callers are responsible for starting a VM before calling wait_ssh_ready.
  - wait_ssh_ready only probes connectivity; it never starts the VM.
  - open_ssh assumes the VM is already running.
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

    # --- infra (delegated to provider) -----------------------------------

    def ensure_network(self) -> None:
        self._provider.ensure_network()

    def ensure_pool(self) -> None:
        self._provider.ensure_pool()

    def vm_exists(self, vm_name: str) -> bool:
        return self._provider.vm_exists(vm_name)

    def ensure_base_image(self, profile: dict[str, Any]) -> Path:
        return ensure_image(profile, self._images_dir)

    # --- VM lifecycle (delegated to provider) ----------------------------

    def create_vm(
        self,
        role: str,
        distro_id: str,
        profile: dict[str, Any],
        role_cfg: dict[str, Any],
        base_image: Path,
    ) -> str:
        """
        Create a VM with a fresh cloud-init seed.
        Skips silently if the VM already exists.
        Returns the VM name.
        """
        vm_name = f"{role}-{distro_id}"
        if self._provider.vm_exists(vm_name):
            print(f"[i] VM '{vm_name}' already exists, skipping creation")
            return vm_name
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

    def get_disk_path(self, vm_name: str) -> str:
        """Used by Dumper for disk acquisition."""
        return self._provider.get_disk_path(vm_name)

    # --- SSH readiness and connectivity ----------------------------------

    def wait_ssh_ready(
        self,
        vm_name: str,
        timeout: int = 180,
        reason: str = "",
    ) -> str:
        """
        Poll until SSH accepts connections on vm_name.
        Does NOT start the VM — the caller must do that first.
        Returns the IP once ready.
        """
        ip = self._provider.get_vm_ip(vm_name)
        label = f" [{reason}]" if reason else ""
        print(f"[*] Waiting for SSH on {vm_name} ({ip}){label}...")

        deadline = time.time() + timeout
        last_error = ""
        while time.time() < deadline:
            try:
                with SSHClient(ip, self._ssh_user, str(self._ssh_key)) as ssh:
                    ssh.run_checked("true")
                print(f"[+] SSH ready on {vm_name} ({ip}){label}")
                return ip
            except Exception as exc:
                last_error = str(exc)
                time.sleep(5)

        raise RuntimeError(
            f"SSH not ready on '{vm_name}' after {timeout}s: {last_error}"
        )

    def open_ssh(self, vm_name: str) -> SSHClient:
        """
        Return a connected SSHClient for a running VM.
        Caller owns the lifecycle of the returned client.
        VM must already be running.
        """
        ip = self._provider.get_vm_ip(vm_name)
        client = SSHClient(ip, self._ssh_user, str(self._ssh_key))
        client.connect()
        return client

    # --- provisioning ----------------------------------------------------

    def run_playbook_on_vm(
        self,
        vm_name: str,
        playbook: Path,
        extra_vars: dict[str, str] | None = None,
        reason: str = "",
    ) -> str:
        """
        Wait for SSH, then run an Ansible playbook.
        VM must already be running before calling this.
        Returns the IP used.
        """
        ip = self.wait_ssh_ready(vm_name, reason=reason)
        self._run_playbook(ip, playbook, extra_vars=extra_vars)
        return ip

    # --- lab lifecycle ---------------------------------------------------

    def prepare_lab(
        self,
        distro_id: str,
        profile: dict[str, Any],
        role_cfg: dict[str, Any],
    ) -> str:
        """
        One-time setup for a lab VM:
          1. Download and verify base image
          2. Create VM (skips if already exists)
          3. Start VM
          4. Wait for SSH
          5. Run baseline playbook and snapshot (skips if snapshot exists)

        Returns the VM name.
        """
        vm_name = f"lab-{distro_id}"
        base_image = ensure_image(profile, self._images_dir)
        self.create_vm(
            role="lab",
            distro_id=distro_id,
            profile=profile,
            role_cfg=role_cfg,
            base_image=base_image,
        )
        self._provider.start_vm(vm_name)
        ip = self.wait_ssh_ready(vm_name, reason="initial boot")

        if not self._provider.snapshot_exists(vm_name, BASELINE_SNAPSHOT):
            playbook = self._repo_root / LAB_BASELINE_PLAYBOOK
            self._run_playbook(ip, playbook, reason="baseline provisioning")
            self._provider.create_snapshot(vm_name, BASELINE_SNAPSHOT)
        else:
            print(f"[i] Snapshot '{BASELINE_SNAPSHOT}' already on '{vm_name}'")

        return vm_name

    def revert_to_baseline(self, distro_id: str) -> str:
        """
        Revert the lab VM to the baseline snapshot.
        Called before every experiment. Does NOT start the VM —
        the snapshot revert leaves it in the saved state (typically off).
        Caller must call start_vm + wait_ssh_ready after this.
        Returns the VM name.
        """
        vm_name = f"lab-{distro_id}"
        if not self._provider.snapshot_exists(vm_name, BASELINE_SNAPSHOT):
            raise RuntimeError(
                f"No baseline snapshot on '{vm_name}'. Run 'prepare' first."
            )
        self._provider.revert_snapshot(vm_name, BASELINE_SNAPSHOT)
        return vm_name

    def destroy_lab(self, distro_id: str) -> None:
        """Remove the lab VM and all its storage."""
        self._provider.destroy_vm(f"lab-{distro_id}")

    # --- plumbing --------------------------------------------------------

    def close(self) -> None:
        self._provider.close()

    # --- private helpers -------------------------------------------------

    def _run_playbook(
        self,
        ip: str,
        playbook: Path,
        extra_vars: dict[str, str] | None = None,
        reason: str = "",
    ) -> None:
        label = f" [{reason}]" if reason else ""
        print(f"[*] Running playbook {playbook.name} on {ip}{label}...")
        cmd = [
            "ansible-playbook",
            "-i", f"{ip},",
            "-u", self._ssh_user,
            "--private-key", str(self._ssh_key),
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
                ["cloud-localds", str(seed_path), str(user_path), str(meta_path)],
                capture_output=True,
                text=True,
            )
        if result.returncode != 0:
            raise RuntimeError(f"cloud-localds failed:\n{result.stderr.strip()}")
        return seed_path

    def _render_user_data(self) -> str:
        pubkey = self._public_key_path().read_text().strip()
        template = (self._repo_root / CLOUD_INIT_USER_DATA).read_text()
        return template.replace("__SSH_PUBLIC_KEY__", pubkey)

    def _render_meta_data(self, vm_name: str) -> str:
        template = (self._repo_root / CLOUD_INIT_META_DATA).read_text()
        return (
            template
            .replace("__INSTANCE_ID__", vm_name)
            .replace("__LOCAL_HOSTNAME__", vm_name)
        )

    def _public_key_path(self) -> Path:
        key = self._ssh_key
        if key.suffix == ".pub":
            pub = key
        elif key.suffix:
            pub = key.with_suffix(f"{key.suffix}.pub")
        else:
            pub = key.with_name(f"{key.name}.pub")
        if not pub.exists():
            raise FileNotFoundError(f"SSH public key not found: {pub}")
        return pub