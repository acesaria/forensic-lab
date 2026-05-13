"""
orchestrator/core/vm_manager.py

Lab-level VM operations. Knows when and why to start/stop/snapshot VMs.
Delegates all libvirt mechanics to Provider. Never calls libvirt directly.

Lifecycle contract:
  - Callers are responsible for starting a VM before calling wait_ssh_ready.
  - wait_ssh_ready only probes connectivity; it never starts the VM.
  - open_ssh assumes the VM is already running and returns an owned SSHClient.
"""

import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from infra.image_store import ensure_image
from infra.provider import Provider
from orchestrator.core.config import (
    BASELINE_SNAPSHOT,
    CLOUD_INIT_USER_DATA,
    LAB_BASELINE_PLAYBOOK,
    LAB_USER,
)
from orchestrator.core.ssh_client import SSHClient

_log = logging.getLogger(__name__)


class VMManager:
    def __init__(
        self,
        provider: Provider,
        images_path: Path,
        ssh_key: str,
        ssh_pub_key: str,
        repo_root: Path,
    ) -> None:
        self._provider = provider
        self._images_dir = images_path.expanduser().resolve()
        self._ssh_key = Path(ssh_key).expanduser()
        self._ssh_pubkey_text = Path(ssh_pub_key).expanduser().read_text().strip()
        self._repo_root = repo_root

    # --- infra setup (one-time, delegated to provider) -------------------

    def ensure_isolated_network(self) -> None:
        self._provider.ensure_isolated_network()

    def ensure_storage_pool(self) -> None:
        self._provider.ensure_storage_pool()

    # --- image and VM creation -------------------------------------------

    def ensure_base_image(self, profile: dict[str, Any]) -> Path:
        img_cfg = profile["image"]
        url = img_cfg["url"]
        filename = img_cfg.get("filename") or url.rstrip("/").split("/")[-1]
        dest = self._images_dir / filename
        distro_id = profile.get("distro_id", "unknown")
        try:
            return ensure_image(profile, self._images_dir)
        except OSError as exc:
            if dest.exists():
                dest.unlink()
            raise RuntimeError(
                f"download: failed to fetch image for '{distro_id}': {exc}\n"
                "Check host network connectivity."
            ) from exc

    def vm_exists(self, vm_name: str) -> bool:
        return self._provider.vm_exists(vm_name)

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
            _log.info("[i] VM '%s' already exists, skipping creation", vm_name)
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

    # --- VM lifecycle (delegated to provider) ----------------------------

    def start_vm(self, vm_name: str) -> None:
        self._provider.start_vm(vm_name)

    def shutdown_vm(self, vm_name: str, timeout: int = 90) -> None:
        self._provider.shutdown_vm(vm_name, timeout=timeout)

    def destroy_vm(self, vm_name: str) -> None:
        self._provider.destroy_vm(vm_name)

    # --- VM access and introspection -------------------------------------

    def get_disk_path(self, vm_name: str) -> str:
        """Return the host-side disk path for vm_name. Used by Dumper."""
        return self._provider.get_disk_path(vm_name)

    def wait_ssh_ready(
        self,
        vm_name: str,
        timeout: int = 180,
        reason: str = "",
    ) -> str:
        """
        Poll until SSH accepts connections on vm_name.
        Does NOT start the VM -- the caller must do that first.
        Returns the IP once ready.
        """
        ip = self._provider.get_vm_ip(vm_name)
        label = f" [{reason}]" if (reason and _log.isEnabledFor(logging.DEBUG)) else ""
        _log.info("[*] Waiting for SSH on %s (%s)%s...", vm_name, ip, label)

        deadline = time.time() + timeout
        last_error = ""
        while time.time() < deadline:
            try:
                with SSHClient(ip, LAB_USER, str(self._ssh_key)) as ssh:
                    ssh.run_checked("true")
                _log.info("[+] SSH ready on %s (%s)%s", vm_name, ip, label)
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
        client = SSHClient(ip, LAB_USER, str(self._ssh_key))
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
        Wait for SSH, then run an Ansible playbook against vm_name.
        VM must already be running before calling this.
        Returns the IP used.
        """
        ip = self.wait_ssh_ready(vm_name, reason=reason)
        self._run_playbook(ip, playbook, extra_vars=extra_vars, reason=reason)
        return ip

    # --- lab lifecycle (experiment-time operations) ----------------------

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
        base_image = self.ensure_base_image(profile)
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
            _log.info("[*] Shutting down %s before snapshot...", vm_name)
            self._provider.shutdown_vm(vm_name)
            self._provider.create_snapshot(vm_name, BASELINE_SNAPSHOT)
        else:
            _log.info(
                "[i] Snapshot '%s' already on '%s'",
                BASELINE_SNAPSHOT,
                vm_name,
            )

        return vm_name

    def revert_to_baseline(self, distro_id: str) -> str:
        """
        Revert the lab VM to the baseline snapshot.
        Shuts the VM down first if it is running -- libvirt requires the
        domain to be off for disk-only snapshot reverts.
        Does NOT start the VM. Caller must call start_vm + wait_ssh_ready.
        Returns the VM name.
        """
        vm_name = f"lab-{distro_id}"
        if not self._provider.snapshot_exists(vm_name, BASELINE_SNAPSHOT):
            raise RuntimeError(
                f"No baseline snapshot on '{vm_name}'. Run 'prepare' first."
            )
        if self._provider.is_running(vm_name):
            _log.info("[*] Shutting down '%s' before snapshot revert...", vm_name)
            self._provider.shutdown_vm(vm_name)
        self._provider.revert_snapshot(vm_name, BASELINE_SNAPSHOT)
        return vm_name

    # --- teardown --------------------------------------------------------

    def destroy_lab(self, distro_id: str) -> None:
        """Remove the lab VM and all its storage."""
        self._provider.destroy_vm(f"lab-{distro_id}")

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
        _log.debug("[*] Running playbook %s on %s%s...", playbook.name, ip, label)
        cmd = [
            "ansible-playbook",
            "-i",
            f"{ip},",
            "-u",
            LAB_USER,
            "--private-key",
            str(self._ssh_key),
            "--ssh-common-args",
            "-o StrictHostKeyChecking=no",
            str(playbook),
        ]
        if extra_vars:
            for k, v in extra_vars.items():
                cmd.extend(["-e", f"{k}={v}"])
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            raise RuntimeError(
                f"Ansible playbook failed (rc={result.returncode}): {playbook}\n"
                f"{stdout}\n{stderr}"
            )
        if _log.isEnabledFor(logging.DEBUG):
            _log.debug("%s", result.stdout or "")
            _log.debug("[+] Playbook %s done", playbook.name)

    def _create_cloud_init_seed(self, vm_name: str) -> Path:
        pool_path = self._provider.pool_path()
        seed_path = pool_path / f"{vm_name}-seed.iso"
        if seed_path.exists():
            seed_path.unlink()

        with tempfile.TemporaryDirectory() as tmp:
            meta_path = Path(tmp) / "meta-data"
            user_path = Path(tmp) / "user-data"
            meta_path.write_text(f"instance-id: {vm_name}\nlocal-hostname: {vm_name}\n")
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
        template = (self._repo_root / CLOUD_INIT_USER_DATA).read_text()
        return template.replace("__SSH_PUBLIC_KEY__", self._ssh_pubkey_text)
