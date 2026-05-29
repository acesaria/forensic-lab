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
from infra.provider import Provider, remove_file_if_exists
from orchestrator.core.config import (
    BASELINE_SNAPSHOT,
    CLOUD_INIT_NETWORK_CONFIG,
    CLOUD_INIT_USER_DATA,
    LAB_BASELINE_PLAYBOOK,
    LAB_VM_PREFIX,
    LAB_USER,
)
from orchestrator.core import console
from orchestrator.core.paths import ProjectPaths
from orchestrator.core.ssh_client import SSHClient

_log = logging.getLogger(__name__)


class VMManager:
    def __init__(
        self,
        provider: Provider,
        paths: ProjectPaths,
    ) -> None:
        self._provider = provider
        self._paths = paths
        self._images_dir = paths.images_dir
        self._ssh_key = paths.ssh_key
        self._ssh_pubkey_text = paths.ssh_pub_key.read_text().strip()
        self._repo_root = paths.repo_root

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
            console.info(f"VM '{vm_name}' already exists; skipping creation")
            return vm_name
        seed_path = self._create_cloud_init_seed(vm_name, role)
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

    def shutdown_vm(self, vm_name: str, timeout: int = 60) -> None:
        self._provider.shutdown_vm(vm_name, timeout=timeout)

    def suspend_vm(self, vm_name: str) -> None:
        self._provider.suspend_vm(vm_name)

    def resume_vm(self, vm_name: str) -> None:
        self._provider.resume_vm(vm_name)

    def prepare_disk_acquisition_external(
        self, vm_name: str, overlay_path: Path
    ) -> None:
        # Take a live external disk snapshot so guest writes divert to the
        # overlay and the base qcow2 becomes safe for host-side acquisition.
        # Guest stays running.
        self._provider.create_external_disk_snapshot(vm_name, overlay_path)

    def finalize_disk_acquisition_external(
        self, vm_name: str, overlay_path: Path
    ) -> None:
        # Pivot the running guest back to the base chain, then drop the
        # overlay file. blockcommit --pivot removes the overlay from the
        # chain but typically leaves the file on disk.
        self._provider.commit_external_disk_snapshot(vm_name)
        remove_file_if_exists(overlay_path)

    def destroy_vm(self, vm_name: str) -> None:
        self._provider.destroy_vm(vm_name)

    # --- VM access and introspection -------------------------------------

    def get_disk_path(self, vm_name: str) -> Path:
        """Return the host-side disk path for vm_name. Used by Dumper."""
        return self._provider.get_disk_path(vm_name)

    def wait_ssh_ready(
        self,
        vm_name: str,
        timeout: int = 240,
        reason: str = "",
    ) -> str:
        """
        Poll until SSH accepts connections on vm_name.
        Does NOT start the VM -- the caller must do that first.
        Returns the IP once ready.
        """
        ip = self._provider.get_vm_ip(vm_name)
        label = f" [{reason}]" if (reason and _log.isEnabledFor(logging.DEBUG)) else ""
        console.step(f"waiting for SSH on {vm_name} ({ip}){label}...")

        deadline = time.time() + timeout
        last_error = ""
        while time.time() < deadline:
            try:
                with SSHClient(ip, LAB_USER, self._ssh_key) as ssh:
                    ssh.run_checked("true")
                console.ok(f"SSH ready on {vm_name} ({ip}){label}")
                return ip
            except Exception as exc:
                last_error = str(exc)
                time.sleep(5)

        raise RuntimeError(
            f"SSH not ready on '{vm_name}' after {timeout}s: {last_error}"
        )

    def internet_on(self, vm_name: str, wait: int = 5) -> None:
        """Bring the NAT NIC link up; sleep briefly to let DHCP settle."""
        self._provider.set_nat_link(vm_name, up=True)
        console.info("NAT NIC link up")
        time.sleep(wait)

    def internet_off(self, vm_name: str, quiet: bool = False) -> None:
        """Bring the NAT NIC link down. quiet=True suppresses the log line --
        used by the orchestrator's safety-net so we don't double-print after
        the scenario already cleaned up."""
        self._provider.set_nat_link(vm_name, up=False)
        if not quiet:
            console.info("NAT NIC link down")

    def open_ssh(self, vm_name: str) -> SSHClient:
        """
        Return a connected SSHClient for a running VM.
        Caller owns the lifecycle of the returned client.
        VM must already be running.
        """
        ip = self._provider.get_vm_ip(vm_name)
        client = SSHClient(ip, LAB_USER, self._ssh_key)
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
        VM must already be running before calling this. Returns the IP.
        Single entry point for playbook execution: ansible's own connect
        retries are not generous enough for a freshly-booted VM, so the
        wait_ssh_ready probe up-front is the only one we do.
        """
        ip = self.wait_ssh_ready(vm_name, reason=reason)
        label = f" [{reason}]" if reason else ""
        _log.debug("running playbook %s on %s%s...", playbook.name, ip, label)
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
            raise RuntimeError(
                f"Ansible playbook failed (rc={result.returncode}): {playbook}\n"
                f"{result.stdout or ''}\n{result.stderr or ''}"
            )
        if _log.isEnabledFor(logging.DEBUG):
            _log.debug("%s", result.stdout or "")
            _log.debug("playbook %s done", playbook.name)
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
          4. Run baseline playbook (waits for SSH internally) and snapshot

        Returns the VM name.
        """
        vm_name = f"{LAB_VM_PREFIX}-{distro_id}"
        base_image = self.ensure_base_image(profile)
        self.create_vm(
            role="lab",
            distro_id=distro_id,
            profile=profile,
            role_cfg=role_cfg,
            base_image=base_image,
        )
        self._provider.start_vm(vm_name)

        playbook = self._repo_root / LAB_BASELINE_PLAYBOOK
        self.internet_on(vm_name)
        try:
            self.run_playbook_on_vm(
                vm_name, playbook, reason="baseline provisioning"
            )
        finally:
            self.internet_off(vm_name)
        console.step(f"shutting down {vm_name} before snapshot...")
        self._provider.shutdown_vm(vm_name)
        self._provider.create_snapshot(vm_name, BASELINE_SNAPSHOT)
        return vm_name

    def revert_to_baseline(self, distro_id: str) -> str:
        """
        Revert the lab VM to the baseline snapshot.
        Shuts the VM down first if it is running -- libvirt requires the
        domain to be off for disk-only snapshot reverts.
        Does NOT start the VM. Caller must call start_vm + wait_ssh_ready.
        Returns the VM name.
        """
        vm_name = f"{LAB_VM_PREFIX}-{distro_id}"
        if not self._provider.snapshot_exists(vm_name, BASELINE_SNAPSHOT):
            raise RuntimeError(
                f"No baseline snapshot on '{vm_name}'. Run 'setup' first."
            )
        if self._provider.is_running(vm_name):
            console.step(f"shutting down '{vm_name}' before snapshot revert...")
            self._provider.shutdown_vm(vm_name)
        self._provider.revert_snapshot(vm_name, BASELINE_SNAPSHOT)
        return vm_name

    # --- teardown --------------------------------------------------------

    def destroy_lab(self, distro_id: str) -> None:
        """Remove the lab VM and all its storage."""
        self._provider.destroy_vm(f"{LAB_VM_PREFIX}-{distro_id}")

    def close(self) -> None:
        self._provider.close()

    # --- private helpers -------------------------------------------------

    def _create_cloud_init_seed(self, vm_name: str, role: str) -> Path:
        pool_path = self._provider.pool_path()
        seed_path = pool_path / f"{vm_name}-seed.iso"
        if seed_path.exists():
            seed_path.unlink()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            meta_path = tmp_dir / "meta-data"
            user_path = tmp_dir / "user-data"
            meta_path.write_text(f"instance-id: {vm_name}\nlocal-hostname: {vm_name}\n")
            user_path.write_text(self._render_user_data())

            cmd = ["cloud-localds"]
            # Lab role gets a two-NIC explicit netplan so the isolated NIC's
            # DHCP default route + DNS are suppressed; otherwise apt would
            # sometimes route via the dead 192.168.100.1 gateway.
            if role == "lab":
                net_path = tmp_dir / "network-config"
                net_path.write_text(self._render_network_data())
                cmd.extend(["--network-config", str(net_path)])
            cmd.extend([str(seed_path), str(user_path), str(meta_path)])

            result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"cloud-localds failed:\n{result.stderr.strip()}")
        return seed_path

    def _render_user_data(self) -> str:
        template = (self._repo_root / CLOUD_INIT_USER_DATA).read_text()
        return template.replace("__SSH_PUBLIC_KEY__", self._ssh_pubkey_text)

    def _render_network_data(self) -> str:
        return (self._repo_root / CLOUD_INIT_NETWORK_CONFIG).read_text()
