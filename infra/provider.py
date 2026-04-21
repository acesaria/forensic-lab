"""
infra/provider.py

Direct interface to libvirt. Handles all VM lifecycle operations:
network, storage pool, VM creation/destruction, snapshots, and IP resolution.

All callers pass a config dict loaded from config.yaml. This module
knows nothing about experiments — it just manages VMs as resources.
"""

import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

import libvirt


# ---------------------------------------------------------------------------
# Inline XML definitions
# ---------------------------------------------------------------------------

_ISOLATED_NETWORK_XML = """
<network>
  <name>forensics-isolated</name>
  <bridge name="virbr-forensics" stp="on" delay="0"/>
  <ip address="192.168.100.1" netmask="255.255.255.0">
    <dhcp>
      <range start="192.168.100.10" end="192.168.100.50"/>
    </dhcp>
  </ip>
</network>
"""


def _pool_xml(name: str, path: str) -> str:
    return f"""
<pool type="dir">
  <name>{name}</name>
  <target>
    <path>{path}</path>
  </target>
</pool>
"""


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------

class Provider:
    """
    Manages the libvirt infrastructure for the forensic lab.

    Instantiate once per session with the parsed config.yaml dict.
    """

    def __init__(self, cfg: dict[str, Any], repo_root: Path) -> None:
        lab = cfg["lab"]
        self._uri: str = lab["libvirt_uri"]
        self._pool_name: str = lab["pool_name"]
        self._pool_path: Path = Path(lab["pool_path"]).expanduser().resolve()
        self._ssh_key_path: Path = Path(lab["ssh_key"]).expanduser().resolve()
        auth_path = lab.get("ssh_authorized_keys_path")
        self._ssh_authorized_keys_path: Path = (
            Path(auth_path).expanduser().resolve()
            if auth_path
            else Path(f"{self._ssh_key_path}.pub")
        )
        self._net_isolated: str = lab["networks"]["isolated"]
        self._net_internet: str = lab["networks"]["internet"]
        self._cloud_init_dir: Path = repo_root / "infra" / "cloud-init"
        self._conn: Optional[libvirt.virConnect] = None

    # --- connection --------------------------------------------------------

    def _connect(self) -> libvirt.virConnect:
        if self._conn is None or self._conn.isAlive() == 0:
            self._conn = libvirt.open(self._uri)
            if self._conn is None:
                raise RuntimeError(f"Failed to connect to libvirt: {self._uri}")
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # --- network -----------------------------------------------------------

    def ensure_network(self) -> None:
        """Create and start forensics-isolated network if not present."""
        conn = self._connect()
        try:
            net = conn.networkLookupByName(self._net_isolated)
            if not net.isActive():
                net.create()
            print(f"[i] Network '{self._net_isolated}' already present")
            return
        except libvirt.libvirtError:
            pass

        print(f"[*] Defining network '{self._net_isolated}'...")
        net = conn.networkDefineXML(_ISOLATED_NETWORK_XML)
        net.setAutostart(1)
        net.create()
        print(f"[+] Network '{self._net_isolated}' created")

    # --- storage pool ------------------------------------------------------

    def ensure_pool(self) -> None:
        """Create and start the storage pool if not present."""
        conn = self._connect()
        self._pool_path.mkdir(parents=True, exist_ok=True)

        try:
            pool = conn.storagePoolLookupByName(self._pool_name)
            if not pool.isActive():
                pool.create()
            print(f"[i] Pool '{self._pool_name}' already present")
            return
        except libvirt.libvirtError:
            pass

        print(f"[*] Defining pool '{self._pool_name}' at {self._pool_path}...")
        pool = conn.storagePoolDefineXML(
            _pool_xml(self._pool_name, str(self._pool_path))
        )
        pool.setAutostart(1)
        pool.build(0)
        pool.create()
        print(f"[+] Pool '{self._pool_name}' created")

    # --- VM creation -------------------------------------------------------

    def create_vm(
        self,
        role: str,
        distro_id: str,
        profile: dict[str, Any],
        role_cfg: dict[str, Any],
        base_image: Path,
    ) -> str:
        """
        Create a VM from a role + distro profile.

        Returns the domain name.
        Skips silently if the domain already exists.
        """
        vm_name = f"{role}-{distro_id}"
        conn = self._connect()

        try:
            conn.lookupByName(vm_name)
            print(f"[i] VM '{vm_name}' already exists, skipping")
            return vm_name
        except libvirt.libvirtError:
            pass

        disk_path = self._pool_path / f"{vm_name}.qcow2"
        seed_path = self._pool_path / f"{vm_name}-seed.iso"

        # overlay on top of the immutable base image
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2",
             "-b", str(base_image), "-F", "qcow2",
             str(disk_path), role_cfg["disk_size"]],
            check=True, capture_output=True, text=True,
        )

        # cloud-init seed ISO (user-data + meta-data, no network-config)
        user_data = self._cloud_init_dir / role / "user-data"
        with tempfile.TemporaryDirectory() as tmp:
            meta_data = Path(tmp) / "meta-data"
            meta_data.write_text(
                f"instance-id: {vm_name}\nlocal-hostname: {vm_name}\n"
            )
            rendered_user_data = Path(tmp) / "user-data"
            rendered_user_data.write_text(self._render_user_data(role))
            subprocess.run(
                ["cloud-localds", str(seed_path),
                 str(rendered_user_data), str(meta_data)],
                check=True, capture_output=True, text=True,
            )

        network = role_cfg.get("network",
            self._net_isolated if role == "lab" else self._net_internet
        )
        os_variant = profile.get("os_variant") or "generic"

        print(f"[*] Creating VM '{vm_name}'...")
        subprocess.run(
            [
                "virt-install",
                "--name",       vm_name,
                "--memory",     str(role_cfg["ram_mb"]),
                "--vcpus",      str(role_cfg["vcpus"]),
                "--disk",       f"path={disk_path},format=qcow2,bus=virtio",
                "--disk",       f"path={seed_path},format=raw,bus=virtio,readonly=on",
                "--network",    f"network={network},model=virtio",
                "--os-variant", os_variant,
                "--import",
                "--graphics",   "none",
                "--console",    "pty,target_type=virtio",
                "--noautoconsole",
            ],
            check=True, capture_output=True, text=True,
        )
        print(f"[+] VM '{vm_name}' created")
        return vm_name

    # --- VM destruction ----------------------------------------------------

    def destroy_vm(self, vm_name: str) -> None:
        """Stop, undefine and remove all storage for a VM."""
        conn = self._connect()
        try:
            dom = conn.lookupByName(vm_name)
        except libvirt.libvirtError:
            print(f"[i] VM '{vm_name}' not found, nothing to destroy")
            return

        state, _ = dom.state()
        if state == libvirt.VIR_DOMAIN_RUNNING:
            dom.destroy()  # force off

        dom.undefineWithSnapshots()
        print(f"[+] VM '{vm_name}' undefined")

        for suffix in (".qcow2", "-seed.iso"):
            p = self._pool_path / f"{vm_name}{suffix}"
            if p.exists():
                p.unlink()
                print(f"[+] Removed {p.name}")

    # --- start / stop ------------------------------------------------------

    def start_vm(self, vm_name: str) -> None:
        conn = self._connect()
        dom = conn.lookupByName(vm_name)
        state, _ = dom.state()
        if state != libvirt.VIR_DOMAIN_RUNNING:
            dom.create()
            print(f"[+] VM '{vm_name}' started")

    def shutdown_vm(self, vm_name: str, timeout: int = 90) -> None:
        """Graceful shutdown with fallback to force-off."""
        conn = self._connect()
        dom = conn.lookupByName(vm_name)
        state, _ = dom.state()
        if state != libvirt.VIR_DOMAIN_RUNNING:
            return

        dom.shutdown()
        deadline = time.time() + timeout
        while time.time() < deadline:
            state, _ = dom.state()
            if state == libvirt.VIR_DOMAIN_SHUTOFF:
                return
            time.sleep(2)

        print(f"[!] Graceful shutdown timed out, forcing off '{vm_name}'")
        dom.destroy()

    # --- IP resolution -----------------------------------------------------

    def get_vm_ip(self, vm_name: str, timeout: int = 120) -> str:
        """
        Poll until the VM acquires a DHCP lease and return its IP.
        Raises RuntimeError on timeout.
        """
        conn = self._connect()
        dom = conn.lookupByName(vm_name)
        deadline = time.time() + timeout

        print(f"[*] Waiting for IP on '{vm_name}'...")
        while time.time() < deadline:
            try:
                ifaces = dom.interfaceAddresses(
                    libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE
                )
                for iface in ifaces.values():
                    for addr in iface.get("addrs", []):
                        if addr["type"] == libvirt.VIR_IP_ADDR_TYPE_IPV4:
                            ip = addr["addr"]
                            print(f"[+] {vm_name}: {ip}")
                            return ip
            except libvirt.libvirtError:
                pass
            time.sleep(5)

        raise RuntimeError(
            f"Timed out waiting for IP on '{vm_name}' after {timeout}s"
        )

    # --- snapshots ---------------------------------------------------------

    def snapshot_exists(self, vm_name: str, snapshot_name: str) -> bool:
        conn = self._connect()
        try:
            dom = conn.lookupByName(vm_name)
            dom.snapshotLookupByName(snapshot_name)
            return True
        except libvirt.libvirtError:
            return False

    def create_snapshot(self, vm_name: str, snapshot_name: str) -> None:
        conn = self._connect()
        dom = conn.lookupByName(vm_name)
        xml = f"""
        <domainsnapshot>
          <name>{snapshot_name}</name>
          <description>Baseline snapshot — clean state before experiments</description>
        </domainsnapshot>
        """
        dom.snapshotCreateXML(xml, 0)
        print(f"[+] Snapshot '{snapshot_name}' created on '{vm_name}'")

    def revert_snapshot(self, vm_name: str, snapshot_name: str) -> None:
        conn = self._connect()
        dom = conn.lookupByName(vm_name)
        snap = dom.snapshotLookupByName(snapshot_name)
        dom.revertToSnapshot(snap)
        print(f"[+] '{vm_name}' reverted to snapshot '{snapshot_name}'")

    # --- disk info (used by dumper) ----------------------------------------

    def get_disk_path(self, vm_name: str) -> str:
        """Return the path of the primary qcow2 disk for a domain."""
        conn = self._connect()
        dom = conn.lookupByName(vm_name)
        xml = dom.XMLDesc()
        # simple parse: find first <source file='...'> inside a <disk> block
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
        for disk in root.findall(".//disk[@type='file'][@device='disk']"):
            src = disk.find("source")
            if src is not None:
                return src.attrib["file"]
        raise RuntimeError(f"Could not find disk path for '{vm_name}'")

    def _render_user_data(self, role: str) -> str:
        user_data_path = self._cloud_init_dir / role / "user-data"
        data = user_data_path.read_text()
        if not self._ssh_authorized_keys_path.exists():
            raise FileNotFoundError(
                f"SSH authorized key not found: {self._ssh_authorized_keys_path}"
            )
        pubkey = self._ssh_authorized_keys_path.read_text().strip()
        rendered_lines: list[str] = []
        replaced = False
        for line in data.splitlines():
            stripped = line.strip()
            if stripped.startswith("- ssh-") and not replaced:
                indent = line.split("-")[0]
                rendered_lines.append(f"{indent}- {pubkey}")
                replaced = True
                continue
            rendered_lines.append(line)
        return "\n".join(rendered_lines) + "\n"
