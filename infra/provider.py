"""
infra/provider.py

Direct interface to libvirt. The "Provider contract" below lists every method
a future alternative provider (e.g. VMware, cloud API) must implement.

Provider contract
-----------------
Infra:
    pool_path() -> Path
    close() -> None
    ensure_isolated_network() -> None
    ensure_storage_pool() -> None

VM creation / destruction:
    create_vm(role, distro_id, profile, role_cfg, base_image, seed_path) -> str
    destroy_vm(vm_name) -> None

VM lifecycle:
    vm_exists(vm_name) -> bool
    start_vm(vm_name) -> None
    shutdown_vm(vm_name, timeout) -> None
    restart_vm(vm_name) -> None

Introspection:
    get_vm_ip(vm_name, timeout) -> str
    get_disk_path(vm_name) -> str

Snapshots (disk-only, taken while VM is shutoff):
    snapshot_exists(vm_name, snapshot_name) -> bool
    create_snapshot(vm_name, snapshot_name) -> None
    revert_snapshot(vm_name, snapshot_name) -> None

Notes:
- Snapshots are disk-only, always taken while the VM is shutoff.
  Callers shut down the VM before create_snapshot, and start it
  after revert_snapshot.
- start_vm is idempotent: no-op if already running.
- destroy_vm is idempotent: no-op if VM does not exist.
- close() must be called when the provider is no longer needed.
"""

import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, cast

import libvirt

# ---------------------------------------------------------------------------
# Infrastructure constants
# Adjust the address range here if it conflicts with your local network.
# ---------------------------------------------------------------------------

_ISOLATED_NETWORK_NAME = "forensics-isolated"

_ISOLATED_NETWORK_XML = f"""\
<network>
  <name>{_ISOLATED_NETWORK_NAME}</name>
  <bridge name="virbr-forensics" stp="on" delay="0"/>
  <ip address="192.168.100.1" netmask="255.255.255.0">
    <dhcp>
      <range start="192.168.100.10" end="192.168.100.99"/>
    </dhcp>
  </ip>
</network>"""


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class Provider:
    """
    Libvirt implementation of the Provider contract.
    Instantiate once per session. Knows nothing about experiments.
    """

    def __init__(
        self,
        libvirt_uri: str,
        pool_name: str,
        pool_path: Path,
    ) -> None:
        self._uri = libvirt_uri
        self._pool_name = pool_name
        self._pool_path = pool_path.expanduser().resolve()
        self._conn: libvirt.virConnect | None = None

    # --- public accessors ------------------------------------------------

    def pool_path(self) -> Path:
        return self._pool_path

    # --- connection ------------------------------------------------------

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

    # --- one-time infra --------------------------------------------------

    def ensure_isolated_network(self) -> None:
        """Create and autostart the isolated network if not already present."""
        conn = self._connect()
        try:
            net = conn.networkLookupByName(_ISOLATED_NETWORK_NAME)
            if not net.isActive():
                net.create()
            print(f"[i] Network '{_ISOLATED_NETWORK_NAME}' already present")
            return
        except libvirt.libvirtError:
            pass
        print(f"[*] Defining network '{_ISOLATED_NETWORK_NAME}'...")
        net = conn.networkDefineXML(_ISOLATED_NETWORK_XML)
        net.setAutostart(1)
        net.create()
        print(f"[+] Network '{_ISOLATED_NETWORK_NAME}' created")

    def ensure_storage_pool(self) -> None:
        """Create and autostart the storage pool if not already present."""
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
        pool = conn.storagePoolDefineXML(self._pool_xml())
        pool.setAutostart(1)
        pool.build(0)
        pool.create()
        print(f"[+] Pool '{self._pool_name}' created")

    def _pool_xml(self) -> str:
        # Pool name and path are instance-specific, so this cannot be a module constant.
        return f"""\
<pool type='dir'>
  <name>{self._pool_name}</name>
  <target>
    <path>{self._pool_path}</path>
  </target>
</pool>"""

    # --- VM existence and creation ---------------------------------------

    def vm_exists(self, vm_name: str) -> bool:
        conn = self._connect()
        try:
            conn.lookupByName(vm_name)
            return True
        except libvirt.libvirtError:
            return False

    def create_vm(
        self,
        role: str,
        distro_id: str,
        profile: dict[str, Any],
        role_cfg: dict[str, Any],
        base_image: Path,
        seed_path: Path | None = None,
    ) -> str:
        """Create a VM from a role + distro profile. Returns the domain name."""
        vm_name = f"{role}-{distro_id}"
        conn = self._connect()
        try:
            conn.lookupByName(vm_name)
            print(f"[i] VM '{vm_name}' already exists, skipping")
            return vm_name
        except libvirt.libvirtError:
            pass

        disk_path = self._pool_path / f"{vm_name}.qcow2"
        self._create_disk_overlay(base_image, disk_path, role_cfg["disk_size"])
        network = role_cfg.get("network")
        os_variant = profile.get("os_variant") or "generic"

        print(f"[*] Creating VM '{vm_name}'...")
        cmd = [
            "virt-install",
            "--name",
            vm_name,
            "--memory",
            str(role_cfg["ram_mb"]),
            "--vcpus",
            str(role_cfg["vcpus"]),
            "--disk",
            f"path={disk_path},format=qcow2,bus=virtio",
            "--network",
            f"network={network},model=virtio",
            "--os-variant",
            os_variant,
            "--import",
            "--graphics",
            "none",
            "--console",
            "pty,target_type=virtio",
            "--noautoconsole",
        ]
        if seed_path is not None:
            cmd.extend(
                ["--disk", f"path={seed_path},format=raw,bus=virtio,readonly=on"]
            )

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"virt-install failed:\n{result.stderr.strip()}")
        print(f"[+] VM '{vm_name}' created")
        return vm_name

    def _create_disk_overlay(
        self, base_image: Path, disk_path: Path, disk_size: str
    ) -> None:
        if disk_path.exists():
            disk_path.unlink()
        result = subprocess.run(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-b",
                str(base_image),
                "-F",
                "qcow2",
                str(disk_path),
                disk_size,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"qemu-img failed:\n{result.stderr.strip()}")

    # --- VM lifecycle ----------------------------------------------------

    def start_vm(self, vm_name: str) -> None:
        """Start a shutoff VM. No-op if already running."""
        conn = self._connect()
        dom = conn.lookupByName(vm_name)
        if dom.state()[0] != libvirt.VIR_DOMAIN_RUNNING:
            dom.create()
            print(f"[+] VM '{vm_name}' started")

    def shutdown_vm(self, vm_name: str, timeout: int = 90) -> None:
        """Graceful ACPI shutdown with force-off fallback."""
        conn = self._connect()
        dom = conn.lookupByName(vm_name)
        if dom.state()[0] != libvirt.VIR_DOMAIN_RUNNING:
            return
        dom.shutdown()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                state = conn.lookupByName(vm_name).state()[0]
            except libvirt.libvirtError:
                return  # domain disappeared: already off
            if state == libvirt.VIR_DOMAIN_SHUTOFF:
                print(f"[+] '{vm_name}' shut down gracefully")
                return
            time.sleep(2)
        print(f"[!] Graceful shutdown timed out, forcing off '{vm_name}'")
        conn.lookupByName(vm_name).destroy()

    def restart_vm(self, vm_name: str) -> None:
        """Force-off then cold-start. Guards against already-shutoff state."""
        conn = self._connect()
        dom = conn.lookupByName(vm_name)
        if dom.state()[0] == libvirt.VIR_DOMAIN_RUNNING:
            dom.destroy()
        dom.create()

    # --- VM destruction --------------------------------------------------

    def destroy_vm(self, vm_name: str) -> None:
        """Force-stop, undefine, and remove all storage. No-op if not found."""
        conn = self._connect()
        try:
            dom = conn.lookupByName(vm_name)
        except libvirt.libvirtError:
            print(f"[i] VM '{vm_name}' not found, nothing to destroy")
            return
        self._stop_domain_if_active(dom)
        self._undefine_domain(dom, vm_name)
        self._verify_domain_removed(conn, vm_name)
        self._remove_domain_artifacts(vm_name)

    def _stop_domain_if_active(self, dom: libvirt.virDomain) -> None:
        state, _ = dom.state()
        if state in (
            libvirt.VIR_DOMAIN_RUNNING,
            libvirt.VIR_DOMAIN_BLOCKED,
            libvirt.VIR_DOMAIN_PAUSED,
            libvirt.VIR_DOMAIN_PMSUSPENDED,
        ):
            dom.destroy()

    def _undefine_domain(self, dom: libvirt.virDomain, vm_name: str) -> None:
        flags = (
            getattr(libvirt, "VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA", 0)
            | getattr(libvirt, "VIR_DOMAIN_UNDEFINE_MANAGED_SAVE", 0)
            | getattr(libvirt, "VIR_DOMAIN_UNDEFINE_NVRAM", 0)
        )
        try:
            dom.undefineFlags(flags)
        except libvirt.libvirtError as exc:
            raise RuntimeError(f"Failed to undefine '{vm_name}': {exc}") from exc

    def _verify_domain_removed(self, conn: libvirt.virConnect, vm_name: str) -> None:
        try:
            conn.lookupByName(vm_name)
        except libvirt.libvirtError:
            print(f"[+] VM '{vm_name}' undefined")
        else:
            raise RuntimeError(
                f"VM '{vm_name}' still defined after destroy; manual cleanup required"
            )

    def _remove_domain_artifacts(self, vm_name: str) -> None:
        for suffix in (".qcow2", "-seed.iso"):
            p = self._pool_path / f"{vm_name}{suffix}"
            if p.exists():
                p.unlink()
                print(f"[+] Removed {p.name}")

    # --- introspection ---------------------------------------------------

    def get_vm_ip(self, vm_name: str, timeout: int = 120) -> str:
        """Poll DHCP leases until an IPv4 address appears for the VM."""
        conn = self._connect()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                dom = conn.lookupByName(vm_name)  # re-fetch avoids stale handle
                raw = dom.interfaceAddresses(
                    libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE, 0
                )
                ifaces: dict[str, dict[str, Any]] = (
                    cast(dict[str, dict[str, Any]], raw) or {}
                )
                for iface in ifaces.values():
                    for addr in iface.get("addrs", []):
                        if addr.get("type") == libvirt.VIR_IP_ADDR_TYPE_IPV4:
                            return addr["addr"]
            except libvirt.libvirtError:
                pass
            time.sleep(5)
        raise RuntimeError(f"Timed out waiting for IP on '{vm_name}' after {timeout}s")

    def get_disk_path(self, vm_name: str) -> str:
        """Return the primary qcow2 disk path for a domain."""
        conn = self._connect()
        dom = conn.lookupByName(vm_name)
        root = ET.fromstring(dom.XMLDesc())
        for disk in root.findall(".//disk[@type='file'][@device='disk']"):
            src = disk.find("source")
            if src is not None:
                return src.attrib["file"]
        raise RuntimeError(f"Could not find disk path for '{vm_name}'")

    # --- snapshots -------------------------------------------------------

    def snapshot_exists(self, vm_name: str, snapshot_name: str) -> bool:
        conn = self._connect()
        try:
            dom = conn.lookupByName(vm_name)
            dom.snapshotLookupByName(snapshot_name)
            return True
        except libvirt.libvirtError:
            return False

    def create_snapshot(self, vm_name: str, snapshot_name: str) -> None:
        """Create a disk-only snapshot. VM must be shutoff before calling this."""
        conn = self._connect()
        dom = conn.lookupByName(vm_name)
        xml = f"""\
<domainsnapshot>
  <name>{snapshot_name}</name>
  <description>Baseline snapshot - clean state before experiments</description>
</domainsnapshot>"""
        # Flag 0: disk-only when domain is shutoff, which is required by our workflow.
        dom.snapshotCreateXML(xml, 0)
        print(f"[+] Snapshot '{snapshot_name}' created on '{vm_name}'")

    def revert_snapshot(self, vm_name: str, snapshot_name: str) -> None:
        """Revert to snapshot. Leaves VM shutoff - caller must start it."""
        conn = self._connect()
        dom = conn.lookupByName(vm_name)
        snap = dom.snapshotLookupByName(snapshot_name)
        dom.revertToSnapshot(snap)
        print(f"[+] '{vm_name}' reverted to '{snapshot_name}'")