"""
infra/provider.py

Direct interface to libvirt. Handles all VM lifecycle operations:
network, storage pool, VM creation/destruction, snapshots, and IP resolution.

This module knows nothing about experiments — it just manages VMs
as resources.
"""

import subprocess
import time
from pathlib import Path
from typing import Any

import xml.etree.ElementTree as ET

import libvirt


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------

class Provider:
    """
    Manages the libvirt infrastructure for the forensic lab.

    Instantiate once per session with explicit configuration primitives.
    """
    def __init__(self, libvirt_uri: str, pool_name: str, pool_path: Path, infra_dir: Path) -> None:
        self._uri = libvirt_uri
        self._pool_name = pool_name
        self._pool_path = pool_path.expanduser().resolve()
        self._infra_dir = infra_dir
        self._network_xml = self._infra_dir / "forensics-isolated.xml"
        self._pool_xml = self._infra_dir / "pool.xml"
        self._net_isolated = self._read_network_name(self._network_xml)
        self._net_internet = "default"
        self._conn = None

    @staticmethod
    def _read_network_name(network_xml: Path) -> str:
        try:
            root = ET.fromstring(network_xml.read_text())
        except (ET.ParseError, OSError):
            return "forensics-isolated"

        name = root.findtext("name")
        return name.strip() if isinstance(name, str) and name.strip() else "forensics-isolated"

    def pool_path(self) -> Path:
        return self._pool_path

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
        net = conn.networkDefineXML(self._network_xml.read_text())
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
        pool_xml = self._render_template(
            self._pool_xml,
            {
                "__POOL_NAME__": self._pool_name,
                "__POOL_PATH__": str(self._pool_path),
            },
        )
        pool = conn.storagePoolDefineXML(pool_xml)
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
        seed_path: Path | None = None,
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
        self._create_disk_overlay(base_image, disk_path, role_cfg["disk_size"])
        network = role_cfg.get(
            "network",
            self._net_isolated if role == "lab" else self._net_internet,
        )
        os_variant = profile.get("os_variant") or "generic"

        print(f"[*] Creating VM '{vm_name}'...")
        cmd = [
            "virt-install",
            "--name",       vm_name,
            "--memory",     str(role_cfg["ram_mb"]),
            "--vcpus",      str(role_cfg["vcpus"]),
            "--disk",       f"path={disk_path},format=qcow2,bus=virtio",
            "--network",    f"network={network},model=virtio",
            "--os-variant", os_variant,
            "--import",
            "--graphics",   "none",
            "--console",    "pty,target_type=virtio",
            "--noautoconsole",
        ]
        if seed_path is not None:
            cmd.extend([
                "--disk",
                f"path={seed_path},format=raw,bus=virtio,readonly=on",
            ])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"virt-install failed:\n{result.stderr.strip()}")
        
        print(f"[+] VM '{vm_name}' created")
        return vm_name

    def _create_disk_overlay(self, base_image: Path, disk_path: Path, disk_size: str) -> None:
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

    # --- VM destruction ----------------------------------------------------

    def destroy_vm(self, vm_name: str) -> None:
        """Stop, undefine and remove all storage for a VM."""
        conn = self._connect()
        try:
            dom = conn.lookupByName(vm_name)
        except libvirt.libvirtError:
            print(f"[i] VM '{vm_name}' not found, nothing to destroy")
            return

        self._stop_domain_if_active(dom)
        self._undefine_domain(conn, dom, vm_name)
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
            dom.destroy()  # force off

    # TODO(refactor): simplify to a single undefineFlags call —
    # the multi-layer fallback was written for edge cases that don't
    # occur in a controlled lab environment
    def _undefine_domain(self, conn: libvirt.virConnect, dom: libvirt.virDomain, vm_name: str) -> None:
        # Some local libvirt/python bindings do not expose undefineWithSnapshots,
        # and some domains require extra flags (managed-save/NVRAM) to undefine.
        undefined = False
        try:
            undefine_with_snapshots = getattr(dom, "undefineWithSnapshots", None)
            if callable(undefine_with_snapshots):
                undefine_with_snapshots()
                undefined = True
        except (AttributeError, libvirt.libvirtError):
            pass

        if not undefined:
            try:
                flags = 0
                flags |= getattr(libvirt, "VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA", 0)
                flags |= getattr(libvirt, "VIR_DOMAIN_UNDEFINE_MANAGED_SAVE", 0)
                flags |= getattr(libvirt, "VIR_DOMAIN_UNDEFINE_NVRAM", 0)
                dom.undefineFlags(flags)
                undefined = True
            except (AttributeError, libvirt.libvirtError):
                pass

        if not undefined:
            try:
                conn.lookupByName(vm_name)
            except libvirt.libvirtError:
                undefined = True

        if not undefined:
            subprocess.run(
                ["virsh", "undefine", vm_name, "--snapshots-metadata", "--managed-save", "--nvram"],
                check=False,
                capture_output=True,
                text=True,
            )

    def _verify_domain_removed(self, conn: libvirt.virConnect, vm_name: str) -> None:
        try:
            conn.lookupByName(vm_name)
        except libvirt.libvirtError:
            print(f"[+] VM '{vm_name}' undefined")
        else:
            raise RuntimeError(
                f"VM '{vm_name}' still defined after destroy attempt; manual cleanup may be required"
            )

    def _remove_domain_artifacts(self, vm_name: str) -> None:
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

    def restart_vm(self, vm_name: str) -> None:
        conn = self._connect()
        dom = conn.lookupByName(vm_name)
        dom.destroy()          # force off immediately — VM just booted, nothing to lose
        dom.create()           # cold start with new XML config applied

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

        while time.time() < deadline:
            try:
                raw_ifaces = dom.interfaceAddresses(
                    libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE
                )
                iface_values = raw_ifaces.values() if isinstance(raw_ifaces, dict) else ()

                for iface in iface_values:
                    if not isinstance(iface, dict):
                        continue
                    addrs = iface.get("addrs", [])
                    if not isinstance(addrs, list):
                        continue

                    for addr in addrs:
                        if not isinstance(addr, dict):
                            continue
                        if addr.get("type") == libvirt.VIR_IP_ADDR_TYPE_IPV4:
                            ip = addr.get("addr")
                            if isinstance(ip, str):
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
        root = ET.fromstring(xml)
        for disk in root.findall(".//disk[@type='file'][@device='disk']"):
            src = disk.find("source")
            if src is not None:
                return src.attrib["file"]
        raise RuntimeError(f"Could not find disk path for '{vm_name}'")

    @staticmethod
    def _render_template(path: Path, replacements: dict[str, str]) -> str:
        data = path.read_text()
        for placeholder, value in replacements.items():
            data = data.replace(placeholder, value)
        return data

    def vm_exists(self, vm_name: str) -> bool:
        conn = self._connect()
        try:
            conn.lookupByName(vm_name)
            return True
        except libvirt.libvirtError:
            return False
