"""CLI entry point for forensic-lab."""

import argparse
import subprocess
from pathlib import Path
from typing import Any

import yaml

from infra.provider import Provider
from orchestrator.core.vm_manager import VMManager


def _load_config(repo_root: Path) -> dict[str, Any]:
    with open(repo_root / "config.yaml") as f:
        cfg = yaml.safe_load(f)

    # Support both canonical nested layout and the provided first-steps example.
    if "lab" in cfg and isinstance(cfg["lab"], dict) and "libvirt_uri" in cfg["lab"]:
        return cfg

    if "lab" in cfg and isinstance(cfg["lab"], dict):
        role_lab = cfg["lab"]
    else:
        role_lab = {}

    role_build_isf = cfg.get("build-isf", {})
    if not isinstance(role_build_isf, dict):
        role_build_isf = {}

    networks = cfg.get("networks", {})
    if not isinstance(networks, dict):
        networks = {}

    return {
        "lab": {
            "libvirt_uri": cfg["libvirt_uri"],
            "pool_name": cfg["pool_name"],
            "pool_path": cfg["pool_path"],
            "ssh_user": cfg["ssh_user"],
            "ssh_key": cfg["ssh_key"],
            "shared_dir": cfg["shared_dir"],
            "networks": {
                "isolated": networks.get("isolated", "forensics-isolated"),
                "internet": networks.get("internet", "default"),
            },
        },
        "role_defaults": {
            "lab": {
                "disk_size": role_lab["disk_size"],
                "ram_mb": role_lab["ram_mb"],
                "vcpus": role_lab["vcpus"],
            },
            "build-isf": role_build_isf,
        },
    }


def _load_profile(repo_root: Path, distro_id: str) -> dict[str, Any]:
    path = repo_root / "infra" / "profiles" / f"{distro_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"No profile found for distro '{distro_id}' at {path}")
    with open(path) as f:
        return yaml.safe_load(f)


def _domain_state(vm_name: str) -> str | None:
    r = subprocess.run(
        ["virsh", "domstate", vm_name],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return None
    return r.stdout.strip().lower()


def _destroy_fallback(cfg: dict[str, Any], distro_id: str) -> None:
    vm_name = f"lab-{distro_id}"
    state = _domain_state(vm_name)
    if state is None:
        print(f"[i] VM '{vm_name}' not found, nothing to destroy")
        return
    if "running" in state:
        subprocess.run(["virsh", "destroy", vm_name], check=False)
    subprocess.run(["virsh", "undefine", vm_name, "--snapshots-metadata"], check=False)
    pool_path = Path(cfg["lab"]["pool_path"]).expanduser().resolve()
    for suffix in (".qcow2", "-seed.iso"):
        path = pool_path / f"{vm_name}{suffix}"
        if path.exists():
            path.unlink()
            print(f"[+] Removed {path.name}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="forensic-lab")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("setup", help="Create libvirt network and pool")

    prepare = sub.add_parser("prepare", help="Prepare distro VM and baseline")
    prepare.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")

    destroy = sub.add_parser("destroy", help="Destroy distro VM and storage")
    destroy.add_argument("--distro", required=True, help="Distro ID")

    return parser


def main() -> None:
    repo_root = Path(__file__).resolve().parent
    args = build_parser().parse_args()

    cfg = _load_config(repo_root)
    provider = Provider(cfg, repo_root)
    manager = VMManager(cfg, provider, repo_root)

    try:
        if args.command == "setup":
            provider.ensure_network()
            provider.ensure_pool()
            return

        distro_id = args.distro
        if args.command == "prepare":
            vm_name = f"lab-{distro_id}"
            state = _domain_state(vm_name)
            if state is not None and "running" not in state:
                provider.start_vm(vm_name)
            profile = _load_profile(repo_root, distro_id)
            manager.prepare_lab(distro_id, profile)
            return

        if args.command == "destroy":
            try:
                manager.destroy_lab(distro_id)
            except AttributeError as e:
                if "undefineWithSnapshots" not in str(e):
                    raise
                print("[!] Provider destroy path incompatible with local libvirt binding; using virsh fallback")
                _destroy_fallback(cfg, distro_id)
    finally:
        provider.close()


if __name__ == "__main__":
    main()
