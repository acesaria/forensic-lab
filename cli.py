"""CLI entry point for forensic-lab."""

import argparse
from pathlib import Path
from typing import Any

import yaml

from infra.provider import Provider
from orchestrator.core.vm_manager import VMManager


def _load_config(repo_root: Path) -> dict[str, Any]:
    with open(repo_root / "config.yaml") as f:
        return yaml.safe_load(f)


def _load_profile(repo_root: Path, distro_id: str) -> dict[str, Any]:
    path = repo_root / "infra" / "profiles" / f"{distro_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"No profile found for distro '{distro_id}' at {path}")
    with open(path) as f:
        return yaml.safe_load(f)


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
            profile = _load_profile(repo_root, distro_id)
            manager.prepare_lab(distro_id, profile)
            return

        if args.command == "destroy":
            manager.destroy_lab(distro_id)
    finally:
        provider.close()


if __name__ == "__main__":
    main()
