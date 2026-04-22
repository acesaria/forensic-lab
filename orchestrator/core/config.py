"""Shared configuration and profile loading helpers."""

from pathlib import Path
from typing import Any

import yaml


def load_config(repo_root: Path) -> dict[str, Any]:
    """Load project config and normalize legacy flat schema when needed."""
    with open(repo_root / "config.yaml") as f:
        cfg = yaml.safe_load(f)

    # Canonical schema already present.
    if "lab" in cfg and isinstance(cfg["lab"], dict) and "libvirt_uri" in cfg["lab"]:
        return cfg

    # Legacy compatibility path.
    role_lab = cfg.get("lab", {}) if isinstance(cfg.get("lab", {}), dict) else {}
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
            "ssh_authorized_keys_path": cfg.get("ssh_authorized_keys_path"),
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


def load_profile(repo_root: Path, distro_id: str) -> dict[str, Any]:
    """Load distro profile by id from infra/profiles."""
    path = repo_root / "infra" / "profiles" / f"{distro_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"No profile found for distro '{distro_id}' at {path}")
    with open(path) as f:
        return yaml.safe_load(f)
