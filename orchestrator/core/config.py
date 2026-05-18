"""Project constants and configuration loader."""

from pathlib import Path
from typing import Any

import yaml

# --- Project constants (never change unless you restructure the project) ---

BASELINE_SNAPSHOT = "baseline"
# Must match the user created in infra/cloud-init/user-data
LAB_USER = "labuser"

LAB_BASELINE_PLAYBOOK = Path("infra/ansible/lab_baseline.yml")
ISF_BUILD_PLAYBOOK = Path("infra/ansible/isf_build.yml")
ISF_SHARED_DIR = Path("shared/isf")
PROFILES_DIR = Path("infra/profiles")
CLOUD_INIT_DIR = Path("infra/cloud-init")
CLOUD_INIT_USER_DATA = CLOUD_INIT_DIR / "user-data"

# VM name prefixes -- must match naming convention in README
LAB_VM_PREFIX = "lab"
BUILD_VM_PREFIX = "build-isf"

# Atomic Red Team atomics directory
ATOMICS_DIR = "atomics"

# Baseline acquisition filenames
BASELINE_MEMORY_FILENAME = "baseline_memory.raw"
BASELINE_DISK_FILENAME = "baseline_disk.E01"

# Scenario identifiers
VERIFY_SCENARIO = "verify"

# --- Loaders ---


def load_config(repo_root: Path) -> dict[str, Any]:
    """Load and validate config.yaml. Returns raw validated dict."""
    config_path = repo_root / "config.yaml"
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    if "host" not in cfg or not isinstance(cfg["host"], dict):
        raise ValueError("config.yaml must contain a 'host' mapping")
    if "isolated_network_name" not in cfg.get("host", {}):
        raise ValueError("config.yaml must contain host.isolated_network_name")
    return cfg


def load_profile(repo_root: Path, distro_id: str) -> dict[str, Any]:
    """Load distro profile YAML by id."""
    path = repo_root / PROFILES_DIR / f"{distro_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"No profile for '{distro_id}' at {path}")
    with open(path) as f:
        return yaml.safe_load(f)
