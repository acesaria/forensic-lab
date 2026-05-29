"""
Project constants and configuration loader.

Path-handling contract
----------------------
All filesystem paths configured in `config.yaml` under `host:` are normalized
to absolute `pathlib.Path` objects inside `load_config()`. Downstream code
trusts these are absolute and does not re-normalize.

Bundled paths (playbooks, profiles dir, cloud-init template) are kept as
relative `Path` fragments below and joined with `repo_root` at the call site.
"""

from pathlib import Path
from typing import Any

import yaml

# --- Project constants (never change unless you restructure the project) ---

BASELINE_SNAPSHOT = "baseline"
# Must match the user created in infra/cloud-init/user-data
LAB_USER = "labuser"


# Bundled paths -- relative to repo_root, joined at call sites.
LAB_BASELINE_PLAYBOOK = Path("infra/ansible/lab_baseline.yml")
ISF_BUILD_PLAYBOOK = Path("infra/ansible/isf_build.yml")
PROFILES_DIR = Path("infra/profiles")
CLOUD_INIT_DIR = Path("infra/cloud-init")
CLOUD_INIT_USER_DATA = CLOUD_INIT_DIR / "user-data"
CLOUD_INIT_NETWORK_CONFIG = CLOUD_INIT_DIR / "network-config"

# VM name prefixes -- must match naming convention in README
LAB_VM_PREFIX = "lab"
BUILD_VM_PREFIX = "build-isf"

# Gateway IP on the isolated libvirt network. Must match the address bound in
# the network XML at infra/provider.py. Used by scenarios that need a
# host-side listener (e.g. reverse shells) reachable from the lab VM.
ISOLATED_NETWORK_GATEWAY = "192.168.100.1"

# Baseline acquisition filenames
BASELINE_MEMORY_FILENAME = "baseline_memory.raw"
BASELINE_DISK_FILENAME = "baseline_disk.E01"

# Scenario identifiers
VERIFY_SCENARIO = "verify"

# --- Path normalization (one source of truth) ---

# Fields in config.yaml `host:` that are filesystem paths. Every entry here is
# normalized to an absolute Path inside load_config(); add new path fields here.
# Layout under shared_dir / state_dir is fixed by ProjectPaths -- users tune
# the roots, not the leaves.
_HOST_PATH_FIELDS = (
    "ssh_key",
    "ssh_pub_key",
    "state_dir",
    "shared_dir",
)


def _resolve_path(value: str, repo_root: Path) -> Path:
    """Expand ~, anchor relative paths to repo_root, return an absolute Path."""
    p = Path(value).expanduser()
    if not p.is_absolute():
        p = repo_root / p
    return p.resolve()


# --- Loaders ---


def load_config(repo_root: Path) -> dict[str, Any]:
    """
    Load and validate config.yaml.

    After this returns, every field listed in _HOST_PATH_FIELDS is an absolute
    pathlib.Path. Consumers should treat them as such and not re-normalize.
    """
    config_path = repo_root / "config.yaml"
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    if "host" not in cfg or not isinstance(cfg["host"], dict):
        raise ValueError("config.yaml must contain a 'host' mapping")
    host = cfg["host"]
    if "isolated_network_name" not in host:
        raise ValueError("config.yaml must contain host.isolated_network_name")
    for field in _HOST_PATH_FIELDS:
        if field in host:
            host[field] = _resolve_path(host[field], repo_root)
    return cfg


def load_profile(repo_root: Path, distro_id: str) -> dict[str, Any]:
    """Load distro profile YAML by id."""
    path = repo_root / PROFILES_DIR / f"{distro_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"No profile for '{distro_id}' at {path}")
    with open(path) as f:
        return yaml.safe_load(f)


def load_scenarios(repo_root: Path) -> dict[str, Any]:
    """Load scenarios.yaml. Returns an empty dict if the file is empty."""
    return yaml.safe_load((repo_root / "scenarios.yaml").read_text()) or {}
