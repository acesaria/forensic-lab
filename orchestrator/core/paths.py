"""
orchestrator/core/paths.py

Single source of truth for every filesystem location the project uses.

User-tunable roots come from config.yaml (machine-local):
    repo_root, shared_dir, state_dir, ssh_key, ssh_pub_key

Derived locations are computed as properties so callers never re-derive
"shared_dir / 'dumps'" or "repo_root / 'vendor/...'" on their own. Per-run
directories are built via run_dumps_dir() / run_results_dir() from a `run_id`
("{distro}_{scenario}_{ts}") so the dumps and results trees stay in lockstep.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any


# Bundled, repo-relative path -- atomic-red-team is a git subtree at a fixed
# location, not user-tunable. Joined with repo_root at the property below.
_ATOMICS_REL = Path("vendor/atomic-red-team/atomics")


@dataclass(frozen=True)
class ProjectPaths:
    repo_root: Path
    shared_dir: Path
    state_dir: Path
    ssh_key: Path
    ssh_pub_key: Path

    @classmethod
    def from_config(cls, repo_root: Path, host_cfg: dict[str, Any]) -> "ProjectPaths":
        return cls(
            repo_root=repo_root,
            shared_dir=host_cfg["shared_dir"],
            state_dir=host_cfg["state_dir"],
            ssh_key=host_cfg["ssh_key"],
            ssh_pub_key=host_cfg["ssh_pub_key"],
        )

    # --- shared/ tree (experiment outputs) -------------------------------

    @property
    def dumps_dir(self) -> Path:
        return self.shared_dir / "dumps"

    @property
    def results_dir(self) -> Path:
        return self.shared_dir / "results"

    @property
    def isf_dir(self) -> Path:
        return self.shared_dir / "isf"

    # --- state_dir tree (libvirt-owned storage) --------------------------

    @property
    def images_dir(self) -> Path:
        return self.state_dir / "images"

    @property
    def pool_dir(self) -> Path:
        return self.state_dir / "disks"

    # --- bundled ---------------------------------------------------------

    @property
    def atomics_dir(self) -> Path:
        return self.repo_root / _ATOMICS_REL

    # --- per-run -------------------------------------------------------

    def run_dumps_dir(self, run_id: str) -> Path:
        return self.dumps_dir / run_id

    def run_results_dir(self, run_id: str) -> Path:
        return self.results_dir / run_id
